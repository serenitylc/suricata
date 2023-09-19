/* Copyright (C) 2015-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and app-layer-mssqldb.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * MssqlDB application layer detector and parser for learning and
 * mssqldb purposes.
 *
 * This mssqldb implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "conf.h"
#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-mssqldb.h"

#include "util-unittest.h"
#include "util-validate.h"
#include "util-enum.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define MSSQLDB_DEFAULT_PORT "7"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define MSSQLDB_MIN_FRAME_LEN 1

/* Enum of app-layer events for the protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For mssqldb we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert mssqldb any any -> any any (msg:"SURICATA MssqlDB empty message"; \
 *    app-layer-event:mssqldb.empty_message; sid:X; rev:Y;)
 */
enum {
    MSSQLDB_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap mssqldb_decoder_event_table[] = {
    {"EMPTY_MESSAGE", MSSQLDB_DECODER_EVENT_EMPTY_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static MssqlDBTransaction *MssqlDBTxAlloc(MssqlDBState *state)
{
    MssqlDBTransaction *tx = SCCalloc(1, sizeof(MssqlDBTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

static void MssqlDBTxFree(void *txv)
{
    MssqlDBTransaction *tx = txv;

    if (tx->request_buffer != NULL) {
        SCFree(tx->request_buffer);
    }

    if (tx->response_buffer != NULL) {
        SCFree(tx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    SCFree(tx);
}

static void *MssqlDBStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogNotice("Allocating mssqldb state.");
    MssqlDBState *state = SCCalloc(1, sizeof(MssqlDBState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void MssqlDBStateFree(void *state)
{
    MssqlDBState *mssqldb_state = state;
    MssqlDBTransaction *tx;
    SCLogNotice("Freeing mssqldb state.");
    while ((tx = TAILQ_FIRST(&mssqldb_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&mssqldb_state->tx_list, tx, next);
        MssqlDBTxFree(tx);
    }
    SCFree(mssqldb_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the MssqlDBState object.
 * \param tx_id the transaction ID to free.
 */
static void MssqlDBStateTxFree(void *statev, uint64_t tx_id)
{
    MssqlDBState *state = statev;
    MssqlDBTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &state->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&state->tx_list, tx, next);
        MssqlDBTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int MssqlDBStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, mssqldb_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "mssqldb enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int MssqlDBStateGetEventInfoById(int event_id, const char **event_name,
                                         AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, mssqldb_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "mssqldb enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/**
 * \brief Probe the input to server to see if it looks like mssqldb.
 *
 * \retval ALPROTO_MSSQLDB if it looks like mssqldb,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_MSSQLDB,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto MssqlDBProbingParserTs(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is mssqldb. */
    if (input_len >= MSSQLDB_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_MSSQLDB.");
        return ALPROTO_MSSQLDB;
    }

    SCLogNotice("Protocol not detected as ALPROTO_MSSQLDB.");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to client to see if it looks like mssqldb.
 *     MssqlDBProbingParserTs can be used instead if the protocol
 *     is symmetric.
 *
 * \retval ALPROTO_MSSQLDB if it looks like mssqldb,
 *     ALPROTO_FAILED, if it is clearly not ALPROTO_MSSQLDB,
 *     otherwise ALPROTO_UNKNOWN.
 */
static AppProto MssqlDBProbingParserTc(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is mssqldb. */
    if (input_len >= MSSQLDB_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_MSSQLDB.");
        return ALPROTO_MSSQLDB;
    }

    SCLogNotice("Protocol not detected as ALPROTO_MSSQLDB.");
    return ALPROTO_UNKNOWN;
}

static AppLayerResult MssqlDBParseRequest(Flow *f, void *statev, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    MssqlDBState *state = statev;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
    const uint8_t flags = StreamSliceGetFlags(&stream_slice);

    SCLogNotice("Parsing mssqldb request: len=%"PRIu32, input_len);

    if (input == NULL) {
        if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
            /* This is a signal that the stream is done. Do any
             * cleanup if needed. Usually nothing is required here. */
            SCReturnStruct(APP_LAYER_OK);
        } else if (flags & STREAM_GAP) {
            /* This is a signal that there has been a gap in the
             * stream. This only needs to be handled if gaps were
             * enabled during protocol registration. The input_len
             * contains the size of the gap. */
            SCReturnStruct(APP_LAYER_OK);
        }
        /* This should not happen. If input is NULL, one of the above should be
         * true. */
        DEBUG_VALIDATE_BUG_ON(true);
        SCReturnStruct(APP_LAYER_ERROR);
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an echo protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly received
     * data belongs to.
     */
    MssqlDBTransaction *tx = MssqlDBTxAlloc(state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new MssqlDB tx.");
        goto end;
    }
    SCLogNotice("Allocated MssqlDB tx %"PRIu64".", tx->tx_id);

    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->tx_data.events, MSSQLDB_DECODER_EVENT_EMPTY_MESSAGE);
    }

end:
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult MssqlDBParseResponse(Flow *f, void *statev, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    MssqlDBState *state = statev;
    MssqlDBTransaction *tx = NULL, *ttx;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    SCLogNotice("Parsing MssqlDB response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_OK);
    }

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * MssqlDBState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &state->tx_list, next) {
        tx = ttx;
    }

    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on state %p.",
            state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on state %p.",
        tx->tx_id, state);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_buffer != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        SCFree(tx->response_buffer);
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    /* Set the response_done flag for transaction state checking in
     * MssqlDBGetStateProgress(). */
    tx->response_done = 1;

end:
    SCReturnStruct(APP_LAYER_OK);
}

static uint64_t MssqlDBGetTxCnt(void *statev)
{
    const MssqlDBState *state = statev;
    SCLogNotice("Current tx count is %"PRIu64".", state->transaction_max);
    return state->transaction_max;
}

static void *MssqlDBGetTx(void *statev, uint64_t tx_id)
{
    MssqlDBState *state = statev;
    MssqlDBTransaction *tx;

    SCLogDebug("Requested tx ID %" PRIu64 ".", tx_id);

    TAILQ_FOREACH(tx, &state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogDebug("Transaction %" PRIu64 " found, returning tx object %p.", tx_id, tx);
            return tx;
        }
    }

    SCLogDebug("Transaction ID %" PRIu64 " not found.", tx_id);
    return NULL;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen. The response_done flag is set on response for
 * checking here.
 */
static int MssqlDBGetStateProgress(void *txv, uint8_t direction)
{
    MssqlDBTransaction *tx = txv;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", tx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && tx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For the mssqldb, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief retrieve the tx data used for logging, config, detection
 */
static AppLayerTxData *MssqlDBGetTxData(void *vtx)
{
    MssqlDBTransaction *tx = vtx;
    return &tx->tx_data;
}

void RegisterMssqlDBParsers(void)
{
    const char *proto_name = "mssqldb";

    /* Check if MssqlDB TCP detection is enabled. If it does not exist in
     * the configuration file then it will be disabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, false)) {

        SCLogDebug("MssqlDB TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_MSSQLDB, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, MSSQLDB_DEFAULT_PORT,
                ALPROTO_MSSQLDB, 0, MSSQLDB_MIN_FRAME_LEN, STREAM_TOSERVER,
                MssqlDBProbingParserTs, MssqlDBProbingParserTc);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_MSSQLDB, 0, MSSQLDB_MIN_FRAME_LEN,
                    MssqlDBProbingParserTs, MssqlDBProbingParserTc)) {
                SCLogDebug("No mssqldb app-layer configuration, enabling echo"
                           " detection TCP detection on port %s.",
                        MSSQLDB_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    MSSQLDB_DEFAULT_PORT, ALPROTO_MSSQLDB, 0,
                    MSSQLDB_MIN_FRAME_LEN, STREAM_TOSERVER,
                    MssqlDBProbingParserTs, MssqlDBProbingParserTc);
            }

        }

    }

    else {
        SCLogDebug("Protocol detector and parser disabled for MssqlDB.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering MssqlDB protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new MssqlDB flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBStateAlloc, MssqlDBStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MSSQLDB,
            STREAM_TOSERVER, MssqlDBParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MSSQLDB,
            STREAM_TOCLIENT, MssqlDBParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBStateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_MSSQLDB, 1, 1);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_MSSQLDB, MssqlDBGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBGetTxData);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_MSSQLDB,
            MssqlDBStateGetEventInfoById);

        /* Leave this is if your parser can handle gaps, otherwise
         * remove. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_MSSQLDB,
            APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogDebug("MssqlDB protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MSSQLDB,
        MssqlDBParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void MssqlDBParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
