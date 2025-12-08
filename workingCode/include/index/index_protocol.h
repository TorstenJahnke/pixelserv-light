/*
 * index_protocol.h - IPC Protocol for Index Master/Worker Communication
 *
 * Simple text-based protocol over Unix socket for easy debugging.
 */

#ifndef _INDEX_PROTOCOL_H_
#define _INDEX_PROTOCOL_H_

#include <stdint.h>

/* Default socket path */
#define INDEX_MASTER_SOCKET_DEFAULT "/tmp/pixelserv-index.sock"

/* Protocol commands (text-based for easy debugging) */

/*
 * LOOKUP <domain>\n
 * Response: FOUND <shard_id> <cert_id> <expiry>\n
 *       or: NOTFOUND\n
 *       or: ERROR <message>\n
 */
#define IDX_CMD_LOOKUP   "LOOKUP"

/*
 * INSERT <domain> <shard_id> <cert_id> <expiry>\n
 * Response: OK\n
 *       or: ERROR <message>\n
 */
#define IDX_CMD_INSERT   "INSERT"

/*
 * REMOVE <domain>\n
 * Response: OK\n
 *       or: NOTFOUND\n
 */
#define IDX_CMD_REMOVE   "REMOVE"

/*
 * STATS\n
 * Response: STATS <total_certs> <shards>\n
 */
#define IDX_CMD_STATS    "STATS"

/*
 * SCAN\n  (rebuild index from disk)
 * Response: OK <count>\n
 */
#define IDX_CMD_SCAN     "SCAN"

/*
 * PING\n
 * Response: PONG\n
 */
#define IDX_CMD_PING     "PING"

/* Response prefixes */
#define IDX_RSP_FOUND    "FOUND"
#define IDX_RSP_NOTFOUND "NOTFOUND"
#define IDX_RSP_OK       "OK"
#define IDX_RSP_ERROR    "ERROR"
#define IDX_RSP_STATS    "STATS"
#define IDX_RSP_PONG     "PONG"

/* Message buffer size */
#define IDX_MSG_MAXLEN   512

/* Lookup result structure */
typedef struct {
    int found;
    uint8_t shard_id;
    uint32_t cert_id;
    uint64_t expiry;
} idx_lookup_result_t;

#endif /* _INDEX_PROTOCOL_H_ */
