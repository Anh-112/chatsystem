#ifndef CHAT_SERVER_H
#define CHAT_SERVER_H

#include <stdint.h>

/* ─── Network ───────────────────────────────────────────────── */
#define SERVER_PORT         9000
#define WEB_BRIDGE_PORT     9001
#define MAX_CLIENTS         64
#define MAX_ROOMS           32
#define MAX_ROOM_MEMBERS    32
#define MAX_MSG_LEN         2048
#define MAX_NAME_LEN        64
#define MAX_PASS_LEN        256
#define CIPHER_KEY          42    /* default substitution key */

/* ─── Packet types ──────────────────────────────────────────── */
typedef enum {
    PKT_REGISTER    = 1,
    PKT_LOGIN       = 2,
    PKT_LOGOUT      = 3,
    PKT_SEND_MSG    = 4,   /* encrypted chat message */
    PKT_RECV_MSG    = 5,   /* server → client delivery */
    PKT_CREATE_ROOM = 6,
    PKT_JOIN_ROOM   = 7,
    PKT_LEAVE_ROOM  = 8,
    PKT_LIST_USERS  = 9,
    PKT_LIST_ROOMS  = 10,
    PKT_HISTORY     = 11,
    PKT_OK          = 20,
    PKT_ERROR       = 21,
    PKT_PING        = 30,
    PKT_PONG        = 31,
} PktType;

/* ─── Message target types ──────────────────────────────────── */
typedef enum {
    TARGET_USER  = 1,  /* direct / private message */
    TARGET_ROOM  = 2,  /* group / room message     */
} TargetType;

/* ─── Wire packet (JSON over TCP) ───────────────────────────── */
/*
 * All packets are newline-terminated JSON strings.
 * Schema:
 *  { "type": <PktType>,
 *    "from": "<username>",
 *    "to":   "<username|roomname>",
 *    "target_type": <TargetType>,
 *    "content": "<encrypted or plaintext>",
 *    "token":   "<session token>",
 *    "extra":   "<extra info>"
 *  }
 */

/* ─── Internal structures ───────────────────────────────────── */
typedef struct {
    int    fd;
    char   username[MAX_NAME_LEN];
    char   token[65];       /* random session token */
    int    logged_in;
    int    room_ids[MAX_ROOMS]; /* rooms this client is in */
    int    room_count;
} Client;

typedef struct {
    int  id;
    char name[MAX_NAME_LEN];
    char creator[MAX_NAME_LEN];
    int  member_fds[MAX_ROOM_MEMBERS];
    int  member_count;
} Room;

/* ─── Utility macros ────────────────────────────────────────── */
#define LOG(fmt, ...) fprintf(stderr, "[SERVER] " fmt "\n", ##__VA_ARGS__)

#endif /* CHAT_SERVER_H */
