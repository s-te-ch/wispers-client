/**
 * wispers-connect C example
 *
 * Demonstrates the C API for wispers-connect: register, activate, serve, and
 * ping. Compatible with wconnect, the Python example, and the Go example.
 *
 * Usage:
 *   ./ffi_demo [--hub ADDR] [--storage DIR] status
 *   ./ffi_demo [--hub ADDR] [--storage DIR] register <token>
 *   ./ffi_demo [--hub ADDR] [--storage DIR] activate <code>
 *   ./ffi_demo [--hub ADDR] [--storage DIR] nodes
 *   ./ffi_demo [--hub ADDR] [--storage DIR] serve
 *   ./ffi_demo [--hub ADDR] [--storage DIR] ping [--quic] <node_number>
 *
 * File layout (top-down):
 *   1. Forward declarations (table of contents)
 *   2. main()
 *   3. Commands
 *   4. Serve helpers (accept loops, connection handlers)
 *   5. Node context helpers
 *   6. Display helpers
 *   7. Blocking wrappers (turn async C API → synchronous calls)
 *   8. Sync primitives, callbacks, context structs
 *   9. File-based storage implementation
 */

#include "wispers_connect.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

//==============================================================================
// Types
//==============================================================================

// Returned by node_init(), freed by node_cleanup().
typedef struct {
    void                      *file_ctx;  // opaque, free() when done
    WispersNodeStorageHandle  *storage;
    WispersNodeHandle         *node;
    WispersNodeState           state;
} NodeContext;

//==============================================================================
// Forward declarations
//==============================================================================

// --- Commands ---
static int cmd_status(void);
static int cmd_register(const char *token);
static int cmd_activate(const char *code);
static int cmd_nodes(void);
static int cmd_serve(void);
static int cmd_ping(int peer, int use_quic);

// --- Node context helpers ---
static int  node_init(NodeContext *ctx);
static void node_cleanup(NodeContext *ctx);

// --- Display helpers ---
static void        print_group(WispersNodeHandle *node);
static void        print_usage(const char *prog);
static const char *status_str(WispersStatus s);
static const char *state_str(WispersNodeState s);
static const char *group_state_str(WispersGroupState s);
static const char *activation_status_str(int s);

// --- Serve helpers ---
static void *serving_run_thread(void *arg);
static void *accept_quic_thread(void *arg);
static void *accept_udp_thread(void *arg);
static void  handle_quic_connection(WispersQuicConnectionHandle *conn);
static void *handle_udp_thread(void *arg);

// --- Blocking wrappers (sync wrappers around the async C API) ---
//     Each handles all callback/sync machinery internally.
//
//     Node lifecycle:
static WispersStatus blocking_restore_or_init(WispersNodeStorageHandle *storage,
    WispersNodeHandle **out_node, WispersNodeState *out_state, int timeout_ms);
static WispersStatus blocking_register(WispersNodeHandle *node,
    const char *token, int timeout_ms);
static WispersStatus blocking_activate(WispersNodeHandle *node,
    const char *code, int timeout_ms);
static WispersStatus blocking_group_info(WispersNodeHandle *node,
    WispersGroupInfo **out, int timeout_ms);
//     Serving:
static WispersStatus blocking_start_serving(WispersNodeHandle *node,
    WispersServingHandle **out_serving, WispersServingSession **out_session,
    WispersIncomingConnections **out_incoming, int timeout_ms);
static WispersStatus blocking_generate_activation_code(
    WispersServingHandle *serving, char **out_code, int timeout_ms);
static WispersStatus blocking_serving_run(WispersServingSession *session,
    int timeout_ms);
static WispersStatus blocking_shutdown(WispersServingHandle *serving,
    int timeout_ms);
//     UDP:
static WispersStatus blocking_connect_udp(WispersNodeHandle *node,
    int32_t peer, WispersUdpConnectionHandle **out, int timeout_ms);
static WispersStatus blocking_udp_recv(WispersUdpConnectionHandle *conn,
    uint8_t *buf, size_t buf_size, size_t *out_len, int timeout_ms);
static WispersStatus blocking_accept_udp(WispersIncomingConnections *incoming,
    WispersUdpConnectionHandle **out, int timeout_ms);
//     QUIC:
static WispersStatus blocking_connect_quic(WispersNodeHandle *node,
    int32_t peer, WispersQuicConnectionHandle **out, int timeout_ms);
static WispersStatus blocking_accept_quic(WispersIncomingConnections *incoming,
    WispersQuicConnectionHandle **out, int timeout_ms);
static WispersStatus blocking_quic_open_stream(WispersQuicConnectionHandle *conn,
    WispersQuicStreamHandle **out, int timeout_ms);
static WispersStatus blocking_quic_accept_stream(WispersQuicConnectionHandle *conn,
    WispersQuicStreamHandle **out, int timeout_ms);
static WispersStatus blocking_quic_write(WispersQuicStreamHandle *stream,
    const uint8_t *data, size_t len, int timeout_ms);
static WispersStatus blocking_quic_read(WispersQuicStreamHandle *stream,
    uint8_t *buf, size_t buf_size, size_t *out_len, int timeout_ms);
static WispersStatus blocking_quic_finish(WispersQuicStreamHandle *stream,
    int timeout_ms);
static WispersStatus blocking_quic_close(WispersQuicConnectionHandle *conn,
    int timeout_ms);

// --- File-based storage ---
static WispersNodeStorageHandle *create_storage(void **out_file_ctx);

//==============================================================================
// Globals
//==============================================================================

static const char              *g_hub_addr = NULL;
static const char              *g_storage_dir = NULL;
static volatile sig_atomic_t    g_shutdown_requested = 0;

static void on_signal(int sig) { (void)sig; g_shutdown_requested = 1; }

//==============================================================================
// main
//==============================================================================

int main(int argc, char **argv) {
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
            g_hub_addr = argv[++i]; i++;
        } else if (strncmp(argv[i], "--hub=", 6) == 0) {
            g_hub_addr = argv[i] + 6; i++;
        } else if (strcmp(argv[i], "--storage") == 0 && i + 1 < argc) {
            g_storage_dir = argv[++i]; i++;
        } else if (strncmp(argv[i], "--storage=", 10) == 0) {
            g_storage_dir = argv[i] + 10; i++;
        } else {
            break;
        }
    }

    if (i >= argc) { print_usage(argv[0]); return 1; }
    const char *cmd = argv[i++];

    if (strcmp(cmd, "status") == 0)   return cmd_status();
    if (strcmp(cmd, "nodes") == 0)    return cmd_nodes();
    if (strcmp(cmd, "serve") == 0)    return cmd_serve();

    if (strcmp(cmd, "register") == 0) {
        if (i >= argc) { fprintf(stderr, "register requires a token\n"); return 1; }
        return cmd_register(argv[i]);
    }
    if (strcmp(cmd, "activate") == 0) {
        if (i >= argc) { fprintf(stderr, "activate requires a code\n"); return 1; }
        return cmd_activate(argv[i]);
    }
    if (strcmp(cmd, "ping") == 0) {
        int use_quic = 0;
        if (i < argc && strcmp(argv[i], "--quic") == 0) { use_quic = 1; i++; }
        if (i >= argc) { fprintf(stderr, "ping requires a node number\n"); return 1; }
        int peer = atoi(argv[i]);
        if (peer <= 0) { fprintf(stderr, "invalid node number\n"); return 1; }
        return cmd_ping(peer, use_quic);
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}

//==============================================================================
// Commands
//==============================================================================

static int cmd_status(void) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    WispersRegistrationInfo info;
    if (wispers_storage_read_registration(ctx.storage, &info) == WISPERS_STATUS_SUCCESS) {
        printf("Node state: %s (node %d in group %s)\n",
               state_str(ctx.state), info.node_number, info.connectivity_group_id);
        wispers_registration_info_free(&info);
        print_group(ctx.node);
    } else {
        printf("Node state: %s\n", state_str(ctx.state));
    }

    node_cleanup(&ctx);
    return 0;
}

static int cmd_register(const char *token) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    if (ctx.state != WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot register: already %s\n", state_str(ctx.state));
        node_cleanup(&ctx);
        return 1;
    }

    printf("Registering...\n");
    WispersStatus s = blocking_register(ctx.node, token, 30000);
    if (s != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Registration failed: %s\n", status_str(s));
        node_cleanup(&ctx);
        return 1;
    }

    WispersRegistrationInfo info;
    if (wispers_storage_read_registration(ctx.storage, &info) == WISPERS_STATUS_SUCCESS) {
        printf("Registered as node %d in group %s\n",
               info.node_number, info.connectivity_group_id);
        wispers_registration_info_free(&info);
    } else {
        printf("Registered successfully\n");
    }

    node_cleanup(&ctx);
    return 0;
}

static int cmd_activate(const char *code) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    if (ctx.state == WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot activate: not registered yet\n");
        node_cleanup(&ctx);
        return 1;
    }
    if (ctx.state == WISPERS_NODE_STATE_ACTIVATED) {
        fprintf(stderr, "Already activated\n");
        node_cleanup(&ctx);
        return 1;
    }

    printf("Activating...\n");
    WispersStatus s = blocking_activate(ctx.node, code, 60000);
    if (s != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Activation failed: %s\n", status_str(s));
        node_cleanup(&ctx);
        return 1;
    }

    printf("Activated!\n");
    node_cleanup(&ctx);
    return 0;
}

static int cmd_nodes(void) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    if (ctx.state == WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Not registered yet\n");
        node_cleanup(&ctx);
        return 1;
    }

    print_group(ctx.node);
    node_cleanup(&ctx);
    return 0;
}

static int cmd_serve(void) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    if (ctx.state == WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot serve: not registered yet\n");
        node_cleanup(&ctx);
        return 1;
    }

    printf("Starting serving session (state: %s)...\n", state_str(ctx.state));

    WispersServingHandle *serving;
    WispersServingSession *session;
    WispersIncomingConnections *incoming;
    WispersStatus s = blocking_start_serving(
        ctx.node, &serving, &session, &incoming, 30000);
    if (s != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start serving: %s\n", status_str(s));
        node_cleanup(&ctx);
        return 1;
    }

    // Auto-print activation code if group allows endorsing.
    WispersGroupInfo *gi;
    if (blocking_group_info(ctx.node, &gi, 10000) == WISPERS_STATUS_SUCCESS) {
        WispersGroupState gstate = wispers_group_info_state(gi);
        if (gstate == WISPERS_GROUP_STATE_CAN_ENDORSE ||
            gstate == WISPERS_GROUP_STATE_BOOTSTRAP) {
            char *code;
            if (blocking_generate_activation_code(serving, &code, 10000)
                    == WISPERS_STATUS_SUCCESS) {
                printf("\nActivation code for a new peer:\n  %s\n\n", code);
                wispers_string_free(code);
            }
        }
        wispers_group_info_free(gi);
    }

    // Run session event loop in background (consumes session handle).
    pthread_t run_tid;
    pthread_create(&run_tid, NULL, serving_run_thread, session);

    // Accept incoming connections in background.
    if (incoming) {
        printf("Listening for incoming connections...\n");
        pthread_t t;
        pthread_create(&t, NULL, accept_quic_thread, incoming);
        pthread_detach(t);
        pthread_create(&t, NULL, accept_udp_thread, incoming);
        pthread_detach(t);
    }

    printf("Serving (Ctrl-C to quit)...\n");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_shutdown_requested) sleep(1);

    printf("\nShutting down...\n");
    blocking_shutdown(serving, 5000);
    pthread_join(run_tid, NULL);

    wispers_serving_handle_free(serving);
    if (incoming) wispers_incoming_connections_free(incoming);
    node_cleanup(&ctx);
    return 0;
}

static int cmd_ping(int peer, int use_quic) {
    NodeContext ctx;
    if (node_init(&ctx)) return 1;

    if (ctx.state != WISPERS_NODE_STATE_ACTIVATED) {
        fprintf(stderr, "Cannot ping: not activated (state=%s)\n",
                state_str(ctx.state));
        node_cleanup(&ctx);
        return 1;
    }

    const char *transport = use_quic ? "QUIC" : "UDP";
    printf("Pinging node %d via %s...\n", peer, transport);

    int result = 1;

    if (use_quic) {
        WispersQuicConnectionHandle *conn;
        if (blocking_connect_quic(ctx.node, peer, &conn, 30000)
                != WISPERS_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to connect\n");
            goto done;
        }

        WispersQuicStreamHandle *stream;
        if (blocking_quic_open_stream(conn, &stream, 10000)
                != WISPERS_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to open stream\n");
            wispers_quic_connection_free(conn);
            goto done;
        }

        blocking_quic_write(stream, (const uint8_t *)"PING\n", 5, 10000);
        blocking_quic_finish(stream, 10000);

        uint8_t buf[64];
        size_t len;
        if (blocking_quic_read(stream, buf, sizeof(buf), &len, 10000)
                == WISPERS_STATUS_SUCCESS) {
            printf("Received: %.*s", (int)len, buf);
            result = 0;
        } else {
            fprintf(stderr, "Failed to read response\n");
        }

        wispers_quic_stream_free(stream);
        blocking_quic_close(conn, 5000);
    } else {
        WispersUdpConnectionHandle *conn;
        if (blocking_connect_udp(ctx.node, peer, &conn, 30000)
                != WISPERS_STATUS_SUCCESS) {
            fprintf(stderr, "Failed to connect\n");
            goto done;
        }

        wispers_udp_connection_send(conn, (const uint8_t *)"ping", 4);

        uint8_t buf[64];
        size_t len;
        if (blocking_udp_recv(conn, buf, sizeof(buf), &len, 10000)
                == WISPERS_STATUS_SUCCESS) {
            printf("Received: %.*s\n", (int)len, buf);
            result = 0;
        } else {
            fprintf(stderr, "Failed to receive response\n");
        }

        wispers_udp_connection_close(conn);
    }

    if (result == 0) printf("Ping successful!\n");

done:
    node_cleanup(&ctx);
    return result;
}

//==============================================================================
// Serve helpers
//==============================================================================

static void *serving_run_thread(void *arg) {
    blocking_serving_run((WispersServingSession *)arg, 0x7FFFFFFF);
    return NULL;
}

static void *accept_quic_thread(void *arg) {
    WispersIncomingConnections *incoming = arg;
    while (1) {
        WispersQuicConnectionHandle *conn;
        if (blocking_accept_quic(incoming, &conn, 0x7FFFFFFF)
                != WISPERS_STATUS_SUCCESS)
            break;
        printf("Incoming QUIC connection\n");
        handle_quic_connection(conn);
        blocking_quic_close(conn, 5000);
        printf("Connection closed\n");
    }
    return NULL;
}

static void *accept_udp_thread(void *arg) {
    WispersIncomingConnections *incoming = arg;
    while (1) {
        WispersUdpConnectionHandle *conn;
        if (blocking_accept_udp(incoming, &conn, 0x7FFFFFFF)
                != WISPERS_STATUS_SUCCESS)
            break;
        printf("Incoming UDP connection\n");
        pthread_t t;
        pthread_create(&t, NULL, handle_udp_thread, conn);
        pthread_detach(t);
    }
    return NULL;
}

static void handle_quic_connection(WispersQuicConnectionHandle *conn) {
    WispersQuicStreamHandle *stream;
    if (blocking_quic_accept_stream(conn, &stream, 10000)
            != WISPERS_STATUS_SUCCESS)
        return;

    uint8_t buf[1024];
    size_t len;
    if (blocking_quic_read(stream, buf, sizeof(buf), &len, 10000)
            != WISPERS_STATUS_SUCCESS) {
        wispers_quic_stream_free(stream);
        return;
    }

    printf("  Received %zu bytes: %.*s\n", len, (int)len, buf);

    if (len >= 4 && memcmp(buf, "PING", 4) == 0) {
        printf("  Sending PONG\n");
        blocking_quic_write(stream, (const uint8_t *)"PONG\n", 5, 10000);
        blocking_quic_finish(stream, 10000);
    }

    wispers_quic_stream_free(stream);
}

static void *handle_udp_thread(void *arg) {
    WispersUdpConnectionHandle *conn = arg;
    while (1) {
        uint8_t buf[1024];
        size_t len;
        if (blocking_udp_recv(conn, buf, sizeof(buf), &len, 30000)
                != WISPERS_STATUS_SUCCESS)
            break;
        if (len == 4 && memcmp(buf, "ping", 4) == 0) {
            printf("  Received ping, sending pong\n");
            wispers_udp_connection_send(conn, (const uint8_t *)"pong", 4);
        } else {
            printf("  Received %zu bytes\n", len);
        }
    }
    wispers_udp_connection_close(conn);
    return NULL;
}

//==============================================================================
// Node context helpers
//==============================================================================

static int node_init(NodeContext *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->storage = create_storage(&ctx->file_ctx);
    if (!ctx->storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }
    WispersStatus s = blocking_restore_or_init(
        ctx->storage, &ctx->node, &ctx->state, 10000);
    if (s != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n", status_str(s));
        node_cleanup(ctx);
        return 1;
    }
    return 0;
}

static void node_cleanup(NodeContext *ctx) {
    if (ctx->node)    wispers_node_free(ctx->node);
    if (ctx->storage) wispers_storage_free(ctx->storage);
    free(ctx->file_ctx);
    memset(ctx, 0, sizeof(*ctx));
}

//==============================================================================
// Display helpers
//==============================================================================

static void print_group(WispersNodeHandle *node) {
    WispersGroupInfo *gi;
    if (blocking_group_info(node, &gi, 10000) != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "  (failed to get group info)\n");
        return;
    }
    printf("  Group state: %s\n", group_state_str(wispers_group_info_state(gi)));
    size_t count = wispers_group_info_nodes_count(gi);
    for (size_t i = 0; i < count; i++) {
        const WispersNode *n = wispers_group_info_node_at(gi, i);
        const char *name = wispers_node_name(n);
        printf("  Node %d: %s — %s%s%s\n",
               wispers_node_number(n),
               name ? name : "(unnamed)",
               activation_status_str(wispers_node_activation_status(n)),
               wispers_node_is_self(n) ? " (self)" : "",
               wispers_node_is_online(n) ? " [online]" : "");
    }
    wispers_group_info_free(gi);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s [--hub ADDR] [--storage DIR] status\n"
        "  %s [--hub ADDR] [--storage DIR] register <token>\n"
        "  %s [--hub ADDR] [--storage DIR] activate <code>\n"
        "  %s [--hub ADDR] [--storage DIR] nodes\n"
        "  %s [--hub ADDR] [--storage DIR] serve\n"
        "  %s [--hub ADDR] [--storage DIR] ping [--quic] <node>\n",
        prog, prog, prog, prog, prog, prog);
}

static const char *status_str(WispersStatus s) {
    switch (s) {
    case WISPERS_STATUS_SUCCESS:                 return "SUCCESS";
    case WISPERS_STATUS_NULL_POINTER:            return "NULL_POINTER";
    case WISPERS_STATUS_INVALID_UTF8:            return "INVALID_UTF8";
    case WISPERS_STATUS_STORE_ERROR:             return "STORE_ERROR";
    case WISPERS_STATUS_ALREADY_REGISTERED:      return "ALREADY_REGISTERED";
    case WISPERS_STATUS_NOT_REGISTERED:          return "NOT_REGISTERED";
    case WISPERS_STATUS_NOT_FOUND:               return "NOT_FOUND";
    case WISPERS_STATUS_BUFFER_TOO_SMALL:        return "BUFFER_TOO_SMALL";
    case WISPERS_STATUS_MISSING_CALLBACK:        return "MISSING_CALLBACK";
    case WISPERS_STATUS_INVALID_ACTIVATION_CODE: return "INVALID_ACTIVATION_CODE";
    case WISPERS_STATUS_ACTIVATION_FAILED:       return "ACTIVATION_FAILED";
    case WISPERS_STATUS_HUB_ERROR:               return "HUB_ERROR";
    case WISPERS_STATUS_CONNECTION_FAILED:        return "CONNECTION_FAILED";
    case WISPERS_STATUS_TIMEOUT:                 return "TIMEOUT";
    case WISPERS_STATUS_INVALID_STATE:           return "INVALID_STATE";
    default:                                     return "UNKNOWN";
    }
}

static const char *state_str(WispersNodeState s) {
    switch (s) {
    case WISPERS_NODE_STATE_PENDING:    return "Pending";
    case WISPERS_NODE_STATE_REGISTERED: return "Registered";
    case WISPERS_NODE_STATE_ACTIVATED:  return "Activated";
    default:                            return "Unknown";
    }
}

static const char *group_state_str(WispersGroupState s) {
    switch (s) {
    case WISPERS_GROUP_STATE_ALONE:           return "Alone";
    case WISPERS_GROUP_STATE_BOOTSTRAP:       return "Bootstrap";
    case WISPERS_GROUP_STATE_NEED_ACTIVATION: return "NeedActivation";
    case WISPERS_GROUP_STATE_CAN_ENDORSE:     return "CanEndorse";
    case WISPERS_GROUP_STATE_ALL_ACTIVATED:    return "AllActivated";
    default:                                  return "Unknown";
    }
}

static const char *activation_status_str(int s) {
    switch (s) {
    case WISPERS_ACTIVATION_UNKNOWN:       return "Unknown";
    case WISPERS_ACTIVATION_NOT_ACTIVATED: return "NotActivated";
    case WISPERS_ACTIVATION_ACTIVATED:     return "Activated";
    default:                               return "Unknown";
    }
}

//==============================================================================
// Blocking wrappers
//
// Each wrapper: create context → start async op → wait → return status.
// The sync primitives and callback functions are defined further below.
//==============================================================================

// Forward-declare the sync helpers and callbacks used by blocking wrappers.
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             called;
} SyncState;

static void sync_init(SyncState *s);
static void sync_signal(SyncState *s);
static int  sync_wait(SyncState *s, int timeout_ms);
static void sync_destroy(SyncState *s);

// --- Context structs and callbacks ---

typedef struct { SyncState sync; WispersStatus status; } BasicCtx;

static void basic_cb(void *ctx, WispersStatus status, const char *d) {
    (void)d; BasicCtx *c = ctx; c->status = status; sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersNodeHandle *handle; WispersNodeState state;
} InitCtx;

static void init_cb(void *ctx, WispersStatus status, const char *d,
                     WispersNodeHandle *h, WispersNodeState st) {
    (void)d; InitCtx *c = ctx;
    c->status = status; c->handle = h; c->state = st;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersGroupInfo *info;
} GroupInfoCtx;

static void group_info_cb(void *ctx, WispersStatus status, const char *d,
                           WispersGroupInfo *gi) {
    (void)d; GroupInfoCtx *c = ctx; c->status = status; c->info = gi;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersServingHandle *serving;
    WispersServingSession *session;
    WispersIncomingConnections *incoming;
} ServingCtx;

static void serving_cb(void *ctx, WispersStatus status, const char *d,
                        WispersServingHandle *sv, WispersServingSession *ss,
                        WispersIncomingConnections *ic) {
    (void)d; ServingCtx *c = ctx;
    c->status = status; c->serving = sv; c->session = ss; c->incoming = ic;
    sync_signal(&c->sync);
}

typedef struct { SyncState sync; WispersStatus status; char *code; } ActivationCodeCtx;

static void activation_code_cb(void *ctx, WispersStatus status, const char *d,
                                char *code) {
    (void)d; ActivationCodeCtx *c = ctx; c->status = status; c->code = code;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersQuicConnectionHandle *conn;
} QuicConnCtx;

static void quic_conn_cb(void *ctx, WispersStatus status, const char *d,
                          WispersQuicConnectionHandle *conn) {
    (void)d; QuicConnCtx *c = ctx; c->status = status; c->conn = conn;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersQuicStreamHandle *stream;
} QuicStreamCtx;

static void quic_stream_cb(void *ctx, WispersStatus status, const char *d,
                            WispersQuicStreamHandle *stream) {
    (void)d; QuicStreamCtx *c = ctx; c->status = status; c->stream = stream;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    WispersUdpConnectionHandle *conn;
} UdpConnCtx;

static void udp_conn_cb(void *ctx, WispersStatus status, const char *d,
                         WispersUdpConnectionHandle *conn) {
    (void)d; UdpConnCtx *c = ctx; c->status = status; c->conn = conn;
    sync_signal(&c->sync);
}

typedef struct {
    SyncState sync; WispersStatus status;
    uint8_t data[4096]; size_t len;
} DataCtx;

static void data_cb(void *ctx, WispersStatus status, const char *d,
                     const uint8_t *data, size_t len) {
    (void)d; DataCtx *c = ctx; c->status = status;
    if (len > sizeof(c->data)) len = sizeof(c->data);
    if (data && len > 0) memcpy(c->data, data, len);
    c->len = len;
    sync_signal(&c->sync);
}

// --- Wrapper implementations ---

static WispersStatus blocking_restore_or_init(WispersNodeStorageHandle *storage,
    WispersNodeHandle **out_node, WispersNodeState *out_state, int timeout_ms)
{
    InitCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_storage_restore_or_init_async(storage, &ctx, init_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) {
        *out_node = ctx.handle;
        *out_state = ctx.state;
    }
    return ctx.status;
}

static WispersStatus blocking_register(WispersNodeHandle *node,
    const char *token, int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_register_async(node, token, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_activate(WispersNodeHandle *node,
    const char *code, int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_activate_async(node, code, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_group_info(WispersNodeHandle *node,
    WispersGroupInfo **out, int timeout_ms)
{
    GroupInfoCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_group_info_async(node, &ctx, group_info_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.info;
    return ctx.status;
}

static WispersStatus blocking_start_serving(WispersNodeHandle *node,
    WispersServingHandle **out_serving, WispersServingSession **out_session,
    WispersIncomingConnections **out_incoming, int timeout_ms)
{
    ServingCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_start_serving_async(node, &ctx, serving_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) {
        *out_serving = ctx.serving;
        *out_session = ctx.session;
        *out_incoming = ctx.incoming;
    }
    return ctx.status;
}

static WispersStatus blocking_generate_activation_code(
    WispersServingHandle *serving, char **out_code, int timeout_ms)
{
    ActivationCodeCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_serving_handle_generate_activation_code_async(
        serving, &ctx, activation_code_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out_code = ctx.code;
    return ctx.status;
}

static WispersStatus blocking_serving_run(WispersServingSession *session,
    int timeout_ms)
{
    // Note: session handle is CONSUMED by run_async on success.
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_serving_session_run_async(session, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) {
        sync_destroy(&ctx.sync);
        wispers_serving_session_free(session);
        return s;
    }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_shutdown(WispersServingHandle *serving,
    int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_serving_handle_shutdown_async(serving, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_connect_udp(WispersNodeHandle *node,
    int32_t peer, WispersUdpConnectionHandle **out, int timeout_ms)
{
    UdpConnCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_connect_udp_async(node, peer, &ctx, udp_conn_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.conn;
    return ctx.status;
}

static WispersStatus blocking_udp_recv(WispersUdpConnectionHandle *conn,
    uint8_t *buf, size_t buf_size, size_t *out_len, int timeout_ms)
{
    DataCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_udp_connection_recv_async(conn, &ctx, data_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) {
        size_t n = ctx.len < buf_size ? ctx.len : buf_size;
        memcpy(buf, ctx.data, n);
        *out_len = n;
    }
    return ctx.status;
}

static WispersStatus blocking_accept_udp(WispersIncomingConnections *incoming,
    WispersUdpConnectionHandle **out, int timeout_ms)
{
    UdpConnCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_incoming_accept_udp_async(incoming, &ctx, udp_conn_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.conn;
    return ctx.status;
}

static WispersStatus blocking_connect_quic(WispersNodeHandle *node,
    int32_t peer, WispersQuicConnectionHandle **out, int timeout_ms)
{
    QuicConnCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_node_connect_quic_async(node, peer, &ctx, quic_conn_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.conn;
    return ctx.status;
}

static WispersStatus blocking_accept_quic(WispersIncomingConnections *incoming,
    WispersQuicConnectionHandle **out, int timeout_ms)
{
    QuicConnCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_incoming_accept_quic_async(incoming, &ctx, quic_conn_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.conn;
    return ctx.status;
}

static WispersStatus blocking_quic_open_stream(WispersQuicConnectionHandle *conn,
    WispersQuicStreamHandle **out, int timeout_ms)
{
    QuicStreamCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_connection_open_stream_async(conn, &ctx, quic_stream_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.stream;
    return ctx.status;
}

static WispersStatus blocking_quic_accept_stream(WispersQuicConnectionHandle *conn,
    WispersQuicStreamHandle **out, int timeout_ms)
{
    QuicStreamCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_connection_accept_stream_async(conn, &ctx, quic_stream_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) *out = ctx.stream;
    return ctx.status;
}

static WispersStatus blocking_quic_write(WispersQuicStreamHandle *stream,
    const uint8_t *data, size_t len, int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_stream_write_async(stream, data, len, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_quic_read(WispersQuicStreamHandle *stream,
    uint8_t *buf, size_t buf_size, size_t *out_len, int timeout_ms)
{
    DataCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_stream_read_async(stream, buf_size, &ctx, data_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    if (ctx.status == WISPERS_STATUS_SUCCESS) {
        size_t n = ctx.len < buf_size ? ctx.len : buf_size;
        memcpy(buf, ctx.data, n);
        *out_len = n;
    }
    return ctx.status;
}

static WispersStatus blocking_quic_finish(WispersQuicStreamHandle *stream,
    int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_stream_finish_async(stream, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

static WispersStatus blocking_quic_close(WispersQuicConnectionHandle *conn,
    int timeout_ms)
{
    BasicCtx ctx = {0};
    sync_init(&ctx.sync);
    WispersStatus s = wispers_quic_connection_close_async(conn, &ctx, basic_cb);
    if (s != WISPERS_STATUS_SUCCESS) { sync_destroy(&ctx.sync); return s; }
    if (!sync_wait(&ctx.sync, timeout_ms)) { sync_destroy(&ctx.sync); return WISPERS_STATUS_TIMEOUT; }
    sync_destroy(&ctx.sync);
    return ctx.status;
}

//==============================================================================
// Sync primitives
//==============================================================================

static void sync_init(SyncState *s) {
    pthread_mutex_init(&s->mutex, NULL);
    pthread_cond_init(&s->cond, NULL);
    s->called = 0;
}

static void sync_destroy(SyncState *s) {
    pthread_mutex_destroy(&s->mutex);
    pthread_cond_destroy(&s->cond);
}

static void sync_signal(SyncState *s) {
    pthread_mutex_lock(&s->mutex);
    s->called = 1;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mutex);
}

static int sync_wait(SyncState *s, int timeout_ms) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec  += 1;
        deadline.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&s->mutex);
    while (!s->called) {
        if (pthread_cond_timedwait(&s->cond, &s->mutex, &deadline) == ETIMEDOUT) {
            pthread_mutex_unlock(&s->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&s->mutex);
    return 1;
}

//==============================================================================
// File-based storage
//==============================================================================

#define ROOT_KEY_FILE     "root_key.bin"
#define REGISTRATION_FILE "registration.pb"

typedef struct { char dir[512]; } FileStorageCtx;

static void build_path(char *out, size_t n, const char *dir, const char *file) {
    snprintf(out, n, "%s/%s", dir, file);
}

static WispersStatus fs_load_root_key(void *ctx, uint8_t *out, size_t out_len) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, ROOT_KEY_FILE);
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? WISPERS_STATUS_NOT_FOUND : WISPERS_STATUS_STORE_ERROR;
    size_t n = fread(out, 1, out_len, f); fclose(f);
    return n == out_len ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static WispersStatus fs_save_root_key(void *ctx, const uint8_t *key, size_t len) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, ROOT_KEY_FILE);
    FILE *f = fopen(path, "wb");
    if (!f) return WISPERS_STATUS_STORE_ERROR;
    size_t n = fwrite(key, 1, len, f); fclose(f);
    return n == len ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static WispersStatus fs_delete_root_key(void *ctx) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, ROOT_KEY_FILE);
    return (unlink(path) == 0 || errno == ENOENT) ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static WispersStatus fs_load_registration(void *ctx, uint8_t *buf, size_t buf_len, size_t *out_len) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, REGISTRATION_FILE);
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? WISPERS_STATUS_NOT_FOUND : WISPERS_STATUS_STORE_ERROR;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return WISPERS_STATUS_STORE_ERROR; }
    *out_len = (size_t)sz;
    if ((size_t)sz > buf_len) { fclose(f); return WISPERS_STATUS_BUFFER_TOO_SMALL; }
    size_t n = fread(buf, 1, (size_t)sz, f); fclose(f);
    return n == (size_t)sz ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static WispersStatus fs_save_registration(void *ctx, const uint8_t *buf, size_t len) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, REGISTRATION_FILE);
    FILE *f = fopen(path, "wb");
    if (!f) return WISPERS_STATUS_STORE_ERROR;
    size_t n = fwrite(buf, 1, len, f); fclose(f);
    return n == len ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static WispersStatus fs_delete_registration(void *ctx) {
    char path[600]; build_path(path, sizeof(path), ((FileStorageCtx*)ctx)->dir, REGISTRATION_FILE);
    return (unlink(path) == 0 || errno == ENOENT) ? WISPERS_STATUS_SUCCESS : WISPERS_STATUS_STORE_ERROR;
}

static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    }
    mkdir(tmp, 0700);
}

static void default_storage_path(char *out, size_t n) {
#ifdef __APPLE__
    const char *home = getenv("HOME");
    snprintf(out, n, "%s/Library/Application Support/wconnect/default", home ? home : "/tmp");
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0]) {
        snprintf(out, n, "%s/wconnect/default", xdg);
    } else {
        const char *home = getenv("HOME");
        snprintf(out, n, "%s/.config/wconnect/default", home ? home : "/tmp");
    }
#endif
}

static WispersNodeStorageHandle *create_storage(void **out_file_ctx) {
    FileStorageCtx *fctx = calloc(1, sizeof(FileStorageCtx));
    if (!fctx) return NULL;

    if (g_storage_dir) {
        snprintf(fctx->dir, sizeof(fctx->dir), "%s", g_storage_dir);
    } else {
        default_storage_path(fctx->dir, sizeof(fctx->dir));
    }
    mkdir_p(fctx->dir);

    WispersNodeStorageCallbacks cb = {
        .ctx                = fctx,
        .load_root_key      = fs_load_root_key,
        .save_root_key      = fs_save_root_key,
        .delete_root_key    = fs_delete_root_key,
        .load_registration  = fs_load_registration,
        .save_registration  = fs_save_registration,
        .delete_registration = fs_delete_registration,
    };
    WispersNodeStorageHandle *storage = wispers_storage_new_with_callbacks(&cb);

    if (g_hub_addr) wispers_storage_override_hub_addr(storage, g_hub_addr);
    if (out_file_ctx) *out_file_ctx = fctx;
    return storage;
}
