/**
 * FFI Demo Program
 *
 * Demonstrates using the wispers-connect C API to:
 * - Initialize/restore node state
 * - Register with hub (if needed)
 * - Activate with a pairing code (if needed)
 * - Serve (for endorsing other nodes)
 * - Ping another node
 *
 * This is a minimal C equivalent of what `wconnect` does.
 *
 * Usage:
 *   ./ffi_demo [--hub <addr>] status              - Show current node state
 *   ./ffi_demo [--hub <addr>] register <token>    - Register with the given token
 *   ./ffi_demo [--hub <addr>] activate <code>     - Activate with pairing code
 *   ./ffi_demo [--hub <addr>] serve [--pairing-code] - Serve and optionally print pairing code
 *   ./ffi_demo [--hub <addr>] ping <node_number>  - Ping another node
 */

#include "wispers_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <stdatomic.h>

//------------------------------------------------------------------------------
// Constants and globals
//------------------------------------------------------------------------------

#define STATE_DIR "/.ffi_demo"
#define ROOT_KEY_FILE "root_key.bin"
#define REGISTRATION_FILE "registration.bin"
#define ROOT_KEY_LEN 32
#define MAX_REGISTRATION_LEN (64 * 1024)

// Global options (parsed from argv before command)
static const char *g_hub_addr = NULL;

// Wait for async callback with timeout (in milliseconds)
#define WAIT_FOR_CALLBACK(ctx, timeout_ms) \
    for (int _i = 0; _i < (timeout_ms) / 10 && !atomic_load(&(ctx).called); _i++) { \
        usleep(10000); \
    }

//------------------------------------------------------------------------------
// Callback contexts
//------------------------------------------------------------------------------

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersStage stage;
    WispersPendingNodeHandle *pending;
    WispersRegisteredNodeHandle *registered;
    WispersActivatedNodeHandle *activated;
} InitCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersRegisteredNodeHandle *registered;
} RegisterCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersActivatedNodeHandle *activated;
} ActivateCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersServingHandle *serving;
    WispersServingSession *session;
    WispersIncomingConnections *incoming;
} ServingCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    char *pairing_code;
} PairingCodeCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
} BasicCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersQuicConnectionHandle *connection;
} QuicConnCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    WispersQuicStreamHandle *stream;
} QuicStreamCtx;

typedef struct {
    atomic_int called;
    WispersStatus status;
    const uint8_t *data;
    size_t len;
} DataCtx;

//------------------------------------------------------------------------------
// Callbacks
//------------------------------------------------------------------------------

static void init_callback(
    void *ctx,
    WispersStatus status,
    WispersStage stage,
    WispersPendingNodeHandle *pending,
    WispersRegisteredNodeHandle *registered,
    WispersActivatedNodeHandle *activated
) {
    InitCtx *c = (InitCtx *)ctx;
    c->status = status;
    c->stage = stage;
    c->pending = pending;
    c->registered = registered;
    c->activated = activated;
    atomic_store(&c->called, 1);
}

static void register_callback(
    void *ctx,
    WispersStatus status,
    WispersRegisteredNodeHandle *registered
) {
    RegisterCtx *c = (RegisterCtx *)ctx;
    c->status = status;
    c->registered = registered;
    atomic_store(&c->called, 1);
}

static void activate_callback(
    void *ctx,
    WispersStatus status,
    WispersActivatedNodeHandle *activated
) {
    ActivateCtx *c = (ActivateCtx *)ctx;
    c->status = status;
    c->activated = activated;
    atomic_store(&c->called, 1);
}

static void serving_callback(
    void *ctx,
    WispersStatus status,
    WispersServingHandle *serving,
    WispersServingSession *session,
    WispersIncomingConnections *incoming
) {
    ServingCtx *c = (ServingCtx *)ctx;
    c->status = status;
    c->serving = serving;
    c->session = session;
    c->incoming = incoming;
    atomic_store(&c->called, 1);
}

static void pairing_code_callback(
    void *ctx,
    WispersStatus status,
    char *pairing_code
) {
    PairingCodeCtx *c = (PairingCodeCtx *)ctx;
    c->status = status;
    c->pairing_code = pairing_code;
    atomic_store(&c->called, 1);
}

static void basic_callback(void *ctx, WispersStatus status) {
    BasicCtx *c = (BasicCtx *)ctx;
    c->status = status;
    atomic_store(&c->called, 1);
}

static void quic_conn_callback(
    void *ctx,
    WispersStatus status,
    WispersQuicConnectionHandle *connection
) {
    QuicConnCtx *c = (QuicConnCtx *)ctx;
    c->status = status;
    c->connection = connection;
    atomic_store(&c->called, 1);
}

static void quic_stream_callback(
    void *ctx,
    WispersStatus status,
    WispersQuicStreamHandle *stream
) {
    QuicStreamCtx *c = (QuicStreamCtx *)ctx;
    c->status = status;
    c->stream = stream;
    atomic_store(&c->called, 1);
}

static void data_callback(
    void *ctx,
    WispersStatus status,
    const uint8_t *data,
    size_t len
) {
    DataCtx *c = (DataCtx *)ctx;
    c->status = status;
    c->data = data;
    c->len = len;
    atomic_store(&c->called, 1);
}

//------------------------------------------------------------------------------
// File-based storage implementation
//------------------------------------------------------------------------------

typedef struct {
    char dir_path[512];  // e.g., "/home/user/.ffi_demo"
} StorageCtx;

static void build_file_path(char *out, size_t out_len, const char *dir, const char *filename) {
    snprintf(out, out_len, "%s/%s", dir, filename);
}

static WispersStatus load_root_key(void *ctx, uint8_t *out_key, size_t out_key_len) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, ROOT_KEY_FILE);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) {
            return WISPERS_STATUS_NOT_FOUND;
        }
        return WISPERS_STATUS_STORE_ERROR;
    }

    size_t read = fread(out_key, 1, out_key_len, f);
    fclose(f);

    if (read != out_key_len) {
        return WISPERS_STATUS_STORE_ERROR;
    }
    return WISPERS_STATUS_SUCCESS;
}

static WispersStatus save_root_key(void *ctx, const uint8_t *key, size_t key_len) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, ROOT_KEY_FILE);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return WISPERS_STATUS_STORE_ERROR;
    }

    size_t written = fwrite(key, 1, key_len, f);
    fclose(f);

    if (written != key_len) {
        return WISPERS_STATUS_STORE_ERROR;
    }
    return WISPERS_STATUS_SUCCESS;
}

static WispersStatus delete_root_key(void *ctx) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, ROOT_KEY_FILE);

    if (unlink(path) != 0 && errno != ENOENT) {
        return WISPERS_STATUS_STORE_ERROR;
    }
    return WISPERS_STATUS_SUCCESS;
}

static WispersStatus load_registration(void *ctx, uint8_t *buffer, size_t buffer_len, size_t *out_len) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, REGISTRATION_FILE);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) {
            return WISPERS_STATUS_NOT_FOUND;
        }
        return WISPERS_STATUS_STORE_ERROR;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        fclose(f);
        return WISPERS_STATUS_STORE_ERROR;
    }

    if ((size_t)size > buffer_len) {
        fclose(f);
        return WISPERS_STATUS_BUFFER_TOO_SMALL;
    }

    size_t read = fread(buffer, 1, (size_t)size, f);
    fclose(f);

    if (read != (size_t)size) {
        return WISPERS_STATUS_STORE_ERROR;
    }

    *out_len = (size_t)size;
    return WISPERS_STATUS_SUCCESS;
}

static WispersStatus save_registration(void *ctx, const uint8_t *buffer, size_t buffer_len) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, REGISTRATION_FILE);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return WISPERS_STATUS_STORE_ERROR;
    }

    size_t written = fwrite(buffer, 1, buffer_len, f);
    fclose(f);

    if (written != buffer_len) {
        return WISPERS_STATUS_STORE_ERROR;
    }
    return WISPERS_STATUS_SUCCESS;
}

static WispersStatus delete_registration(void *ctx) {
    StorageCtx *s = (StorageCtx *)ctx;
    char path[600];
    build_file_path(path, sizeof(path), s->dir_path, REGISTRATION_FILE);

    if (unlink(path) != 0 && errno != ENOENT) {
        return WISPERS_STATUS_STORE_ERROR;
    }
    return WISPERS_STATUS_SUCCESS;
}

static WispersNodeStorageHandle *create_storage(StorageCtx **out_ctx) {
    StorageCtx *ctx = calloc(1, sizeof(StorageCtx));
    if (!ctx) {
        return NULL;
    }

    // Build path: $HOME/.ffi_demo
    const char *home = getenv("HOME");
    if (!home) {
        home = "/tmp";
    }
    snprintf(ctx->dir_path, sizeof(ctx->dir_path), "%s%s", home, STATE_DIR);
    mkdir(ctx->dir_path, 0700);  // Create if not exists, ignore errors

    WispersNodeStorageCallbacks callbacks = {
        .ctx = ctx,
        .load_root_key = load_root_key,
        .save_root_key = save_root_key,
        .delete_root_key = delete_root_key,
        .load_registration = load_registration,
        .save_registration = save_registration,
        .delete_registration = delete_registration,
    };
    WispersNodeStorageHandle *storage = wispers_storage_new_with_callbacks(&callbacks);

    // Apply hub override if specified
    if (g_hub_addr != NULL) {
        wispers_storage_override_hub_addr(storage, g_hub_addr);
    }

    if (out_ctx) {
        *out_ctx = ctx;
    }
    return storage;
}

//------------------------------------------------------------------------------
// Helper: get current time in milliseconds
//------------------------------------------------------------------------------

static long long current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

//------------------------------------------------------------------------------
// Helper: status to string
//------------------------------------------------------------------------------

static const char *status_str(WispersStatus status) {
    switch (status) {
        case WISPERS_STATUS_SUCCESS: return "SUCCESS";
        case WISPERS_STATUS_NULL_POINTER: return "NULL_POINTER";
        case WISPERS_STATUS_INVALID_UTF8: return "INVALID_UTF8";
        case WISPERS_STATUS_STORE_ERROR: return "STORE_ERROR";
        case WISPERS_STATUS_ALREADY_REGISTERED: return "ALREADY_REGISTERED";
        case WISPERS_STATUS_NOT_REGISTERED: return "NOT_REGISTERED";
        case WISPERS_STATUS_UNEXPECTED_STAGE: return "UNEXPECTED_STAGE";
        case WISPERS_STATUS_NOT_FOUND: return "NOT_FOUND";
        case WISPERS_STATUS_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
        case WISPERS_STATUS_MISSING_CALLBACK: return "MISSING_CALLBACK";
        case WISPERS_STATUS_INVALID_PAIRING_CODE: return "INVALID_PAIRING_CODE";
        case WISPERS_STATUS_ACTIVATION_FAILED: return "ACTIVATION_FAILED";
        case WISPERS_STATUS_HUB_ERROR: return "HUB_ERROR";
        case WISPERS_STATUS_CONNECTION_FAILED: return "CONNECTION_FAILED";
        case WISPERS_STATUS_TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

//------------------------------------------------------------------------------
// Commands
//------------------------------------------------------------------------------

static void print_usage(const char *program) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [--hub <addr>] status              - Show current node state\n", program);
    fprintf(stderr, "  %s [--hub <addr>] register <token>    - Register with the given token\n", program);
    fprintf(stderr, "  %s [--hub <addr>] activate <code>     - Activate with pairing code\n", program);
    fprintf(stderr, "  %s [--hub <addr>] serve [--pairing-code] - Serve and optionally print pairing code\n", program);
    fprintf(stderr, "  %s [--hub <addr>] ping <node_number>  - Ping another node\n", program);
}

static int cmd_status(void) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    InitCtx ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(ctx, 5000);

    if (!atomic_load(&ctx.called)) {
        fprintf(stderr, "Timeout waiting for restore callback\n");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Restore failed: %s\n", status_str(ctx.status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    switch (ctx.stage) {
        case WISPERS_STAGE_PENDING:
            printf("Node state: Pending (not registered)\n");
            wispers_pending_node_free(ctx.pending);
            break;
        case WISPERS_STAGE_REGISTERED: {
            // Read registration info to get node number
            WispersRegistrationInfo info;
            WispersStatus read_status = wispers_storage_read_registration(storage, &info);
            if (read_status == WISPERS_STATUS_SUCCESS) {
                printf("Node state: Registered (node %d in group %s)\n",
                       info.node_number, info.connectivity_group_id);
                wispers_registration_info_free(&info);
            } else {
                printf("Node state: Registered (unable to read details)\n");
            }
            wispers_registered_node_free(ctx.registered);
            break;
        }
        case WISPERS_STAGE_ACTIVATED: {
            // Read registration info to get node number
            WispersRegistrationInfo info;
            WispersStatus read_status = wispers_storage_read_registration(storage, &info);
            if (read_status == WISPERS_STATUS_SUCCESS) {
                printf("Node state: Activated (node %d in group %s)\n",
                       info.node_number, info.connectivity_group_id);
                wispers_registration_info_free(&info);
            } else {
                printf("Node state: Activated (unable to read details)\n");
            }
            wispers_activated_node_free(ctx.activated);
            break;
        }
        default:
            printf("Node state: Unknown (%d)\n", ctx.stage);
            break;
    }

    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

static int cmd_register(const char *token) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(init_ctx, 5000);

    if (!atomic_load(&init_ctx.called) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                atomic_load(&init_ctx.called) ? status_str(init_ctx.status) : "timeout");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Check we're in pending state
    if (init_ctx.stage != WISPERS_STAGE_PENDING) {
        fprintf(stderr, "Cannot register: already registered (stage=%d)\n", init_ctx.stage);
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Register with the hub
    printf("Registering with hub...\n");
    RegisterCtx reg_ctx = {0};
    status = wispers_pending_node_register_async(init_ctx.pending, token, &reg_ctx, register_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start registration: %s\n", status_str(status));
        wispers_pending_node_free(init_ctx.pending);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait longer for hub communication
    WAIT_FOR_CALLBACK(reg_ctx, 30000);

    if (!atomic_load(&reg_ctx.called)) {
        fprintf(stderr, "Timeout waiting for registration callback\n");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (reg_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Registration failed: %s\n", status_str(reg_ctx.status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Read registration info to get node number
    WispersRegistrationInfo info;
    WispersStatus read_status = wispers_storage_read_registration(storage, &info);
    if (read_status == WISPERS_STATUS_SUCCESS) {
        printf("Registered as node %d in group %s\n", info.node_number, info.connectivity_group_id);
        wispers_registration_info_free(&info);
    } else {
        printf("Registered successfully (unable to read details)\n");
    }

    wispers_registered_node_free(reg_ctx.registered);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

static int cmd_activate(const char *pairing_code) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(init_ctx, 5000);

    if (!atomic_load(&init_ctx.called) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                atomic_load(&init_ctx.called) ? status_str(init_ctx.status) : "timeout");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Check we're in registered state
    if (init_ctx.stage == WISPERS_STAGE_PENDING) {
        fprintf(stderr, "Cannot activate: not registered yet\n");
        wispers_pending_node_free(init_ctx.pending);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }
    if (init_ctx.stage == WISPERS_STAGE_ACTIVATED) {
        fprintf(stderr, "Cannot activate: already activated\n");
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Activate with the pairing code
    printf("Activating with pairing code...\n");
    ActivateCtx act_ctx = {0};
    status = wispers_registered_node_activate_async(init_ctx.registered, pairing_code, &act_ctx, activate_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start activation: %s\n", status_str(status));
        wispers_registered_node_free(init_ctx.registered);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait longer for activation (involves hub communication and potentially P2P)
    WAIT_FOR_CALLBACK(act_ctx, 60000);

    if (!atomic_load(&act_ctx.called)) {
        fprintf(stderr, "Timeout waiting for activation callback\n");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (act_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Activation failed: %s\n", status_str(act_ctx.status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Activation successful!\n");

    wispers_activated_node_free(act_ctx.activated);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

// Handle a single QUIC connection: accept stream, read request, respond with PONG
static void handle_quic_connection(WispersQuicConnectionHandle *conn) {
    // Accept a stream
    QuicStreamCtx stream_ctx = {0};
    WispersStatus status = wispers_quic_connection_accept_stream_async(conn, &stream_ctx, quic_stream_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start accept_stream: %s\n", status_str(status));
        return;
    }

    WAIT_FOR_CALLBACK(stream_ctx, 10000);
    if (!atomic_load(&stream_ctx.called) || stream_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to accept stream: %s\n",
               atomic_load(&stream_ctx.called) ? status_str(stream_ctx.status) : "timeout");
        return;
    }

    printf("  Stream accepted\n");

    // Read the request
    DataCtx read_ctx = {0};
    status = wispers_quic_stream_read_async(stream_ctx.stream, 1024, &read_ctx, data_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start read: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    WAIT_FOR_CALLBACK(read_ctx, 10000);
    if (!atomic_load(&read_ctx.called) || read_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to read: %s\n",
               atomic_load(&read_ctx.called) ? status_str(read_ctx.status) : "timeout");
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    printf("  Received %zu bytes: %.*s\n", read_ctx.len, (int)read_ctx.len, read_ctx.data);

    // Respond with PONG
    const uint8_t pong_data[] = "PONG\n";
    BasicCtx write_ctx = {0};
    status = wispers_quic_stream_write_async(stream_ctx.stream, pong_data, sizeof(pong_data) - 1, &write_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start write: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    WAIT_FOR_CALLBACK(write_ctx, 10000);
    if (!atomic_load(&write_ctx.called) || write_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to write PONG: %s\n",
               atomic_load(&write_ctx.called) ? status_str(write_ctx.status) : "timeout");
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    // Finish the stream
    BasicCtx finish_ctx = {0};
    status = wispers_quic_stream_finish_async(stream_ctx.stream, &finish_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start finish: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    WAIT_FOR_CALLBACK(finish_ctx, 10000);
    printf("  Sent PONG response\n");

    wispers_quic_stream_free(stream_ctx.stream);
}

static int cmd_serve(int print_pairing_code) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(init_ctx, 5000);

    if (!atomic_load(&init_ctx.called) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                atomic_load(&init_ctx.called) ? status_str(init_ctx.status) : "timeout");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Must be registered or activated to serve
    if (init_ctx.stage == WISPERS_STAGE_PENDING) {
        fprintf(stderr, "Cannot serve: not registered yet\n");
        wispers_pending_node_free(init_ctx.pending);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Start serving based on stage
    ServingCtx serv_ctx = {0};
    if (init_ctx.stage == WISPERS_STAGE_REGISTERED) {
        printf("Starting serving session (registered node - bootstrap only)...\n");
        status = wispers_registered_node_start_serving_async(init_ctx.registered, &serv_ctx, serving_callback);
    } else {
        printf("Starting serving session (activated node)...\n");
        status = wispers_activated_node_start_serving_async(init_ctx.activated, &serv_ctx, serving_callback);
    }

    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start serving: %s\n", status_str(status));
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait for serving to start
    WAIT_FOR_CALLBACK(serv_ctx, 30000);

    if (!atomic_load(&serv_ctx.called)) {
        fprintf(stderr, "Timeout waiting for serving callback\n");
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (serv_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start serving: %s\n", status_str(serv_ctx.status));
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Serving session started\n");

    // Generate and print pairing code if requested
    if (print_pairing_code) {
        PairingCodeCtx pc_ctx = {0};
        status = wispers_serving_handle_generate_pairing_code_async(serv_ctx.serving, &pc_ctx, pairing_code_callback);
        if (status == WISPERS_STATUS_SUCCESS) {
            WAIT_FOR_CALLBACK(pc_ctx, 10000);
            if (atomic_load(&pc_ctx.called) && pc_ctx.status == WISPERS_STATUS_SUCCESS && pc_ctx.pairing_code) {
                printf("Pairing code: %s\n", pc_ctx.pairing_code);
                wispers_string_free(pc_ctx.pairing_code);
            } else if (atomic_load(&pc_ctx.called)) {
                fprintf(stderr, "Failed to generate pairing code: %s\n", status_str(pc_ctx.status));
            } else {
                fprintf(stderr, "Timeout generating pairing code\n");
            }
        } else {
            fprintf(stderr, "Failed to start pairing code generation: %s\n", status_str(status));
        }
    }

    printf("Serving... (press Ctrl-C to stop)\n");

    // Run the serving session in background
    BasicCtx run_ctx = {0};
    status = wispers_serving_session_run_async(serv_ctx.session, &run_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to run serving session: %s\n", status_str(status));
        wispers_serving_handle_free(serv_ctx.serving);
        wispers_serving_session_free(serv_ctx.session);
        wispers_incoming_connections_free(serv_ctx.incoming);
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // If activated, handle incoming QUIC connections with ping/pong responder
    if (serv_ctx.incoming != NULL) {
        printf("Listening for incoming QUIC connections...\n");
        while (!atomic_load(&run_ctx.called)) {
            // Try to accept an incoming QUIC connection
            QuicConnCtx conn_ctx = {0};
            status = wispers_incoming_accept_quic_async(serv_ctx.incoming, &conn_ctx, quic_conn_callback);
            if (status != WISPERS_STATUS_SUCCESS) {
                fprintf(stderr, "Failed to start accept_quic: %s\n", status_str(status));
                usleep(1000000);  // Wait 1s before retrying
                continue;
            }

            // Wait for connection with periodic checks if session ended
            while (!atomic_load(&conn_ctx.called) && !atomic_load(&run_ctx.called)) {
                usleep(100000);  // 100ms
            }

            if (atomic_load(&run_ctx.called)) {
                break;  // Session ended
            }

            if (!atomic_load(&conn_ctx.called) || conn_ctx.status != WISPERS_STATUS_SUCCESS) {
                if (atomic_load(&conn_ctx.called)) {
                    printf("Accept connection failed: %s\n", status_str(conn_ctx.status));
                }
                continue;
            }

            printf("Accepted incoming QUIC connection\n");
            handle_quic_connection(conn_ctx.connection);
            wispers_quic_connection_free(conn_ctx.connection);
        }
    } else {
        // Registered node - just wait for session to end
        while (!atomic_load(&run_ctx.called)) {
            usleep(100000);  // 100ms
        }
    }

    printf("Serving session ended: %s\n", status_str(run_ctx.status));

    // Cleanup
    wispers_serving_handle_free(serv_ctx.serving);
    wispers_incoming_connections_free(serv_ctx.incoming);
    if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
    if (init_ctx.activated) wispers_activated_node_free(init_ctx.activated);
    wispers_storage_free(storage);
    free(storage_ctx);
    return run_ctx.status == WISPERS_STATUS_SUCCESS ? 0 : 1;
}

static int cmd_ping(int node_number) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(init_ctx, 5000);

    if (!atomic_load(&init_ctx.called) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                atomic_load(&init_ctx.called) ? status_str(init_ctx.status) : "timeout");
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Must be activated to ping
    if (init_ctx.stage != WISPERS_STAGE_ACTIVATED) {
        fprintf(stderr, "Cannot ping: node must be activated (current stage=%d)\n", init_ctx.stage);
        if (init_ctx.pending) wispers_pending_node_free(init_ctx.pending);
        if (init_ctx.registered) wispers_registered_node_free(init_ctx.registered);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Connecting to node %d via QUIC...\n", node_number);
    long long start_time = current_time_ms();

    // Connect via QUIC
    QuicConnCtx conn_ctx = {0};
    status = wispers_activated_node_connect_quic_async(init_ctx.activated, node_number, &conn_ctx, quic_conn_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start QUIC connection: %s\n", status_str(status));
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait for connection (up to 30 seconds for NAT traversal)
    WAIT_FOR_CALLBACK(conn_ctx, 30000);

    if (!atomic_load(&conn_ctx.called)) {
        fprintf(stderr, "Timeout waiting for QUIC connection\n");
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (conn_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "QUIC connection failed: %s\n", status_str(conn_ctx.status));
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Connected, opening stream...\n");

    // Open a stream
    QuicStreamCtx stream_ctx = {0};
    status = wispers_quic_connection_open_stream_async(conn_ctx.connection, &stream_ctx, quic_stream_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to open stream: %s\n", status_str(status));
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(stream_ctx, 10000);

    if (!atomic_load(&stream_ctx.called) || stream_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to open stream: %s\n",
                atomic_load(&stream_ctx.called) ? status_str(stream_ctx.status) : "timeout");
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Write PING
    const uint8_t ping_data[] = "PING\n";
    BasicCtx write_ctx = {0};
    status = wispers_quic_stream_write_async(stream_ctx.stream, ping_data, sizeof(ping_data) - 1, &write_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PING: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(write_ctx, 10000);

    if (!atomic_load(&write_ctx.called) || write_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to write PING: %s\n",
                atomic_load(&write_ctx.called) ? status_str(write_ctx.status) : "timeout");
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Finish write side
    BasicCtx finish_ctx = {0};
    status = wispers_quic_stream_finish_async(stream_ctx.stream, &finish_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to finish stream: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(finish_ctx, 10000);

    if (!atomic_load(&finish_ctx.called) || finish_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to finish stream: %s\n",
                atomic_load(&finish_ctx.called) ? status_str(finish_ctx.status) : "timeout");
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Read response
    DataCtx read_ctx = {0};
    status = wispers_quic_stream_read_async(stream_ctx.stream, 1024, &read_ctx, data_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to read response: %s\n", status_str(status));
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    WAIT_FOR_CALLBACK(read_ctx, 10000);

    long long end_time = current_time_ms();
    long long elapsed = end_time - start_time;

    if (!atomic_load(&read_ctx.called)) {
        fprintf(stderr, "Timeout waiting for PONG response\n");
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (read_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to read response: %s\n", status_str(read_ctx.status));
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        wispers_activated_node_free(init_ctx.activated);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Check for PONG response
    if (read_ctx.len >= 4 && memcmp(read_ctx.data, "PONG", 4) == 0) {
        printf("PONG from node %d in %lldms\n", node_number, elapsed);
    } else {
        printf("Got response from node %d in %lldms: ", node_number, elapsed);
        fwrite(read_ctx.data, 1, read_ctx.len, stdout);
        printf("\n");
    }

    // Cleanup
    wispers_quic_stream_free(stream_ctx.stream);

    BasicCtx close_ctx = {0};
    wispers_quic_connection_close_async(conn_ctx.connection, &close_ctx, basic_callback);
    WAIT_FOR_CALLBACK(close_ctx, 5000);

    wispers_activated_node_free(init_ctx.activated);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

//------------------------------------------------------------------------------
// Main
//------------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    // Parse global options (--hub)
    int arg_idx = 1;
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "--hub") == 0) {
            if (arg_idx + 1 >= argc) {
                fprintf(stderr, "--hub requires an address argument\n");
                return 1;
            }
            g_hub_addr = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "--help") == 0 || strcmp(argv[arg_idx], "-h") == 0) {
            print_usage(argv[0]);
            return 0;  // Success for help
        } else {
            // Unknown option, might be command-specific flag
            break;
        }
    }

    if (arg_idx >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[arg_idx];
    arg_idx++;

    if (strcmp(command, "status") == 0) {
        return cmd_status();
    } else if (strcmp(command, "register") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "register: missing token argument\n");
            return 1;
        }
        return cmd_register(argv[arg_idx]);
    } else if (strcmp(command, "activate") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "activate: missing pairing code argument\n");
            return 1;
        }
        return cmd_activate(argv[arg_idx]);
    } else if (strcmp(command, "serve") == 0) {
        // Check for --pairing-code flag
        int print_pairing_code = 0;
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "--pairing-code") == 0) {
                print_pairing_code = 1;
            } else {
                fprintf(stderr, "serve: unknown argument: %s\n", argv[arg_idx]);
                return 1;
            }
            arg_idx++;
        }
        return cmd_serve(print_pairing_code);
    } else if (strcmp(command, "ping") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "ping: missing node number argument\n");
            return 1;
        }
        int node_number = atoi(argv[arg_idx]);
        return cmd_ping(node_number);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
}
