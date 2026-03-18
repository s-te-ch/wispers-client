/**
 * FFI Demo Program
 *
 * Demonstrates using the wispers-connect C API (unified node handle) to:
 * - Initialize/restore node state
 * - Register with hub (if needed)
 * - Activate with an activation code (if needed)
 * - Serve (for endorsing other nodes)
 * - Ping another node
 *
 * This is a minimal C equivalent of what `wconnect` does.
 *
 * Usage:
 *   ./ffi_demo [--hub <addr>] status              - Show current node state
 *   ./ffi_demo [--hub <addr>] register <token>    - Register with the given token
 *   ./ffi_demo [--hub <addr>] activate <code>     - Activate with activation code
 *   ./ffi_demo [--hub <addr>] serve [--activation-code] - Serve and optionally print activation code
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
#include <pthread.h>

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

//------------------------------------------------------------------------------
// Synchronization helpers using condition variables
//------------------------------------------------------------------------------

// All callback contexts embed this struct for synchronization
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int called;
} SyncState;

// Initialize synchronization state (call before starting async operation)
static void sync_init(SyncState *s) {
    pthread_mutex_init(&s->mutex, NULL);
    pthread_cond_init(&s->cond, NULL);
    s->called = 0;
}

// Clean up synchronization state (call when done with context)
static void sync_destroy(SyncState *s) {
    pthread_mutex_destroy(&s->mutex);
    pthread_cond_destroy(&s->cond);
}

// Signal completion (call from callback, AFTER setting all other fields)
static void sync_signal(SyncState *s) {
    pthread_mutex_lock(&s->mutex);
    s->called = 1;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mutex);
}

// Wait for completion with timeout. Returns 1 if signaled, 0 if timeout.
static int sync_wait(SyncState *s, int timeout_ms) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&s->mutex);
    while (!s->called) {
        int rc = pthread_cond_timedwait(&s->cond, &s->mutex, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&s->mutex);
            return 0;  // Timeout
        }
    }
    pthread_mutex_unlock(&s->mutex);
    return 1;  // Signaled
}

// Check if signaled (non-blocking)
static int sync_is_called(SyncState *s) {
    pthread_mutex_lock(&s->mutex);
    int called = s->called;
    pthread_mutex_unlock(&s->mutex);
    return called;
}

//------------------------------------------------------------------------------
// Callback contexts
//------------------------------------------------------------------------------

typedef struct {
    SyncState sync;
    WispersStatus status;
    WispersNodeState state;
    WispersNodeHandle *handle;
} InitCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
    WispersServingHandle *serving;
    WispersServingSession *session;
    WispersIncomingConnections *incoming;
} ServingCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
    char *activation_code;
} ActivationCodeCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
} BasicCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
    WispersQuicConnectionHandle *connection;
} QuicConnCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
    WispersQuicStreamHandle *stream;
} QuicStreamCtx;

typedef struct {
    SyncState sync;
    WispersStatus status;
    uint8_t data[1024];  // Copy of data (buffer only valid during callback)
    size_t len;
} DataCtx;

//------------------------------------------------------------------------------
// Callbacks
//------------------------------------------------------------------------------

static void init_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersNodeHandle *handle,
    WispersNodeState state
) {
    (void)error_detail;
    InitCtx *c = (InitCtx *)ctx;
    c->status = status;
    c->state = state;
    c->handle = handle;
    sync_signal(&c->sync);
}

static void serving_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersServingHandle *serving,
    WispersServingSession *session,
    WispersIncomingConnections *incoming
) {
    (void)error_detail;
    ServingCtx *c = (ServingCtx *)ctx;
    c->status = status;
    c->serving = serving;
    c->session = session;
    c->incoming = incoming;
    sync_signal(&c->sync);
}

static void activation_code_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    char *activation_code
) {
    (void)error_detail;
    ActivationCodeCtx *c = (ActivationCodeCtx *)ctx;
    c->status = status;
    c->activation_code = activation_code;
    sync_signal(&c->sync);
}

static void basic_callback(void *ctx, WispersStatus status, const char *error_detail) {
    (void)error_detail;
    BasicCtx *c = (BasicCtx *)ctx;
    c->status = status;
    sync_signal(&c->sync);
}

static void quic_conn_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersQuicConnectionHandle *connection
) {
    (void)error_detail;
    QuicConnCtx *c = (QuicConnCtx *)ctx;
    c->status = status;
    c->connection = connection;
    sync_signal(&c->sync);
}

static void quic_stream_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersQuicStreamHandle *stream
) {
    (void)error_detail;
    QuicStreamCtx *c = (QuicStreamCtx *)ctx;
    c->status = status;
    c->stream = stream;
    sync_signal(&c->sync);
}

static void data_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    const uint8_t *data,
    size_t len
) {
    (void)error_detail;
    DataCtx *c = (DataCtx *)ctx;
    c->status = status;
    // Copy data - the buffer is only valid during the callback
    if (len > sizeof(c->data)) {
        len = sizeof(c->data);
    }
    if (data && len > 0) {
        memcpy(c->data, data, len);
    }
    c->len = len;
    sync_signal(&c->sync);
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
        case WISPERS_STATUS_NOT_FOUND: return "NOT_FOUND";
        case WISPERS_STATUS_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
        case WISPERS_STATUS_MISSING_CALLBACK: return "MISSING_CALLBACK";
        case WISPERS_STATUS_INVALID_ACTIVATION_CODE: return "INVALID_ACTIVATION_CODE";
        case WISPERS_STATUS_ACTIVATION_FAILED: return "ACTIVATION_FAILED";
        case WISPERS_STATUS_HUB_ERROR: return "HUB_ERROR";
        case WISPERS_STATUS_CONNECTION_FAILED: return "CONNECTION_FAILED";
        case WISPERS_STATUS_TIMEOUT: return "TIMEOUT";
        case WISPERS_STATUS_INVALID_STATE: return "INVALID_STATE";
        default: return "UNKNOWN";
    }
}

static const char *state_str(WispersNodeState state) {
    switch (state) {
        case WISPERS_NODE_STATE_PENDING: return "Pending";
        case WISPERS_NODE_STATE_REGISTERED: return "Registered";
        case WISPERS_NODE_STATE_ACTIVATED: return "Activated";
        default: return "Unknown";
    }
}

//------------------------------------------------------------------------------
// Commands
//------------------------------------------------------------------------------

static void print_usage(const char *program) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [--hub <addr>] status              - Show current node state\n", program);
    fprintf(stderr, "  %s [--hub <addr>] register <token>    - Register with the given token\n", program);
    fprintf(stderr, "  %s [--hub <addr>] activate <code>     - Activate with activation code\n", program);
    fprintf(stderr, "  %s [--hub <addr>] serve [--activation-code] - Serve and optionally print activation code\n", program);
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
    sync_init(&ctx.sync);
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        sync_destroy(&ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&ctx.sync, 5000)) {
        fprintf(stderr, "Timeout waiting for restore callback\n");
        sync_destroy(&ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Restore failed: %s\n", status_str(ctx.status));
        sync_destroy(&ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Read registration info for details (if available)
    WispersRegistrationInfo info;
    WispersStatus read_status = wispers_storage_read_registration(storage, &info);

    if (read_status == WISPERS_STATUS_SUCCESS) {
        printf("Node state: %s (node %d in group %s)\n",
               state_str(ctx.state), info.node_number, info.connectivity_group_id);
        wispers_registration_info_free(&info);
    } else {
        printf("Node state: %s\n", state_str(ctx.state));
    }

    wispers_node_free(ctx.handle);
    sync_destroy(&ctx.sync);
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
    sync_init(&init_ctx.sync);
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&init_ctx.sync, 5000) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                sync_is_called(&init_ctx.sync) ? status_str(init_ctx.status) : "timeout");
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Check we're in pending state
    if (init_ctx.state != WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot register: already registered (state=%s)\n", state_str(init_ctx.state));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Register with the hub
    printf("Registering with hub...\n");
    BasicCtx reg_ctx = {0};
    sync_init(&reg_ctx.sync);
    status = wispers_node_register_async(init_ctx.handle, token, &reg_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start registration: %s\n", status_str(status));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&reg_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait longer for hub communication
    if (!sync_wait(&reg_ctx.sync, 30000)) {
        fprintf(stderr, "Timeout waiting for registration callback\n");
        wispers_node_free(init_ctx.handle);
        sync_destroy(&reg_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (reg_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Registration failed: %s\n", status_str(reg_ctx.status));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&reg_ctx.sync);
        sync_destroy(&init_ctx.sync);
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

    wispers_node_free(init_ctx.handle);
    sync_destroy(&reg_ctx.sync);
    sync_destroy(&init_ctx.sync);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

static int cmd_activate(const char *activation_code) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    sync_init(&init_ctx.sync);
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&init_ctx.sync, 5000) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                sync_is_called(&init_ctx.sync) ? status_str(init_ctx.status) : "timeout");
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Check we're in registered state
    if (init_ctx.state == WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot activate: not registered yet\n");
        wispers_node_free(init_ctx.handle);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }
    if (init_ctx.state == WISPERS_NODE_STATE_ACTIVATED) {
        fprintf(stderr, "Cannot activate: already activated\n");
        wispers_node_free(init_ctx.handle);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Activate with the activation code
    printf("Activating with activation code...\n");
    BasicCtx act_ctx = {0};
    sync_init(&act_ctx.sync);
    status = wispers_node_activate_async(init_ctx.handle, activation_code, &act_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start activation: %s\n", status_str(status));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&act_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait longer for activation (involves hub communication and potentially P2P)
    if (!sync_wait(&act_ctx.sync, 60000)) {
        fprintf(stderr, "Timeout waiting for activation callback\n");
        wispers_node_free(init_ctx.handle);
        sync_destroy(&act_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (act_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Activation failed: %s\n", status_str(act_ctx.status));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&act_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Activation successful!\n");

    wispers_node_free(init_ctx.handle);
    sync_destroy(&act_ctx.sync);
    sync_destroy(&init_ctx.sync);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

// Handle a single QUIC connection: accept stream, read request, respond with PONG
static void handle_quic_connection(WispersQuicConnectionHandle *conn) {
    // Accept a stream
    QuicStreamCtx stream_ctx = {0};
    sync_init(&stream_ctx.sync);
    WispersStatus status = wispers_quic_connection_accept_stream_async(conn, &stream_ctx, quic_stream_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start accept_stream: %s\n", status_str(status));
        sync_destroy(&stream_ctx.sync);
        return;
    }

    if (!sync_wait(&stream_ctx.sync, 10000) || stream_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to accept stream: %s\n",
               sync_is_called(&stream_ctx.sync) ? status_str(stream_ctx.status) : "timeout");
        sync_destroy(&stream_ctx.sync);
        return;
    }

    printf("  Stream accepted\n");

    // Read the request
    DataCtx read_ctx = {0};
    sync_init(&read_ctx.sync);
    status = wispers_quic_stream_read_async(stream_ctx.stream, 1024, &read_ctx, data_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start read: %s\n", status_str(status));
        sync_destroy(&read_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    if (!sync_wait(&read_ctx.sync, 10000) || read_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to read: %s\n",
               sync_is_called(&read_ctx.sync) ? status_str(read_ctx.status) : "timeout");
        sync_destroy(&read_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    printf("  Received %zu bytes: %.*s\n", read_ctx.len, (int)read_ctx.len, read_ctx.data);

    // Respond with PONG
    const uint8_t pong_data[] = "PONG\n";
    BasicCtx write_ctx = {0};
    sync_init(&write_ctx.sync);
    status = wispers_quic_stream_write_async(stream_ctx.stream, pong_data, sizeof(pong_data) - 1, &write_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start write: %s\n", status_str(status));
        sync_destroy(&write_ctx.sync);
        sync_destroy(&read_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    if (!sync_wait(&write_ctx.sync, 10000) || write_ctx.status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to write PONG: %s\n",
               sync_is_called(&write_ctx.sync) ? status_str(write_ctx.status) : "timeout");
        sync_destroy(&write_ctx.sync);
        sync_destroy(&read_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    // Finish the stream
    BasicCtx finish_ctx = {0};
    sync_init(&finish_ctx.sync);
    status = wispers_quic_stream_finish_async(stream_ctx.stream, &finish_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        printf("  Failed to start finish: %s\n", status_str(status));
        sync_destroy(&finish_ctx.sync);
        sync_destroy(&write_ctx.sync);
        sync_destroy(&read_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        wispers_quic_stream_free(stream_ctx.stream);
        return;
    }

    sync_wait(&finish_ctx.sync, 10000);
    printf("  Sent PONG response\n");

    sync_destroy(&finish_ctx.sync);
    sync_destroy(&write_ctx.sync);
    sync_destroy(&read_ctx.sync);
    sync_destroy(&stream_ctx.sync);
    wispers_quic_stream_free(stream_ctx.stream);
}

static int cmd_serve(int print_activation_code) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state to get current stage
    InitCtx init_ctx = {0};
    sync_init(&init_ctx.sync);
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&init_ctx.sync, 5000) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                sync_is_called(&init_ctx.sync) ? status_str(init_ctx.status) : "timeout");
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Must be registered or activated to serve
    if (init_ctx.state == WISPERS_NODE_STATE_PENDING) {
        fprintf(stderr, "Cannot serve: not registered yet\n");
        wispers_node_free(init_ctx.handle);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Start serving
    ServingCtx serv_ctx = {0};
    sync_init(&serv_ctx.sync);
    if (init_ctx.state == WISPERS_NODE_STATE_REGISTERED) {
        printf("Starting serving session (registered node - bootstrap only)...\n");
    } else {
        printf("Starting serving session (activated node)...\n");
    }
    status = wispers_node_start_serving_async(init_ctx.handle, &serv_ctx, serving_callback);

    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start serving: %s\n", status_str(status));
        sync_destroy(&serv_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Wait for serving to start
    if (!sync_wait(&serv_ctx.sync, 30000)) {
        fprintf(stderr, "Timeout waiting for serving callback\n");
        sync_destroy(&serv_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (serv_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start serving: %s\n", status_str(serv_ctx.status));
        sync_destroy(&serv_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Serving session started\n");

    // Generate and print activation code if requested
    if (print_activation_code) {
        ActivationCodeCtx ac_ctx = {0};
        sync_init(&ac_ctx.sync);
        status = wispers_serving_handle_generate_activation_code_async(serv_ctx.serving, &ac_ctx, activation_code_callback);
        if (status == WISPERS_STATUS_SUCCESS) {
            if (sync_wait(&ac_ctx.sync, 10000) && ac_ctx.status == WISPERS_STATUS_SUCCESS && ac_ctx.activation_code) {
                printf("Activation code: %s\n", ac_ctx.activation_code);
                wispers_string_free(ac_ctx.activation_code);
            } else if (sync_is_called(&ac_ctx.sync)) {
                fprintf(stderr, "Failed to generate activation code: %s\n", status_str(ac_ctx.status));
            } else {
                fprintf(stderr, "Timeout generating activation code\n");
            }
        } else {
            fprintf(stderr, "Failed to start activation code generation: %s\n", status_str(status));
        }
        sync_destroy(&ac_ctx.sync);
    }

    printf("Serving... (press Ctrl-C to stop)\n");

    // Run the serving session in background
    BasicCtx run_ctx = {0};
    sync_init(&run_ctx.sync);
    status = wispers_serving_session_run_async(serv_ctx.session, &run_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to run serving session: %s\n", status_str(status));
        sync_destroy(&run_ctx.sync);
        sync_destroy(&serv_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_serving_handle_free(serv_ctx.serving);
        wispers_serving_session_free(serv_ctx.session);
        wispers_incoming_connections_free(serv_ctx.incoming);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // If activated, handle incoming QUIC connections with ping/pong responder
    if (serv_ctx.incoming != NULL) {
        printf("Listening for incoming QUIC connections...\n");
        while (!sync_is_called(&run_ctx.sync)) {
            // Try to accept an incoming QUIC connection
            QuicConnCtx conn_ctx = {0};
            sync_init(&conn_ctx.sync);
            status = wispers_incoming_accept_quic_async(serv_ctx.incoming, &conn_ctx, quic_conn_callback);
            if (status != WISPERS_STATUS_SUCCESS) {
                fprintf(stderr, "Failed to start accept_quic: %s\n", status_str(status));
                sync_destroy(&conn_ctx.sync);
                usleep(1000000);  // Wait 1s before retrying
                continue;
            }

            // Wait for connection with periodic checks if session ended
            while (!sync_is_called(&conn_ctx.sync) && !sync_is_called(&run_ctx.sync)) {
                usleep(100000);  // 100ms
            }

            if (sync_is_called(&run_ctx.sync)) {
                sync_destroy(&conn_ctx.sync);
                break;
            }

            if (conn_ctx.status == WISPERS_STATUS_SUCCESS && conn_ctx.connection) {
                printf("Incoming QUIC connection accepted\n");
                handle_quic_connection(conn_ctx.connection);

                // Close the connection
                BasicCtx close_ctx = {0};
                sync_init(&close_ctx.sync);
                wispers_quic_connection_close_async(conn_ctx.connection, &close_ctx, basic_callback);
                sync_wait(&close_ctx.sync, 5000);
                sync_destroy(&close_ctx.sync);

                printf("Connection closed\n");
            } else if (sync_is_called(&conn_ctx.sync)) {
                fprintf(stderr, "Accept failed: %s\n", status_str(conn_ctx.status));
            }

            sync_destroy(&conn_ctx.sync);
        }
    } else {
        // Just wait for session to end
        sync_wait(&run_ctx.sync, 0x7FFFFFFF);  // Wait forever
    }

    printf("Serving session ended: %s\n", status_str(run_ctx.status));

    sync_destroy(&run_ctx.sync);
    sync_destroy(&serv_ctx.sync);
    sync_destroy(&init_ctx.sync);
    wispers_serving_handle_free(serv_ctx.serving);
    wispers_incoming_connections_free(serv_ctx.incoming);
    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);
    free(storage_ctx);
    return 0;
}

static int cmd_ping(int peer_node_number) {
    StorageCtx *storage_ctx = NULL;
    WispersNodeStorageHandle *storage = create_storage(&storage_ctx);
    if (!storage) {
        fprintf(stderr, "Failed to create storage\n");
        return 1;
    }

    // First, restore state
    InitCtx init_ctx = {0};
    sync_init(&init_ctx.sync);
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start restore: %s\n", status_str(status));
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&init_ctx.sync, 5000) || init_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to restore state: %s\n",
                sync_is_called(&init_ctx.sync) ? status_str(init_ctx.status) : "timeout");
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Must be activated to ping
    if (init_ctx.state != WISPERS_NODE_STATE_ACTIVATED) {
        fprintf(stderr, "Cannot ping: not activated (state=%s)\n", state_str(init_ctx.state));
        wispers_node_free(init_ctx.handle);
        sync_destroy(&init_ctx.sync);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Connecting to node %d via QUIC...\n", peer_node_number);

    // Connect to peer
    QuicConnCtx conn_ctx = {0};
    sync_init(&conn_ctx.sync);
    status = wispers_node_connect_quic_async(init_ctx.handle, peer_node_number, &conn_ctx, quic_conn_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start connect: %s\n", status_str(status));
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&conn_ctx.sync, 30000) || conn_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to connect: %s\n",
                sync_is_called(&conn_ctx.sync) ? status_str(conn_ctx.status) : "timeout");
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Connected! Opening stream...\n");

    // Open a stream
    QuicStreamCtx stream_ctx = {0};
    sync_init(&stream_ctx.sync);
    status = wispers_quic_connection_open_stream_async(conn_ctx.connection, &stream_ctx, quic_stream_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to start open_stream: %s\n", status_str(status));
        wispers_quic_connection_free(conn_ctx.connection);
        sync_destroy(&stream_ctx.sync);
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    if (!sync_wait(&stream_ctx.sync, 10000) || stream_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to open stream: %s\n",
                sync_is_called(&stream_ctx.sync) ? status_str(stream_ctx.status) : "timeout");
        wispers_quic_connection_free(conn_ctx.connection);
        sync_destroy(&stream_ctx.sync);
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Stream opened. Sending PING...\n");

    // Send PING
    const uint8_t ping_data[] = "PING\n";
    BasicCtx write_ctx = {0};
    sync_init(&write_ctx.sync);
    status = wispers_quic_stream_write_async(stream_ctx.stream, ping_data, sizeof(ping_data) - 1, &write_ctx, basic_callback);
    if (status != WISPERS_STATUS_SUCCESS || !sync_wait(&write_ctx.sync, 10000) || write_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to send PING\n");
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        sync_destroy(&write_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    // Finish sending
    BasicCtx finish_ctx = {0};
    sync_init(&finish_ctx.sync);
    wispers_quic_stream_finish_async(stream_ctx.stream, &finish_ctx, basic_callback);
    sync_wait(&finish_ctx.sync, 10000);
    sync_destroy(&finish_ctx.sync);

    printf("PING sent. Waiting for PONG...\n");

    // Read response
    DataCtx read_ctx = {0};
    sync_init(&read_ctx.sync);
    status = wispers_quic_stream_read_async(stream_ctx.stream, 1024, &read_ctx, data_callback);
    if (status != WISPERS_STATUS_SUCCESS || !sync_wait(&read_ctx.sync, 10000) || read_ctx.status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "Failed to read response\n");
        wispers_quic_stream_free(stream_ctx.stream);
        wispers_quic_connection_free(conn_ctx.connection);
        sync_destroy(&read_ctx.sync);
        sync_destroy(&write_ctx.sync);
        sync_destroy(&stream_ctx.sync);
        sync_destroy(&conn_ctx.sync);
        sync_destroy(&init_ctx.sync);
        wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        free(storage_ctx);
        return 1;
    }

    printf("Received: %.*s\n", (int)read_ctx.len, read_ctx.data);

    // Close everything
    BasicCtx close_ctx = {0};
    sync_init(&close_ctx.sync);
    wispers_quic_connection_close_async(conn_ctx.connection, &close_ctx, basic_callback);
    sync_wait(&close_ctx.sync, 5000);
    sync_destroy(&close_ctx.sync);

    wispers_quic_stream_free(stream_ctx.stream);
    sync_destroy(&read_ctx.sync);
    sync_destroy(&write_ctx.sync);
    sync_destroy(&stream_ctx.sync);
    sync_destroy(&conn_ctx.sync);
    sync_destroy(&init_ctx.sync);
    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);
    free(storage_ctx);

    printf("Ping successful!\n");
    return 0;
}

//------------------------------------------------------------------------------
// Main
//------------------------------------------------------------------------------

int main(int argc, char **argv) {
    // Parse global options (--hub)
    int arg_idx = 1;
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "--hub") == 0 && arg_idx + 1 < argc) {
            g_hub_addr = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strncmp(argv[arg_idx], "--hub=", 6) == 0) {
            g_hub_addr = argv[arg_idx] + 6;
            arg_idx++;
        } else {
            break;  // Unknown option, might be command
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
            fprintf(stderr, "Error: register requires a token\n");
            print_usage(argv[0]);
            return 1;
        }
        return cmd_register(argv[arg_idx]);
    } else if (strcmp(command, "activate") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "Error: activate requires an activation code\n");
            print_usage(argv[0]);
            return 1;
        }
        return cmd_activate(argv[arg_idx]);
    } else if (strcmp(command, "serve") == 0) {
        int print_activation_code = 0;
        if (arg_idx < argc && strcmp(argv[arg_idx], "--activation-code") == 0) {
            print_activation_code = 1;
        }
        return cmd_serve(print_activation_code);
    } else if (strcmp(command, "ping") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "Error: ping requires a node number\n");
            print_usage(argv[0]);
            return 1;
        }
        int peer = atoi(argv[arg_idx]);
        if (peer <= 0) {
            fprintf(stderr, "Error: invalid node number\n");
            return 1;
        }
        return cmd_ping(peer);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
}
