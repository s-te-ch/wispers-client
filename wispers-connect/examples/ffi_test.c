/**
 * FFI Test Program
 *
 * Tests the wispers-connect C API with the unified node handle.
 */

#include "wispers_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // for usleep

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)

//------------------------------------------------------------------------------
// Phase 1: Infrastructure tests
//------------------------------------------------------------------------------

// Test that callback types compile correctly (not invoked yet)
static void dummy_callback(void *ctx, WispersStatus status, const char *error_detail) {
    (void)ctx;
    (void)status;
    (void)error_detail;
}

static void dummy_init_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersNodeHandle *handle,
    WispersNodeState state
) {
    (void)ctx;
    (void)status;
    (void)error_detail;
    (void)handle;
    (void)state;
}

static int test_callback_types_compile(void) {
    TEST("callback types compile");

    // Just verify these assignments compile - proves the types match
    WispersCallback cb1 = dummy_callback;
    WispersInitCallback cb2 = dummy_init_callback;

    (void)cb1;
    (void)cb2;

    PASS();
    return 0;
}

static int test_status_codes(void) {
    TEST("status codes");

    // Verify status codes exist and have expected values
    if (WISPERS_STATUS_SUCCESS != 0) FAIL("SUCCESS != 0");
    if (WISPERS_STATUS_HUB_ERROR != 11) FAIL("HUB_ERROR != 11");
    if (WISPERS_STATUS_CONNECTION_FAILED != 12) FAIL("CONNECTION_FAILED != 12");
    if (WISPERS_STATUS_TIMEOUT != 13) FAIL("TIMEOUT != 13");
    if (WISPERS_STATUS_INVALID_STATE != 14) FAIL("INVALID_STATE != 14");

    PASS();
    return 0;
}

static int test_node_state_enum(void) {
    TEST("node state enum");

    if (WISPERS_NODE_STATE_PENDING != 0) FAIL("PENDING != 0");
    if (WISPERS_NODE_STATE_REGISTERED != 1) FAIL("REGISTERED != 1");
    if (WISPERS_NODE_STATE_ACTIVATED != 2) FAIL("ACTIVATED != 2");

    PASS();
    return 0;
}

static int test_activation_status_enum(void) {
    TEST("activation status enum");

    if (WISPERS_ACTIVATION_UNKNOWN != 0) FAIL("UNKNOWN != 0");
    if (WISPERS_ACTIVATION_NOT_ACTIVATED != 1) FAIL("NOT_ACTIVATED != 1");
    if (WISPERS_ACTIVATION_ACTIVATED != 2) FAIL("ACTIVATED != 2");

    PASS();
    return 0;
}

static int test_storage_in_memory(void) {
    TEST("storage in-memory create/free");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("wispers_storage_new_in_memory returned NULL");

    wispers_storage_free(storage);
    PASS();
    return 0;
}

static int test_storage_free_null(void) {
    TEST("storage free NULL is safe");

    // Should not crash
    wispers_storage_free(NULL);

    PASS();
    return 0;
}

static int test_handle_free_null(void) {
    TEST("handle free NULL is safe");

    // All free functions should handle NULL safely
    wispers_node_free(NULL);
    wispers_string_free(NULL);

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 2: Sync operations tests
//------------------------------------------------------------------------------

static int test_read_registration_not_found(void) {
    TEST("read_registration returns NOT_FOUND for fresh storage");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    WispersRegistrationInfo info;
    WispersStatus status = wispers_storage_read_registration(storage, &info);

    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_NOT_FOUND) FAIL("expected NOT_FOUND");

    PASS();
    return 0;
}

static int test_read_registration_null_params(void) {
    TEST("read_registration handles NULL params");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    WispersRegistrationInfo info;

    if (wispers_storage_read_registration(NULL, &info) != WISPERS_STATUS_NULL_POINTER)
        FAIL("expected NULL_POINTER for NULL handle");

    if (wispers_storage_read_registration(storage, NULL) != WISPERS_STATUS_NULL_POINTER)
        FAIL("expected NULL_POINTER for NULL out_info");

    wispers_storage_free(storage);
    PASS();
    return 0;
}

static int test_override_hub_addr(void) {
    TEST("override_hub_addr");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    WispersStatus status = wispers_storage_override_hub_addr(storage, "http://localhost:8080");
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_SUCCESS) FAIL("expected SUCCESS");

    PASS();
    return 0;
}

static int test_override_hub_addr_null_params(void) {
    TEST("override_hub_addr handles NULL params");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();

    if (wispers_storage_override_hub_addr(NULL, "http://test") != WISPERS_STATUS_NULL_POINTER)
        FAIL("expected NULL_POINTER for NULL handle");

    if (wispers_storage_override_hub_addr(storage, NULL) != WISPERS_STATUS_NULL_POINTER)
        FAIL("expected NULL_POINTER for NULL addr");

    wispers_storage_free(storage);
    PASS();
    return 0;
}

static int test_registration_info_free_null(void) {
    TEST("registration_info_free handles NULL");

    // Should not crash
    wispers_registration_info_free(NULL);

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 3: State initialization tests
//------------------------------------------------------------------------------

// Test context for async callbacks
typedef struct {
    int called;
    WispersStatus status;
    WispersNodeState state;
    WispersNodeHandle *handle;
} InitTestCtx;

static void init_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersNodeHandle *handle,
    WispersNodeState state
) {
    (void)error_detail;
    InitTestCtx *test = (InitTestCtx *)ctx;
    test->called = 1;
    test->status = status;
    test->state = state;
    test->handle = handle;
}

static int test_restore_or_init_fresh_storage(void) {
    TEST("restore_or_init returns pending for fresh storage");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(storage, &ctx, init_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        wispers_storage_free(storage);
        FAIL("failed to start async operation");
    }

    // Wait a bit for the callback (it should be nearly instant for in-memory)
    for (int i = 0; i < 100 && !ctx.called; i++) {
        usleep(10000); // 10ms
    }

    if (!ctx.called) {
        wispers_storage_free(storage);
        FAIL("callback was not invoked");
    }

    if (ctx.status != WISPERS_STATUS_SUCCESS) {
        wispers_storage_free(storage);
        FAIL("callback status was not SUCCESS");
    }

    if (ctx.state != WISPERS_NODE_STATE_PENDING) {
        if (ctx.handle) wispers_node_free(ctx.handle);
        wispers_storage_free(storage);
        FAIL("expected PENDING state");
    }

    if (!ctx.handle) {
        wispers_storage_free(storage);
        FAIL("node handle is NULL");
    }

    // Verify we can query the state
    WispersNodeState queried_state = wispers_node_state(ctx.handle);
    if (queried_state != WISPERS_NODE_STATE_PENDING) {
        wispers_node_free(ctx.handle);
        wispers_storage_free(storage);
        FAIL("wispers_node_state returned wrong state");
    }

    wispers_node_free(ctx.handle);
    wispers_storage_free(storage);
    PASS();
    return 0;
}

static int test_restore_or_init_null_callback(void) {
    TEST("restore_or_init rejects NULL callback");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    WispersStatus status = wispers_storage_restore_or_init_async(storage, NULL, NULL);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_MISSING_CALLBACK) FAIL("expected MISSING_CALLBACK");

    PASS();
    return 0;
}

static int test_restore_or_init_null_handle(void) {
    TEST("restore_or_init rejects NULL handle");

    InitTestCtx ctx = {0};
    WispersStatus status = wispers_storage_restore_or_init_async(NULL, &ctx, init_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 4: Node operations tests
//------------------------------------------------------------------------------

// Test context for simple callbacks
typedef struct {
    int called;
    WispersStatus status;
} SimpleTestCtx;

static void simple_callback(void *ctx, WispersStatus status, const char *error_detail) {
    (void)error_detail;
    SimpleTestCtx *test = (SimpleTestCtx *)ctx;
    test->called = 1;
    test->status = status;
}

static int test_node_register_null_handle(void) {
    TEST("node_register rejects NULL handle");

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_register_async(NULL, "token", &ctx, simple_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_node_register_null_token(void) {
    TEST("node_register rejects NULL token");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_register_async(init_ctx.handle, NULL, &ctx, simple_callback);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_node_register_null_callback(void) {
    TEST("node_register rejects NULL callback");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    WispersStatus status = wispers_node_register_async(init_ctx.handle, "token", NULL, NULL);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_MISSING_CALLBACK) FAIL("expected MISSING_CALLBACK");

    PASS();
    return 0;
}

static int test_node_logout_null_handle(void) {
    TEST("node_logout rejects NULL handle");

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_logout_async(NULL, &ctx, simple_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_node_logout_null_callback(void) {
    TEST("node_logout rejects NULL callback");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    WispersStatus status = wispers_node_logout_async(init_ctx.handle, NULL, NULL);

    // Handle NOT consumed on error
    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_MISSING_CALLBACK) FAIL("expected MISSING_CALLBACK");

    PASS();
    return 0;
}

static int test_node_logout_success(void) {
    TEST("node_logout deletes local state");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_logout_async(init_ctx.handle, &ctx, simple_callback);
    if (status != WISPERS_STATUS_SUCCESS) {
        wispers_storage_free(storage);
        FAIL("failed to start logout");
    }

    // Wait for callback (handle is consumed)
    for (int i = 0; i < 100 && !ctx.called; i++) usleep(10000);

    wispers_storage_free(storage);

    if (!ctx.called) FAIL("logout callback was not invoked");
    if (ctx.status != WISPERS_STATUS_SUCCESS) FAIL("logout callback status was not SUCCESS");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 5: Activation tests
//------------------------------------------------------------------------------

static int test_node_activate_null_handle(void) {
    TEST("node_activate rejects NULL handle");

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_activate_async(
        NULL, "1-abc123xyz0", &ctx, simple_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_node_activate_null_activation_code(void) {
    TEST("node_activate rejects NULL activation_code");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    SimpleTestCtx ctx = {0};
    WispersStatus status = wispers_node_activate_async(init_ctx.handle, NULL, &ctx, simple_callback);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_node_activate_null_callback(void) {
    TEST("node_activate rejects NULL callback");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    WispersStatus status = wispers_node_activate_async(
        init_ctx.handle, "1-abc123xyz0", NULL, NULL);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_MISSING_CALLBACK) FAIL("expected MISSING_CALLBACK");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 6: Group info tests
//------------------------------------------------------------------------------

// Test context for group info callbacks
typedef struct {
    int called;
    WispersStatus status;
    WispersGroupInfo *group_info;
} GroupInfoTestCtx;

static void group_info_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersGroupInfo *group_info
) {
    (void)error_detail;
    GroupInfoTestCtx *test = (GroupInfoTestCtx *)ctx;
    test->called = 1;
    test->status = status;
    test->group_info = group_info;
}

static int test_group_info_free_null(void) {
    TEST("group_info_free handles NULL");

    // Should not crash
    wispers_group_info_free(NULL);

    PASS();
    return 0;
}

static int test_group_info_null_handle(void) {
    TEST("group_info rejects NULL handle");

    GroupInfoTestCtx ctx = {0};
    WispersStatus status = wispers_node_group_info_async(NULL, &ctx, group_info_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_group_info_null_callback(void) {
    TEST("group_info rejects NULL callback");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle) {
        wispers_storage_free(storage);
        FAIL("failed to get node handle");
    }

    WispersStatus status = wispers_node_group_info_async(init_ctx.handle, NULL, NULL);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_MISSING_CALLBACK) FAIL("expected MISSING_CALLBACK");

    PASS();
    return 0;
}

static int test_group_info_invalid_state(void) {
    TEST("group_info returns INVALID_STATE for pending node");

    WispersNodeStorageHandle *storage = wispers_storage_new_in_memory();
    if (!storage) FAIL("failed to create storage");

    InitTestCtx init_ctx = {0};
    wispers_storage_restore_or_init_async(storage, &init_ctx, init_callback);
    for (int i = 0; i < 100 && !init_ctx.called; i++) usleep(10000);

    if (!init_ctx.called || !init_ctx.handle || init_ctx.state != WISPERS_NODE_STATE_PENDING) {
        if (init_ctx.handle) wispers_node_free(init_ctx.handle);
        wispers_storage_free(storage);
        FAIL("failed to get pending node handle");
    }

    GroupInfoTestCtx ctx = {0};
    WispersStatus status = wispers_node_group_info_async(init_ctx.handle, &ctx, group_info_callback);

    wispers_node_free(init_ctx.handle);
    wispers_storage_free(storage);

    if (status != WISPERS_STATUS_INVALID_STATE) FAIL("expected INVALID_STATE");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 7: Serving tests
//------------------------------------------------------------------------------

static int test_serving_handle_free_null(void) {
    TEST("serving_handle_free handles NULL");
    wispers_serving_handle_free(NULL);
    PASS();
    return 0;
}

static int test_serving_session_free_null(void) {
    TEST("serving_session_free handles NULL");
    wispers_serving_session_free(NULL);
    PASS();
    return 0;
}

static int test_incoming_connections_free_null(void) {
    TEST("incoming_connections_free handles NULL");
    wispers_incoming_connections_free(NULL);
    PASS();
    return 0;
}

static int test_node_start_serving_null_handle(void) {
    TEST("node_start_serving rejects NULL handle");

    WispersStatus status = wispers_node_start_serving_async(NULL, NULL, NULL);
    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_generate_activation_code_null_handle(void) {
    TEST("generate_activation_code rejects NULL handle");

    WispersStatus status = wispers_serving_handle_generate_activation_code_async(NULL, NULL, NULL);
    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_session_run_null_handle(void) {
    TEST("session_run rejects NULL handle");

    WispersStatus status = wispers_serving_session_run_async(NULL, NULL, NULL);
    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_shutdown_null_handle(void) {
    TEST("shutdown rejects NULL handle");

    WispersStatus status = wispers_serving_handle_shutdown_async(NULL, NULL, NULL);
    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 8a: UDP connections tests
//------------------------------------------------------------------------------

static void dummy_udp_connection_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersUdpConnectionHandle *connection
) {
    (void)ctx;
    (void)status;
    (void)error_detail;
    (void)connection;
}

static void dummy_data_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    const uint8_t *data,
    size_t len
) {
    (void)ctx;
    (void)status;
    (void)error_detail;
    (void)data;
    (void)len;
}

static int test_udp_callback_types_compile(void) {
    TEST("UDP callback types compile");

    WispersUdpConnectionCallback cb1 = dummy_udp_connection_callback;
    WispersDataCallback cb2 = dummy_data_callback;

    (void)cb1;
    (void)cb2;

    PASS();
    return 0;
}

static int test_connect_udp_null_handle(void) {
    TEST("connect_udp rejects NULL handle");

    WispersStatus status = wispers_node_connect_udp_async(
        NULL, 1, NULL, dummy_udp_connection_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_udp_send_null_handle(void) {
    TEST("udp_send rejects NULL handle");

    uint8_t data[] = {1, 2, 3};
    WispersStatus status = wispers_udp_connection_send(NULL, data, 3);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_udp_recv_null_handle(void) {
    TEST("udp_recv rejects NULL handle");

    WispersStatus status = wispers_udp_connection_recv_async(
        NULL, NULL, dummy_data_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_udp_close_null_safe(void) {
    TEST("udp_close handles NULL safely");

    // Should not crash
    wispers_udp_connection_close(NULL);

    PASS();
    return 0;
}

static int test_udp_free_null_safe(void) {
    TEST("udp_free handles NULL safely");

    // Should not crash
    wispers_udp_connection_free(NULL);

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 8b: QUIC connections tests
//------------------------------------------------------------------------------

static void dummy_quic_connection_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersQuicConnectionHandle *connection
) {
    (void)ctx;
    (void)status;
    (void)error_detail;
    (void)connection;
}

static void dummy_quic_stream_callback(
    void *ctx,
    WispersStatus status,
    const char *error_detail,
    WispersQuicStreamHandle *stream
) {
    (void)ctx;
    (void)status;
    (void)error_detail;
    (void)stream;
}

static int test_quic_callback_types_compile(void) {
    TEST("QUIC callback types compile");

    WispersQuicConnectionCallback cb1 = dummy_quic_connection_callback;
    WispersQuicStreamCallback cb2 = dummy_quic_stream_callback;

    (void)cb1;
    (void)cb2;

    PASS();
    return 0;
}

static int test_connect_quic_null_handle(void) {
    TEST("connect_quic rejects NULL handle");

    WispersStatus status = wispers_node_connect_quic_async(
        NULL, 1, NULL, dummy_quic_connection_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_open_stream_null_handle(void) {
    TEST("quic_open_stream rejects NULL handle");

    WispersStatus status = wispers_quic_connection_open_stream_async(
        NULL, NULL, dummy_quic_stream_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_accept_stream_null_handle(void) {
    TEST("quic_accept_stream rejects NULL handle");

    WispersStatus status = wispers_quic_connection_accept_stream_async(
        NULL, NULL, dummy_quic_stream_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_close_null_handle(void) {
    TEST("quic_close rejects NULL handle");

    WispersStatus status = wispers_quic_connection_close_async(
        NULL, NULL, dummy_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_connection_free_null_safe(void) {
    TEST("quic_connection_free handles NULL safely");

    // Should not crash
    wispers_quic_connection_free(NULL);

    PASS();
    return 0;
}

static int test_quic_stream_free_null_safe(void) {
    TEST("quic_stream_free handles NULL safely");

    // Should not crash
    wispers_quic_stream_free(NULL);

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 8c: QUIC stream operations tests
//------------------------------------------------------------------------------

static int test_quic_stream_write_null_handle(void) {
    TEST("quic_stream_write rejects NULL handle");

    uint8_t data[] = {1, 2, 3};
    WispersStatus status = wispers_quic_stream_write_async(
        NULL, data, 3, NULL, dummy_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_stream_read_null_handle(void) {
    TEST("quic_stream_read rejects NULL handle");

    WispersStatus status = wispers_quic_stream_read_async(
        NULL, 1024, NULL, dummy_data_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_stream_finish_null_handle(void) {
    TEST("quic_stream_finish rejects NULL handle");

    WispersStatus status = wispers_quic_stream_finish_async(
        NULL, NULL, dummy_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_quic_stream_shutdown_null_handle(void) {
    TEST("quic_stream_shutdown rejects NULL handle");

    WispersStatus status = wispers_quic_stream_shutdown_async(
        NULL, NULL, dummy_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Phase 9: Incoming connections tests
//------------------------------------------------------------------------------

static int test_incoming_accept_udp_null_handle(void) {
    TEST("incoming_accept_udp rejects NULL handle");

    WispersStatus status = wispers_incoming_accept_udp_async(
        NULL, NULL, dummy_udp_connection_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

static int test_incoming_accept_quic_null_handle(void) {
    TEST("incoming_accept_quic rejects NULL handle");

    WispersStatus status = wispers_incoming_accept_quic_async(
        NULL, NULL, dummy_quic_connection_callback);

    if (status != WISPERS_STATUS_NULL_POINTER) FAIL("expected NULL_POINTER");

    PASS();
    return 0;
}

//------------------------------------------------------------------------------
// Main
//------------------------------------------------------------------------------

int main(void) {
    printf("=== Wispers Connect FFI Tests (Unified API) ===\n\n");

    int failures = 0;

    // Phase 1 tests
    printf("-- Phase 1: Infrastructure --\n");
    failures += test_callback_types_compile();
    failures += test_status_codes();
    failures += test_node_state_enum();
    failures += test_activation_status_enum();
    failures += test_storage_in_memory();
    failures += test_storage_free_null();
    failures += test_handle_free_null();

    // Phase 2 tests
    printf("\n-- Phase 2: Sync Operations --\n");
    failures += test_read_registration_not_found();
    failures += test_read_registration_null_params();
    failures += test_override_hub_addr();
    failures += test_override_hub_addr_null_params();
    failures += test_registration_info_free_null();

    // Phase 3 tests
    printf("\n-- Phase 3: State Initialization --\n");
    failures += test_restore_or_init_fresh_storage();
    failures += test_restore_or_init_null_callback();
    failures += test_restore_or_init_null_handle();

    // Phase 4 tests
    printf("\n-- Phase 4: Node Operations --\n");
    failures += test_node_register_null_handle();
    failures += test_node_register_null_token();
    failures += test_node_register_null_callback();
    failures += test_node_logout_null_handle();
    failures += test_node_logout_null_callback();
    failures += test_node_logout_success();

    // Phase 5 tests
    printf("\n-- Phase 5: Activation --\n");
    failures += test_node_activate_null_handle();
    failures += test_node_activate_null_activation_code();
    failures += test_node_activate_null_callback();

    // Phase 6 tests
    printf("\n-- Phase 6: Node Listing --\n");
    failures += test_group_info_free_null();
    failures += test_group_info_null_handle();
    failures += test_group_info_null_callback();
    failures += test_group_info_invalid_state();

    // Phase 7 tests
    printf("\n-- Phase 7: Serving --\n");
    failures += test_serving_handle_free_null();
    failures += test_serving_session_free_null();
    failures += test_incoming_connections_free_null();
    failures += test_node_start_serving_null_handle();
    failures += test_generate_activation_code_null_handle();
    failures += test_session_run_null_handle();
    failures += test_shutdown_null_handle();

    // Phase 8a tests
    printf("\n-- Phase 8a: UDP Connections --\n");
    failures += test_udp_callback_types_compile();
    failures += test_connect_udp_null_handle();
    failures += test_udp_send_null_handle();
    failures += test_udp_recv_null_handle();
    failures += test_udp_close_null_safe();
    failures += test_udp_free_null_safe();

    // Phase 8b tests
    printf("\n-- Phase 8b: QUIC Connections --\n");
    failures += test_quic_callback_types_compile();
    failures += test_connect_quic_null_handle();
    failures += test_quic_open_stream_null_handle();
    failures += test_quic_accept_stream_null_handle();
    failures += test_quic_close_null_handle();
    failures += test_quic_connection_free_null_safe();
    failures += test_quic_stream_free_null_safe();

    // Phase 8c tests
    printf("\n-- Phase 8c: QUIC Stream Operations --\n");
    failures += test_quic_stream_write_null_handle();
    failures += test_quic_stream_read_null_handle();
    failures += test_quic_stream_finish_null_handle();
    failures += test_quic_stream_shutdown_null_handle();

    // Phase 9 tests
    printf("\n-- Phase 9: Incoming Connections --\n");
    failures += test_incoming_accept_udp_null_handle();
    failures += test_incoming_accept_quic_null_handle();

    printf("\n");
    if (failures == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) failed.\n", failures);
        return 1;
    }
}
