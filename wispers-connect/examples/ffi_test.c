/**
 * FFI Test Program
 *
 * Tests the wispers-connect C API. Extended with each implementation phase.
 *
 * Phase 1: Storage lifecycle, handle types, callback types compile check
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
static void dummy_callback(void *ctx, WispersStatus status) {
    (void)ctx;
    (void)status;
}

static void dummy_init_callback(
    void *ctx,
    WispersStatus status,
    WispersStage stage,
    WispersPendingNodeStateHandle *pending,
    WispersRegisteredNodeStateHandle *registered,
    WispersActivatedNodeHandle *activated
) {
    (void)ctx;
    (void)status;
    (void)stage;
    (void)pending;
    (void)registered;
    (void)activated;
}

static void dummy_registered_callback(
    void *ctx,
    WispersStatus status,
    WispersRegisteredNodeStateHandle *handle
) {
    (void)ctx;
    (void)status;
    (void)handle;
}

static void dummy_activated_callback(
    void *ctx,
    WispersStatus status,
    WispersActivatedNodeHandle *handle
) {
    (void)ctx;
    (void)status;
    (void)handle;
}

static int test_callback_types_compile(void) {
    TEST("callback types compile");

    // Just verify these assignments compile - proves the types match
    WispersCallback cb1 = dummy_callback;
    WispersInitCallback cb2 = dummy_init_callback;
    WispersRegisteredCallback cb3 = dummy_registered_callback;
    WispersActivatedCallback cb4 = dummy_activated_callback;

    (void)cb1;
    (void)cb2;
    (void)cb3;
    (void)cb4;

    PASS();
    return 0;
}

static int test_status_codes(void) {
    TEST("status codes");

    // Verify new status codes exist and have expected values
    if (WISPERS_STATUS_SUCCESS != 0) FAIL("SUCCESS != 0");
    if (WISPERS_STATUS_HUB_ERROR != 12) FAIL("HUB_ERROR != 12");
    if (WISPERS_STATUS_CONNECTION_FAILED != 13) FAIL("CONNECTION_FAILED != 13");
    if (WISPERS_STATUS_TIMEOUT != 14) FAIL("TIMEOUT != 14");

    PASS();
    return 0;
}

static int test_stage_enum(void) {
    TEST("stage enum");

    if (WISPERS_STAGE_PENDING != 0) FAIL("PENDING != 0");
    if (WISPERS_STAGE_REGISTERED != 1) FAIL("REGISTERED != 1");
    if (WISPERS_STAGE_ACTIVATED != 2) FAIL("ACTIVATED != 2");

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
    wispers_pending_state_free(NULL);
    wispers_registered_state_free(NULL);
    wispers_activated_node_free(NULL);
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
    WispersStage stage;
    WispersPendingNodeStateHandle *pending;
    WispersRegisteredNodeStateHandle *registered;
    WispersActivatedNodeHandle *activated;
} InitTestCtx;

static void init_callback(
    void *ctx,
    WispersStatus status,
    WispersStage stage,
    WispersPendingNodeStateHandle *pending,
    WispersRegisteredNodeStateHandle *registered,
    WispersActivatedNodeHandle *activated
) {
    InitTestCtx *test = (InitTestCtx *)ctx;
    test->called = 1;
    test->status = status;
    test->stage = stage;
    test->pending = pending;
    test->registered = registered;
    test->activated = activated;
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

    if (ctx.stage != WISPERS_STAGE_PENDING) {
        if (ctx.pending) wispers_pending_state_free(ctx.pending);
        if (ctx.registered) wispers_registered_state_free(ctx.registered);
        if (ctx.activated) wispers_activated_node_free(ctx.activated);
        wispers_storage_free(storage);
        FAIL("expected PENDING stage");
    }

    if (!ctx.pending) {
        wispers_storage_free(storage);
        FAIL("pending handle is NULL");
    }

    wispers_pending_state_free(ctx.pending);
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
// Main
//------------------------------------------------------------------------------

int main(void) {
    printf("=== Wispers Connect FFI Tests ===\n\n");

    int failures = 0;

    // Phase 1 tests
    printf("-- Phase 1: Infrastructure --\n");
    failures += test_callback_types_compile();
    failures += test_status_codes();
    failures += test_stage_enum();
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

    printf("\n");
    if (failures == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) failed.\n", failures);
        return 1;
    }
}
