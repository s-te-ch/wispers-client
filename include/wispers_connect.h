#ifndef WISPERS_CONNECT_H
#define WISPERS_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Status codes returned by the FFI functions.
typedef enum {
    WISPERS_STATUS_SUCCESS = 0,
    WISPERS_STATUS_NULL_POINTER = 1,
    WISPERS_STATUS_INVALID_UTF8 = 2,
    WISPERS_STATUS_STORE_ERROR = 3,
    WISPERS_STATUS_ALREADY_REGISTERED = 4,
    WISPERS_STATUS_NOT_REGISTERED = 5,
    WISPERS_STATUS_UNEXPECTED_STAGE = 6,
    WISPERS_STATUS_NOT_FOUND = 7,
    WISPERS_STATUS_BUFFER_TOO_SMALL = 8,
    WISPERS_STATUS_MISSING_CALLBACK = 9,
} WispersStatus;

// Forward declarations for opaque handles.
typedef struct WispersNodeStateManagerHandle WispersNodeStateManagerHandle;
typedef struct WispersPendingNodeStateHandle WispersPendingNodeStateHandle;
typedef struct WispersRegisteredNodeStateHandle WispersRegisteredNodeStateHandle;

// Host-provided storage callbacks. All functions must be non-null when used.
typedef struct {
    void *ctx;
    WispersStatus (*load_root_key)(void *ctx, const char *app_namespace, const char *profile_namespace,
                                   uint8_t *out_key, size_t out_key_len);
    WispersStatus (*save_root_key)(void *ctx, const char *app_namespace, const char *profile_namespace,
                                   const uint8_t *key, size_t key_len);
    WispersStatus (*delete_root_key)(void *ctx, const char *app_namespace, const char *profile_namespace);

    // Registration payloads are serialized by Rust (currently using bincode).
    WispersStatus (*load_registration)(void *ctx, const char *app_namespace, const char *profile_namespace,
                                       uint8_t *buffer, size_t buffer_len, size_t *out_len);
    WispersStatus (*save_registration)(void *ctx, const char *app_namespace, const char *profile_namespace,
                                       const uint8_t *buffer, size_t buffer_len);
    WispersStatus (*delete_registration)(void *ctx, const char *app_namespace, const char *profile_namespace);
} WispersNodeStateStoreCallbacks;

// Manager lifecycle.
WispersNodeStateManagerHandle *wispers_in_memory_manager_new(void);
WispersNodeStateManagerHandle *wispers_manager_new_with_store(const WispersNodeStateStoreCallbacks *callbacks);
void wispers_manager_free(WispersNodeStateManagerHandle *handle);

// Restore or initialize node state. Exactly one of out_pending or out_registered will be set on success.
WispersStatus wispers_manager_restore_or_init(
    WispersNodeStateManagerHandle *handle,
    const char *app_namespace,
    const char *profile_namespace, // optional: pass NULL for default
    WispersPendingNodeStateHandle **out_pending,
    WispersRegisteredNodeStateHandle **out_registered
);

// Pending-state helpers.
void wispers_pending_state_free(WispersPendingNodeStateHandle *handle);
char *wispers_pending_state_registration_url(WispersPendingNodeStateHandle *handle, const char *base_url);
WispersStatus wispers_pending_state_complete_registration(
    WispersPendingNodeStateHandle *handle,
    const char *connectivity_group_id,
    const char *node_id,
    WispersRegisteredNodeStateHandle **out_registered
);

// Registered-state helpers.
void wispers_registered_state_free(WispersRegisteredNodeStateHandle *handle);
WispersStatus wispers_registered_state_delete(WispersRegisteredNodeStateHandle *handle);

// Utility to free strings allocated by the library.
void wispers_string_free(char *ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // WISPERS_CONNECT_H
