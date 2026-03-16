// wispers_helpers.h — Static inline C shim functions for CGo.
// Included by multiple .go files so each CGo compilation unit can call them.

#ifndef WISPERS_HELPERS_H
#define WISPERS_HELPERS_H

#include "wispers_connect.h"

// Forward declarations for //export functions in shims.go.
extern void goWispersCallback(void *ctx, int status, const char *detail);
extern void goWispersInitCallback(void *ctx, int status, const char *detail, void *handle, int state);
extern void goWispersGroupInfoCallback(void *ctx, int status, const char *detail, WispersGroupInfo *gi);
extern void goWispersStartServingCallback(void *ctx, int status, const char *detail, void *serving, void *session, void *incoming);
extern void goWispersActivationCodeCallback(void *ctx, int status, const char *detail, char *code);
extern void goWispersUdpConnectionCallback(void *ctx, int status, const char *detail, void *conn);
extern void goWispersDataCallback(void *ctx, int status, const char *detail, const uint8_t *data, size_t len);
extern void goWispersQuicConnectionCallback(void *ctx, int status, const char *detail, void *conn);
extern void goWispersQuicStreamCallback(void *ctx, int status, const char *detail, void *stream);

// Storage callback forward declarations.
extern int goStorageLoadRootKey(void *ctx, uint8_t *out_key, size_t out_key_len);
extern int goStorageSaveRootKey(void *ctx, const uint8_t *key, size_t key_len);
extern int goStorageDeleteRootKey(void *ctx);
extern int goStorageLoadRegistration(void *ctx, uint8_t *buffer, size_t buffer_len, size_t *out_len);
extern int goStorageSaveRegistration(void *ctx, const uint8_t *buffer, size_t buffer_len);
extern int goStorageDeleteRegistration(void *ctx);

// Shim callback functions that cast Go exports to correct C function pointer types.

static inline void shimWispersCallback(void *ctx, WispersStatus status, const char *detail) {
	goWispersCallback(ctx, (int)status, detail);
}

static inline void shimWispersInitCallback(void *ctx, WispersStatus status, const char *detail, WispersNodeHandle *handle, WispersNodeState state) {
	goWispersInitCallback(ctx, (int)status, detail, (void*)handle, (int)state);
}

static inline void shimWispersGroupInfoCallback(void *ctx, WispersStatus status, const char *detail, WispersGroupInfo *gi) {
	goWispersGroupInfoCallback(ctx, (int)status, detail, gi);
}

static inline void shimWispersStartServingCallback(void *ctx, WispersStatus status, const char *detail, WispersServingHandle *serving, WispersServingSession *session, WispersIncomingConnections *incoming) {
	goWispersStartServingCallback(ctx, (int)status, detail, (void*)serving, (void*)session, (void*)incoming);
}

static inline void shimWispersActivationCodeCallback(void *ctx, WispersStatus status, const char *detail, char *code) {
	goWispersActivationCodeCallback(ctx, (int)status, detail, code);
}

static inline void shimWispersUdpConnectionCallback(void *ctx, WispersStatus status, const char *detail, WispersUdpConnectionHandle *conn) {
	goWispersUdpConnectionCallback(ctx, (int)status, detail, (void*)conn);
}

static inline void shimWispersDataCallback(void *ctx, WispersStatus status, const char *detail, const uint8_t *data, size_t len) {
	goWispersDataCallback(ctx, (int)status, detail, data, len);
}

static inline void shimWispersQuicConnectionCallback(void *ctx, WispersStatus status, const char *detail, WispersQuicConnectionHandle *conn) {
	goWispersQuicConnectionCallback(ctx, (int)status, detail, (void*)conn);
}

static inline void shimWispersQuicStreamCallback(void *ctx, WispersStatus status, const char *detail, WispersQuicStreamHandle *stream) {
	goWispersQuicStreamCallback(ctx, (int)status, detail, (void*)stream);
}

// Helper to build storage callbacks struct with Go shims.
static inline WispersNodeStorageCallbacks makeStorageCallbacks(void *ctx) {
	WispersNodeStorageCallbacks cb;
	cb.ctx = ctx;
	cb.load_root_key = (WispersStatus(*)(void*, uint8_t*, size_t))goStorageLoadRootKey;
	cb.save_root_key = (WispersStatus(*)(void*, const uint8_t*, size_t))goStorageSaveRootKey;
	cb.delete_root_key = (WispersStatus(*)(void*))goStorageDeleteRootKey;
	cb.load_registration = (WispersStatus(*)(void*, uint8_t*, size_t, size_t*))goStorageLoadRegistration;
	cb.save_registration = (WispersStatus(*)(void*, const uint8_t*, size_t))goStorageSaveRegistration;
	cb.delete_registration = (WispersStatus(*)(void*))goStorageDeleteRegistration;
	return cb;
}

// Wrappers that pass shim function pointers to C async calls.

static inline WispersStatus callRestoreOrInitAsync(WispersNodeStorageHandle *h, void *ctx) {
	return wispers_storage_restore_or_init_async(h, ctx, shimWispersInitCallback);
}

static inline WispersStatus callRegisterAsync(WispersNodeHandle *h, const char *token, void *ctx) {
	return wispers_node_register_async(h, token, ctx, shimWispersCallback);
}

static inline WispersStatus callActivateAsync(WispersNodeHandle *h, const char *code, void *ctx) {
	return wispers_node_activate_async(h, code, ctx, shimWispersCallback);
}

static inline WispersStatus callLogoutAsync(WispersNodeHandle *h, void *ctx) {
	return wispers_node_logout_async(h, ctx, shimWispersCallback);
}

static inline WispersStatus callGroupInfoAsync(WispersNodeHandle *h, void *ctx) {
	return wispers_node_group_info_async(h, ctx, shimWispersGroupInfoCallback);
}

static inline WispersStatus callStartServingAsync(WispersNodeHandle *h, void *ctx) {
	return wispers_node_start_serving_async(h, ctx, shimWispersStartServingCallback);
}

static inline WispersStatus callConnectUdpAsync(WispersNodeHandle *h, int32_t peer, void *ctx) {
	return wispers_node_connect_udp_async(h, peer, ctx, shimWispersUdpConnectionCallback);
}

static inline WispersStatus callConnectQuicAsync(WispersNodeHandle *h, int32_t peer, void *ctx) {
	return wispers_node_connect_quic_async(h, peer, ctx, shimWispersQuicConnectionCallback);
}

static inline WispersStatus callUdpRecvAsync(WispersUdpConnectionHandle *h, void *ctx) {
	return wispers_udp_connection_recv_async(h, ctx, shimWispersDataCallback);
}

static inline WispersStatus callQuicOpenStreamAsync(WispersQuicConnectionHandle *h, void *ctx) {
	return wispers_quic_connection_open_stream_async(h, ctx, shimWispersQuicStreamCallback);
}

static inline WispersStatus callQuicAcceptStreamAsync(WispersQuicConnectionHandle *h, void *ctx) {
	return wispers_quic_connection_accept_stream_async(h, ctx, shimWispersQuicStreamCallback);
}

static inline WispersStatus callQuicCloseAsync(WispersQuicConnectionHandle *h, void *ctx) {
	return wispers_quic_connection_close_async(h, ctx, shimWispersCallback);
}

static inline WispersStatus callQuicStreamWriteAsync(WispersQuicStreamHandle *h, const uint8_t *data, size_t len, void *ctx) {
	return wispers_quic_stream_write_async(h, data, len, ctx, shimWispersCallback);
}

static inline WispersStatus callQuicStreamReadAsync(WispersQuicStreamHandle *h, size_t max_len, void *ctx) {
	return wispers_quic_stream_read_async(h, max_len, ctx, shimWispersDataCallback);
}

static inline WispersStatus callQuicStreamFinishAsync(WispersQuicStreamHandle *h, void *ctx) {
	return wispers_quic_stream_finish_async(h, ctx, shimWispersCallback);
}

static inline WispersStatus callQuicStreamShutdownAsync(WispersQuicStreamHandle *h, void *ctx) {
	return wispers_quic_stream_shutdown_async(h, ctx, shimWispersCallback);
}

static inline WispersStatus callGenerateActivationCodeAsync(WispersServingHandle *h, void *ctx) {
	return wispers_serving_handle_generate_pairing_code_async(h, ctx, shimWispersActivationCodeCallback);
}

static inline WispersStatus callServingSessionRunAsync(WispersServingSession *s, void *ctx) {
	return wispers_serving_session_run_async(s, ctx, shimWispersCallback);
}

static inline WispersStatus callServingShutdownAsync(WispersServingHandle *h, void *ctx) {
	return wispers_serving_handle_shutdown_async(h, ctx, shimWispersCallback);
}

static inline WispersStatus callIncomingAcceptUdpAsync(WispersIncomingConnections *h, void *ctx) {
	return wispers_incoming_accept_udp_async(h, ctx, shimWispersUdpConnectionCallback);
}

static inline WispersStatus callIncomingAcceptQuicAsync(WispersIncomingConnections *h, void *ctx) {
	return wispers_incoming_accept_quic_async(h, ctx, shimWispersQuicConnectionCallback);
}

#endif // WISPERS_HELPERS_H
