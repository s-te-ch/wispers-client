# Claude Code Hints

Read [docs/INTERNALS.md](./docs/INTERNALS.md) first — it has the module map, key types, state machine, FFI patterns, and architecture diagrams.

## Build & test

- `cargo build` / `cargo test` from this directory
- C FFI test: `cd wispers-connect/tests/c_ffi && make test`
- C FFI demo: `cd examples/c && make`

## Pitfalls

- **Proto `oneof` field numbering**: field numbers are shared with the parent message, not scoped to the oneof
- **Daemonize before tokio**: `daemonize_serve()` in `wconnect/src/main.rs` must fork before creating the runtime
- **Self-endorsement**: a node cannot activate using its own activation code

## Code style

- `anyhow` in wconnect (CLI), typed errors in wispers-connect (library)
