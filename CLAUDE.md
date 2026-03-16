# Claude Code Hints for Wispers Connect Client

## Quick Orientation

- **What is this?** Rust client library + CLI for peer-to-peer connectivity
- **Start here:** [ARCHITECTURE.md](./ARCHITECTURE.md) for code structure, [../DESIGN.md](../DESIGN.md) for protocol
- **Build:** `cargo build` from this directory
- **Test:** `cargo test`

## Key Files by Task

| If working on... | Read these first |
|------------------|------------------|
| Node state/lifecycle | `wispers-connect/src/state.rs` |
| Hub communication | `wispers-connect/src/hub.rs`, `proto/hub.proto` |
| Serving/endorsing | `wispers-connect/src/serving.rs` |
| Activation flow | `wispers-connect/src/activation.rs` |
| P2P connections | `wispers-connect/src/p2p.rs`, `wispers-connect/src/quic.rs` |
| ICE/NAT traversal | `wispers-connect/src/ice.rs`, `wispers-connect/src/juice.rs` |
| CLI commands | `wconnect/src/main.rs` |
| Daemon mode | `wconnect/src/daemon.rs` |
| Roster crypto | `wispers-connect/src/roster.rs`, `proto/roster.proto` |

## Common Pitfalls

### Proto field numbering
In protobuf `oneof`, field numbers are shared with the parent message. If `ServingRequest` uses fields 1-2, the oneof variants must start at 3+.

### State machine
Nodes must progress: Unregistered → Registered → Activated. You can't skip states. `RegisteredNodeState` can serve (for bootstrap) but can't connect to peers.

### Daemon architecture
The daemon starts the UDS listener *before* connecting to the hub. While connecting, status requests return "not connected yet" rather than blocking.

### Async/daemonize interaction
Daemonization (`daemonize` crate) must happen *before* creating the tokio runtime. See `daemonize_serve()` in main.rs.

### Self-endorsement
A node cannot activate using its own activation code. The `activate` command checks this.

## Code Style

- Error handling: Use `anyhow` in wconnect (CLI), typed errors in wispers-connect (library)
- Async: tokio with multi-threaded runtime
- State persistence: JSON files in `~/.wconnect/` (configurable via `FileStore`)

## Hub Server

The hub is in `connect/hub/` (Go). Key files:
- `routing.go` - Handles StartServing streams, sends Welcome message
- `hubsrv.go` - RPC implementations
