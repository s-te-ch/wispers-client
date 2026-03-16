# Client Architecture

This document describes the code structure of the Wispers Connect client.
For protocol design and concepts, see [../DESIGN.md](../DESIGN.md).

## Directory Structure

```
client/
├── wispers-connect/     # Core library (Rust)
├── wconnect/            # CLI tool
├── wcadm/               # Admin CLI (for integrators)
├── proto/               # Protobuf definitions (shared with hub)
└── libwispers/          # C FFI bindings (for mobile/native integrations)
```

## Module Responsibilities

### wispers-connect (library)

The core library that applications embed. Handles:
- **State management** (`state.rs`): Node lifecycle, persistent storage
- **Hub connection** (`hub.rs`): gRPC client for Hub communication
- **Serving** (`serving.rs`): Long-lived connection for receiving requests
- **Activation** (`activation.rs`): Pairing and roster update logic
- **Crypto** (`keys.rs`, `roster.rs`): Signing keys, roster verification

### wconnect (CLI)

User-facing command-line tool. Handles:
- **Commands**: register, activate, serve, status, etc.
- **Daemon mode** (`daemon.rs`): Background serving with UDS control socket
- **User interaction**: Prompts, output formatting

### Relationship

```
┌─────────────────────────────────────────────────┐
│  wconnect (CLI)                                 │
│  - User commands                                │
│  - Daemon management                            │
│  - UDS server (when serving)                    │
└────────────────────┬────────────────────────────┘
                     │ uses
                     ▼
┌─────────────────────────────────────────────────┐
│  wispers-connect (library)                      │
│  - State machine                                │
│  - Hub gRPC client                              │
│  - Crypto operations                            │
└─────────────────────────────────────────────────┘
```

## Node State Machine

Nodes progress through distinct states, each with different capabilities:

```
                    register(token)
                          │
                          ▼
              ┌───────────────────────┐
              │  RegisteredNodeState  │
              │  - Can authenticate   │
              │  - Can serve (for     │
              │    bootstrap activate)│
              │  - Cannot connect to  │
              │    other nodes        │
              └───────────┬───────────┘
                          │ activate(activation_code)
                          ▼
              ┌───────────────────────┐
              │  ActivatedNodeState   │
              │  - On the roster      │
              │  - Can serve          │
              │  - Can connect to     │
              │    other nodes        │
              │  - Can endorse new    │
              │    nodes              │
              └───────────┬───────────┘
                          │ start_serving()
                          ▼
              ┌───────────────────────┐
              │  ServingSession       │
              │  (handle + runner)    │
              └───────────────────────┘
```

### State Transitions in Code

```rust
// Load or initialize state
let storage = NodeStorage::new(FileStore::new(base_path));
let state = storage.restore_or_init_node_state(...).await?;

match state {
    NodeState::Unregistered(s) => {
        let registered = s.register(token).await?;
    }
    NodeState::Registered(s) => {
        let activated = s.activate(activation_code).await?;
    }
    NodeState::Activated(s) => {
        let (handle, session) = s.start_serving().await?;
        tokio::spawn(session.run());
        // Use handle to control the session
    }
}
```

## Serving Architecture (Handle + Runner)

When a node serves, it uses a split architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                        wconnect serve                           │
│                                                                 │
│  ┌──────────────────┐       ┌─────────────────────────────────┐│
│  │  UDS Server      │       │  ServingSession (runner)        ││
│  │  (daemon.rs)     │       │  - Hub gRPC stream              ││
│  │                  │       │  - Endorsing state              ││
│  │  Accepts JSON    │       │  - Handles PairNodesMessage     ││
│  │  commands from   │       │  - Handles RosterCosignRequest  ││
│  │  other processes │       │                                 ││
│  └────────┬─────────┘       └──────────────▲──────────────────┘│
│           │                                │                    │
│           │ method calls                   │ channel            │
│           ▼                                │                    │
│  ┌─────────────────────────────────────────┴──────────────────┐│
│  │  ServingHandle (Clone-able)                                ││
│  │  - status() -> StatusInfo                                  ││
│  │  - generate_activation_code() -> ActivationCode             ││
│  │  - shutdown()                                              ││
│  └────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

- **ServingSession**: Owns the gRPC stream and endorsing state. Runs as a spawned task.
- **ServingHandle**: Clone-able handle for controlling the session. Communicates via channels.

## Daemon Mode

When running `wconnect serve -d`, the process daemonizes and listens on a Unix socket:

**Socket path**: `~/.wconnect/sockets/{connectivity_group_id}-{node_number}.sock`
**Log file**: `~/.wconnect/logs/{connectivity_group_id}-{node_number}.log`

### JSON Protocol

Commands are newline-delimited JSON:

```json
// Requests
{"cmd": "status"}
{"cmd": "get_activation_code"}
{"cmd": "shutdown"}

// Responses
{"ok": true, "data": {"connected": true, "node_number": 1, ...}}
{"ok": false, "error": "not connected to hub yet"}
```

### Client Commands

Other wconnect invocations detect the daemon and communicate via UDS:
- `wconnect status` - Shows daemon status if running
- `wconnect get-activation-code` - Asks daemon to generate code
- `wconnect serve --stop` - Sends shutdown command

## Activation Flow (Code Path)

From DESIGN.md, activation has two phases. Here's how they map to code:

### Phase 1: Pairing

```
Node B (new)                          Node A (endorser)
────────────                          ─────────────────
activate(code)
  │
  ├─► parse code → (node_number, secret)
  │
  ├─► ActivatingNodeState::pair_with_endorser()
  │     │
  │     ├─► build PairNodesMessage (pubkey, nonce, HMAC)
  │     │
  │     └─► Hub.PairNodes() ──────────────────────────►  ServingSession receives
  │                                                       via StartServing stream
  │                                                           │
  │                                                           ▼
  │                                                      verify HMAC with
  │                                                      stored PairingSecret
  │                                                           │
  │                                                           ▼
  │         ◄─────────────────────────────────────────  reply with own pubkey,
  │                                                      nonce, HMAC
  ▼
verify reply HMAC
store endorser's pubkey
```

### Phase 2: Roster Update

```
Node B                                Hub                    Node A
──────                                ───                    ──────
create new roster
sign addendum
  │
  └─► UpdateRoster() ──────────────►  verify
                                      request cosign ──────► ServingSession
                                                             receives
                                                             RosterCosignRequest
                                                                  │
                                                                  ▼
                                                             verify roster
                                                             matches pairing
                                                                  │
                                       ◄──────────────────── sign & return
                                      combine signatures
                                      store roster
  ◄───────────────────────────────────
done, now activated
```

## Key Types Reference

| Type | Location | Purpose |
|------|----------|---------|
| `NodeStorage` | `state.rs` | Manages persistent node state |
| `NodeState` | `state.rs` | Enum: Unregistered/Registered/Activated |
| `RegisteredNodeState` | `state.rs` | Can serve (bootstrap) or activate |
| `ActivatedNodeState` | `state.rs` | Full node, can serve and connect |
| `ServingHandle` | `serving.rs` | Clone-able control for serving session |
| `ServingSession` | `serving.rs` | Runner that owns hub stream |
| `PairingSecret` | `activation.rs` | Generated secret for endorsing |
| `ActivationCode` | `activation.rs` | User-facing code: `{node}-{secret}` |
| `SigningKeyPair` | `keys.rs` | Ed25519 signing key |

## Proto Messages (Activation)

From `proto/hub.proto`:

| Message | Direction | Purpose |
|---------|-----------|---------|
| `PairNodesMessage` | B → Hub → A → Hub → B | Exchange pubkeys with HMAC |
| `RosterCosignRequest` | Hub → A | Ask endorser to co-sign |
| `RosterCosignResponse` | A → Hub | Endorser's signature |
| `UpdateRosterRequest` | B → Hub | Submit new roster |
| `Welcome` | Hub → Node | Sent on StartServing connect |

## Common Tasks

### Adding a new wconnect command

1. Add variant to `Command` enum in `wconnect/src/main.rs`
2. Add match arm in `async_main()`
3. If it needs daemon communication, add to `DaemonRequest`/`DaemonResponse` in `daemon.rs`

### Adding a new ServingHandle method

1. Add variant to `Command` enum in `wispers-connect/src/serving.rs`
2. Add method on `ServingHandle` that sends command and awaits reply
3. Handle the command in `ServingSession::run()` event loop

### Modifying the proto

1. Edit `proto/*.proto`
2. Regenerate: `cd proto && ./gen.sh` (generates Rust and Go)
3. Update both client (Rust) and hub (Go) code

## P2P Transport Architecture

Activated nodes can establish peer-to-peer connections using two transport types:

```
┌─────────────────────────────────────────┐
│            Application                  │
├───────────────────┬─────────────────────┤
│   UdpConnection   │   QuicConnection    │
│  (raw UDP + AES)  │  (QUIC streams)     │
├───────────────────┴─────────────────────┤
│        IceCaller / IceAnswerer          │
│            (libjuice FFI)               │
├─────────────────────────────────────────┤
│             UDP Socket                  │
└─────────────────────────────────────────┘
```

### Transport Types

| Type | Use Case | Properties |
|------|----------|------------|
| `UdpConnection` | Low-latency, fire-and-forget | AES-GCM encryption, unreliable delivery |
| `QuicConnection` | Reliable data transfer | TLS 1.3 PSK, ordered streams, flow control |

### Key Files

- `p2p.rs` - Public API: `UdpConnection`, `QuicConnection`, `QuicStream`
- `quic.rs` - QUIC implementation using quiche with TLS-PSK authentication
- `ice.rs` - ICE negotiation wrapper around libjuice
- `juice.rs` - Low-level FFI bindings to libjuice C library

### QUIC Authentication

QUIC uses TLS 1.3 Pre-Shared Key (PSK) mode, not certificates:
- PSK derived from X25519 DH exchange (same keys used for UDP encryption)
- Server generates ephemeral in-memory cert (BoringSSL requirement for PSK)
- No certificate verification needed - authentication is via the shared PSK

### Connection Flow

1. Caller requests `StunTurnConfig` from hub
2. Both sides gather ICE candidates via libjuice
3. Caller sends `StartConnectionRequest` (includes transport type, X25519 pubkey)
4. Answerer verifies signature, responds with own X25519 pubkey
5. ICE negotiation establishes UDP path
6. For QUIC: PSK handshake over ICE transport, then streams available
