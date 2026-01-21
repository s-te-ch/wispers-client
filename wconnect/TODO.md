# Daemon + Endorser-Side Activation Implementation

## Goal
Enable `wconnect serve` to accept commands via Unix Domain Socket while serving,
so the endorser can generate pairing codes and handle activation requests.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           wconnect serve                                 │
│                                                                          │
│  ┌──────────────────┐         ┌──────────────────────────────────────┐  │
│  │  UDS Listener    │         │  Library: ServingSession (runner)    │  │
│  │  (JSON commands) │         │  - hub gRPC stream                   │  │
│  │                  │         │  - endorsing state                   │  │
│  │                  │         │  - handles PairNodesMessage          │  │
│  │                  │         │  - handles RosterCosignRequest       │  │
│  │                  │         │                                      │  │
│  └────────┬─────────┘         └──────────────────▲───────────────────┘  │
│           │                                      │                       │
│           │ calls methods                        │ sends commands        │
│           ▼                                      │ via channel           │
│  ┌──────────────────┐                            │                       │
│  │ ServingHandle    │────────────────────────────┘                       │
│  │ - status()       │  (Clone-able, passed to UDS handlers)             │
│  │ - gen_pairing()  │                                                   │
│  │ - shutdown()     │                                                   │
│  └──────────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────────┘

Other wconnect commands detect daemon via UDS and send commands to it.
```

### Handle + Runner Pattern (in library)

```rust
// In wispers-connect library:
let (handle, runner) = ServingSession::new(&activated_node);

// Runner owns the event loop and endorsing state
tokio::spawn(async move { runner.run().await });

// Handle is Clone, can be called from anywhere
let code = handle.generate_pairing_secret().await?;
let status = handle.status().await?;
handle.shutdown().await?;
```

The runner internally:
- Maintains hub gRPC stream
- Stores endorsing state (PairingSecret, pending endorsement)
- Handles PairNodesMessage by verifying MAC with stored secret
- Handles RosterCosignRequest by signing if it matches pending endorsement
- Receives commands from handle via internal channel

## Implementation Plan

### 1. Create ServingSession with handle + runner pattern (library) ✓
- [x] Create `ServingSession` runner that owns:
  - Hub gRPC connection (ServingConnection)
  - Endorsing state (Option<PairingSecret>, Option<PendingEndorsement>)
  - Command receiver channel
- [x] Create `ServingHandle` (Clone) with:
  - Command sender channel
  - Async methods: `status()`, `generate_pairing_secret()`, `shutdown()`
- [x] `ActivatedNode::start_serving() -> (ServingHandle, ServingSession)`
- [x] `ServingSession::run(self) -> Result<(), Error>` - the event loop

### 2. Implement endorsing logic in ServingSession (library) ✓
- [x] Handle PairNodesMessage:
  - Check for stored PairingSecret
  - Verify MAC
  - Store new node's pubkey and nonce
  - Generate our nonce, send reply (MAC'd)
  - Transition to PendingEndorsement state
- [x] Handle RosterCosignRequest:
  - Verify new_node_number matches pending endorsement
  - Verify nonces and pubkey in activation payload
  - Sign activation payload
  - Send RosterCosignResponse
  - Clear endorsement state

### 3. Add daemon module to wconnect (CLI)
- [ ] Create `wconnect/src/daemon.rs` with UDS server
- [ ] Socket path: `~/.wconnect/daemon.sock` (one per user)
- [ ] JSON-lines protocol over UDS
- [ ] Translate JSON commands to ServingHandle method calls

### 4. Integrate daemon into `wconnect serve`
- [ ] Create ServingSession, get handle
- [ ] Spawn runner task
- [ ] Start UDS listener, pass handle to connection handlers
- [ ] Handle stale socket cleanup on startup
- [ ] Graceful shutdown when runner completes or shutdown requested

### 5. Add daemon client mode to wconnect
- [ ] Detect running daemon by trying to connect to socket
- [ ] If daemon running: send JSON command via UDS, display result
- [ ] If no daemon: error with helpful message
- [ ] New command: `wconnect get-pairing-code` (talks to daemon)
- [ ] Update `wconnect status` to show daemon info if available

### 6. (Future) True daemonization
- [ ] Add `-d` flag to detach and run in background
- [ ] Redirect stdout/stderr to log file
- [ ] Add `wconnect serve --stop` to shut down daemon

## JSON Protocol

Request/response over UDS, newline-delimited JSON:

```json
// Requests
{"cmd": "status"}
{"cmd": "get_pairing_code"}
{"cmd": "shutdown"}

// Responses
{"ok": true, "data": {"connected": true, "node_number": 1, "cg_id": "...", "endorsing": null}}
{"ok": true, "data": {"pairing_code": "1-abc123defg"}}
{"ok": true, "data": null}
{"ok": false, "error": "already have active pairing session"}
```

## Socket Path

`~/.wconnect/daemon.sock` (one daemon per user)

## Library Types

```rust
// In wispers-connect/src/serving.rs (new module)

pub struct ServingHandle {
    cmd_tx: mpsc::Sender<Command>,
}

pub struct ServingSession {
    cmd_rx: mpsc::Receiver<Command>,
    conn: ServingConnection,
    signing_key: SigningKeyPair,
    node_number: i32,
    // Endorsing state
    pairing_secret: Option<PairingSecret>,
    pending_endorsement: Option<PendingEndorsement>,
}

struct PendingEndorsement {
    new_node_number: i32,
    new_node_pubkey: Vec<u8>,
    new_node_nonce: Vec<u8>,
    our_nonce: Vec<u8>,
}

enum Command {
    Status { reply: oneshot::Sender<StatusInfo> },
    GeneratePairingSecret { reply: oneshot::Sender<Result<PairingCode, Error>> },
    Shutdown,
}
```
