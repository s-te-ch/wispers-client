# Port Forwarding Implementation

Add TCP port forwarding over QUIC streams, similar to SSH local forwarding.

## Goal

```
wconnect forward <local_port> <node> <remote_port>
```

Listen on `local_port` locally, forward connections through QUIC to `node`,
where they connect to `localhost:remote_port`.

Example:
```bash
# Forward local port 8080 to port 3000 on node 2
wconnect forward 8080 2 3000

# Now localhost:8080 reaches node 2's localhost:3000
curl http://localhost:8080
```

---

## Decisions Log

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| Scope | -L only, -L and -R, full SSH-style | **-L only** | PoC, keep it simple |
| Syntax | SSH-style `-L a:b:c`, positional args | **Positional** | Clearer semantics, less confusion |
| Transport | UDP, QUIC | **QUIC** | Need reliable streams for TCP forwarding |
| Session protocol | Protobuf, line-based, length-prefixed | **Line-based** | Simple, easy to debug |
| Connection model | QUIC-per-TCP, single QUIC + streams | **Single + streams** | Efficient, what QUIC is designed for |

---

## Phase 1: Stream Protocol

### 1.1 Define session types
- [x] `PING\n` - existing ping/pong behavior
- [x] `FORWARD <port>\n` - request TCP forwarding to localhost:port

### 1.2 Update ping command
- [x] Send `PING\n` as first line instead of raw "ping"
- [x] Update serve to parse first line and dispatch

### 1.3 Implement forward handler (serve side)
- [x] On incoming QUIC **stream**, read first line
- [x] If `FORWARD <port>\n`:
  - [x] Connect to `localhost:<port>` via TCP
  - [x] If connection fails, send `ERROR <reason>\n` and close stream
  - [x] If connection succeeds, send `OK\n` and start relaying

---

## Phase 2: Forward Command

### 2.1 CLI
- [x] Add `forward` subcommand: `wconnect forward <local_port> <node> <remote_port>`
- [x] Argument validation (ports 1-65535, node must be number for now)

### 2.2 Local listener
- [x] Bind TCP listener on `localhost:<local_port>`
- [x] Accept incoming connections

### 2.3 QUIC connection
- [x] Connect to target node via QUIC (reuse existing `connect_quic`)
- [x] Open stream, send `FORWARD <remote_port>\n`
- [x] Wait for `OK\n` or error response

### 2.4 Relay
- [x] Bidirectional copy: TCP socket <-> QUIC stream
- [ ] Handle EOF in both directions (half-close) - **partial, reload issue**
- [x] Clean shutdown on stream/socket close

---

## Phase 3: Polish

### 3.1 Multiple connections
- [x] Single QUIC connection to target node, kept alive
- [x] Each incoming TCP connection gets its own QUIC stream

### 3.2 Error handling
- [ ] Connection refused on remote
- [ ] Node not serving
- [ ] QUIC connection failure
- [ ] Timeout configuration

### 3.3 Logging/status
- [ ] Log connections (optional verbose mode)
- [ ] Show active forwards in `wconnect status`?

---

## Future Work (Out of Scope)

- Remote forwarding (`-R` style)
- SOCKS proxy mode
- Bind address configuration (expose externally)
- Forward over UDP transport
- Multiple forwards in single command
- Persistent/reconnecting forwards

---

## Open Questions

1. ~~**One QUIC connection vs many?**~~ **Resolved:** Single QUIC connection, one stream per TCP connection.

2. **Node identification:** Currently node number only. Add node name support later?

---

## Notes

- QUIC streams already provide reliable, ordered delivery - perfect for TCP forwarding
- The session protocol is intentionally simple (line-based) for easy debugging
- Half-close semantics: when TCP client closes write side, call `stream.finish()`
