# Internals

Code map, module responsibilities, and key types for contributors and
curious integrators.

## Directory structure

<!-- TODO: update this tree to reflect the current layout.
     Source material: ARCHITECTURE.md "Directory Structure".
     Current structure:
     client/
     ├── wispers-connect/    # Core Rust library
     │   ├── src/
     │   │   ├── node.rs     # Node type, state machine, group_info
     │   │   ├── hub.rs      # gRPC client for Hub
     │   │   ├── serving.rs  # ServingSession + ServingHandle
     │   │   ├── types.rs    # NodeInfo, GroupInfo, NodeRegistration
     │   │   ├── crypto.rs   # Signing keys, X25519, activation codes
     │   │   ├── roster.rs   # Roster verification, creation
     │   │   ├── p2p.rs      # UdpConnection, QuicConnection
     │   │   ├── ice.rs      # ICE negotiation (libjuice wrapper)
     │   │   ├── ffi/        # C FFI boundary
     │   │   └── ...
     │   ├── include/        # C header (wispers_connect.h)
     │   └── proto/          # Protobuf definitions
     ├── wrappers/
     │   ├── kotlin/         # Kotlin/Android JNA wrapper
     │   └── go/             # Go CGo wrapper
     ├── wconnect/           # CLI tool
     └── docs/               # This directory
     -->

## Module responsibilities

<!-- TODO: one paragraph per module explaining what it owns.
     Source material: ARCHITECTURE.md "Module Responsibilities".
     Cover: node.rs, hub.rs, serving.rs, types.rs, crypto.rs, roster.rs,
     p2p.rs, ice.rs, ffi/, storage.rs. -->

## Key types

<!-- TODO: table of the main types, where they live, and what they do.
     Source material: ARCHITECTURE.md "Key Types Reference".
     Include both Rust types and their wrapper equivalents
     (e.g. Node in Rust vs Node in Kotlin vs wispersgo.Node in Go). -->

## FFI boundary

<!-- TODO: explain how the Rust library is exposed through C FFI:
     - The WispersNode, WispersGroupInfo structs
     - Callback-based async pattern
     - Memory ownership rules (who frees what)
     - Known pitfalls: JNA bool mapping (use Byte not Boolean),
       Structure.toArray() doesn't read() first element
     Source material: ARCHITECTURE.md and MEMORY.md notes on JNA. -->

## Serving architecture

<!-- TODO: explain the Handle + Runner split:
     - ServingSession owns the gRPC stream, runs as spawned task
     - ServingHandle is Clone-able, communicates via channels
     - How activation code generation and endorsement work during serving
     Source material: ARCHITECTURE.md "Serving Architecture" diagram. -->

## Activation flow (code path)

<!-- TODO: map the pairing and roster update flows to specific functions
     and files. This is the "where in the code" complement to
     HOW_IT_WORKS.md's "how it works" explanation.
     Source material: ARCHITECTURE.md "Activation Flow" section. -->

## P2P transport internals

<!-- TODO: cover the implementation details:
     - libjuice FFI (juice.rs) and the ICE wrapper (ice.rs)
     - UDP encryption (AES-GCM with X25519-derived key)
     - QUIC over ICE (quiche with TLS-PSK, BoringSSL)
     - Connection ID management
     Source material: ARCHITECTURE.md "P2P Transport Architecture"
     and "QUIC Authentication" sections. -->

## Proto definitions

<!-- TODO: list the key proto messages and their purposes.
     Source material: ARCHITECTURE.md "Proto Messages" table.
     Cover hub.proto (Node, StartConnectionRequest, PairNodesMessage, etc.)
     and roster.proto (Roster, Addendum, Revocation). -->

## Common contributor tasks

<!-- TODO: recipes for common changes:
     - Adding a new Node method (Rust -> FFI -> C header -> wrappers)
     - Adding a new hub RPC
     - Modifying proto definitions
     - Adding a new CLI command
     Source material: ARCHITECTURE.md "Common Tasks" section. -->
