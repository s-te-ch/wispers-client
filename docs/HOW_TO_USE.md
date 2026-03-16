# How to use it

This guide shows how to integrate Wispers Connect into your application.
Examples are provided for each wrapper: Rust, Kotlin/Android, and Go.

## Prerequisites

<!-- TODO: what you need before integrating:
     - A Wispers Connect domain (from the web UI)
     - An API key for creating connectivity groups and registration tokens
     - The client library for your platform -->

## Setup

<!-- TODO: how to add the library to your project.
     Subsections for each platform:

     ### Rust
     - Cargo dependency
     - Feature flags if any

     ### Kotlin/Android
     - Gradle dependency
     - cargo-ndk setup for building the native library
     - JNA configuration

     ### Go
     - go get / module dependency
     - CGo requirements (linking the Rust .so/.dylib)
     -->

## Storage

<!-- TODO: explain the NodeStateStore interface.
     The library needs persistent storage for root keys and registration.
     Cover:
     - What's stored (root key, registration protobuf)
     - Built-in options (in-memory for testing, file-based for CLI)
     - Implementing custom storage (callbacks for Android SharedPreferences,
       keychain, etc.)
     - Important: use commit() not apply() on Android (see MEMORY.md)
     Show examples for each wrapper. -->

## Registering a node

<!-- TODO: full example of the registration flow:
     1. Integrator backend creates a registration token via REST API
     2. Token is handed to the app (deep link, QR code, paste)
     3. App calls node.register(token)
     Show code for each wrapper. -->

## Activating a node

<!-- TODO: two scenarios:

     ### Bootstrap (first two nodes)
     - Both nodes are registered but no roster exists
     - One node generates an activation code, other enters it
     - Both transition to Activated

     ### Endorsement (subsequent nodes)
     - An activated node generates an activation code while serving
     - The new node calls node.activate(code)

     Show code for each wrapper. -->

## Serving

<!-- TODO: explain the serving session:
     - What it does (connects to Hub, makes node reachable)
     - Starting a serving session
     - Running the event loop
     - Generating activation codes
     - Shutting down
     Show code for each wrapper. -->

## Connecting to peers

<!-- TODO: examples of both transport types:

     ### UDP
     - When to use (real-time, low-latency)
     - Opening a connection, sending/receiving

     ### QUIC
     - When to use (reliable data transfer, multiple streams)
     - Opening a connection, opening streams, read/write/finish
     - Accepting incoming streams

     Show code for each wrapper. -->

## Logout

<!-- TODO: explain what logout does at each state:
     - Pending: deletes local state
     - Registered: deregisters from Hub, deletes local state
     - Activated: self-revokes from roster, deregisters, deletes local state
     Show code for each wrapper. -->

## Error handling

<!-- TODO: cover common error scenarios:
     - Hub unreachable
     - Unauthenticated (node removed server-side)
     - Invalid activation code
     - Peer rejected / unavailable
     - State-inappropriate operations (InvalidState)
     Explain the error types for each wrapper. -->

## Complete example

<!-- TODO: a realistic end-to-end example tying it all together.
     Something like a simple file transfer or echo service.
     Pick one wrapper (probably Go for readability) and show the full
     program. Link to the Files CLI as a real-world example. -->
