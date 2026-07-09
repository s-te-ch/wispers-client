# Changelog

## Unreleased

Compatibility: works with hubs of v0.1.0 or newer (any hub serving the
`wispers.connect.hub.Hub` service name). Starting with this release, every
release states the oldest hub it supports here. This is a support
statement, not something the client verifies against the hub.

- **Version signaling.** The client now sends its version with every hub
  call (`wispers-client-version` metadata). Should a future hub release
  drop support for old clients, a too-old client gets an explicit
  `IncompatibleVersion` error naming both versions, instead of an obscure
  failure. (No hub rejects anything today.) The hub's own version arrives
  in the `wispers-hub-version` response header.
- **Breaking for Rust consumers:** `HubError` gained the
  `IncompatibleVersion` variant and is now `#[non_exhaustive]` like the
  other error enums — exhaustive `match`es need a wildcard arm, once. FFI
  wrappers are unaffected (no new status code).

## v0.11.0 — Proto namespace cleanup and standalone-hub support

Preparation for publishing a standalone, self-hostable hub, plus minor fixes.

- **`wcadm` works with standalone hubs.** API keys from a standalone hub
  (`wc_standalone_…`) are accepted. Unknown key environments are now an error.
- **Proto packages renamed to `wispers.connect.*`.** An implementation detail on
  the wire, meant to prevent name collisions when linking with other proto-based
  software.
- **Python wheel: fixed an enum-member collision.** cffi flattens enum members
  into one namespace, and v0.10.0's `Revoked` appeared twice.  Enum constants
  are now prefixed with the enum name (`WispersNodeState_Revoked`) — Python code
  referencing the old bare names must update. The C header is unchanged.
- **Swift wrapper types gained public initialisers**, enabling Xcode previews
  during app development.

## v0.10.0 — Node revocation

Adds `revoke_node()` in addition to the existing `logout()` and updates
`group_info` reports accordingly. Breaking for library/FFI consumers, but
wire-compatible with earlier versions.

- **Node revocation.** `revoke_node` removes a compromised peer from the roster,
  and a node that has itself been revoked now degrades gracefully. It reports as
  `Revoked`, stops serving, and can clean up via `logout`. It's a bit of a
  footgun, so it is not exposed in `wconnect`.
- **`group_info` now reports each node's lifecycle state.** `NodeInfo.is_activated:
  Option<bool>` becomes `NodeInfo.state: NodeState` (`Registered` / `Activated` /
  `Revoked`), dropping the redundant `ActivationStatus` type; the FFI accessor
  `wispers_node_activation_status` becomes `wispers_group_node_state`. Peer states
  are now reported even before the local node is activated (so you can tell who can
  endorse you).
- **Pairing codes are no longer written to logs.**

## v0.9.2 — Native stream I/O and dead-connection liveness

Improvements triggered by work on integrating `hyper`. `QuicStream` gains native
poll-based I/O, and a dead transport now surfaces as a prompt error everywhere
instead of hanging. No breaking changes.

- **`QuicStream` now implements tokio's `AsyncRead`/`AsyncWrite` directly.** It
  can be handed to hyper (via `TokioIo`) or any tokio I/O consumer without a
  wrapper, replacing the boxed-future adapter callers previously had to write.
  The existing async `read`/`write`/`finish` methods are unchanged.
- **A dead background driver no longer hangs callers.** If the driver stops (for
  example because the ICE transport fails), parked reads, writes as well as
  `open_stream`, `accept_stream`, and `handshake` calls now return a terminal
  error promptly instead of waiting forever.
- **More concurrent-stream headroom.** The per-connection bidirectional stream
  limit is raised from 100 to 256. This is a compromise value arrived at with
  local load testing.

## v0.9.1 — Stream-handling robustness under load

Stability release hardening the QUIC stream lifecycle and send backpressure
under high-churn, high-throughput use (e.g. proxying a web app). No API changes.

- **Backpressure is now honoured in the QUIC send path.** Outgoing packets are
  paced on quiche's schedule instead of flushed as fast as the loop runs, and a
  full ICE send buffer is treated as transient backpressure rather than a fatal
  error. This stops bursts from overrunning the socket buffer — which could
  starve libjuice's STUN keepalives and drop the connection.
- **Stream teardown and credit handling are more robust.** Streams closed or
  dropped mid-flight are now shut down per-direction and reliably return their
  `MAX_STREAMS` credit, fixing stalls, leaks and a race that surfaced under many
  short-lived streams (notably a stream-per-request proxy).
- **`wconnect`'s HTTP proxy** finishes each request's stream promptly, so the
  peer returns stream credit and long proxy sessions stay healthy under load.

## v0.9.0 — API cleanup and more flexible registration and activation

This release bundles a number of changes that may break library clients. The aim
is to do this once and then have a stable interface for a while.

### Support for long-lifetime registration and activation secrets.

Previously, the tokens and codes used in node registration and activation were
tuned for interactive use with easy-to-type codes and short lifetimes. Wispers
now lets you generate longer-lived tokens and codes that are more suitable for
asynchronous forms of communication, such as email.

### API cleanup

During development, a surprising number of symbols ended up being exported from
the library. Moreover, structs returned from the library were written without
forward compatibility in mind. We did an audit of all exported symbols and
corrected any mistakes we found. _While minor in scope, this is a breaking
change_ and you may have to update your callsites. Compiled binaries stay
compatible across versions.

### Miscellaneous

- **Fix: Added missing info to API.**
  - The node's `group_info()` method now returns ID and name of the node's
	connectivity group.
  - Serving status was only available in Rust, now has been added to all
	available langauge wrappers.
  - The `connected` field in serving status now correctly reflects the status.
- **Fix: Hub connection re-connects**. The connection to the hub can get
  temporarily interrupted, which previously caused a serving node to give up,
  although the comments promised retrying behaviour. This caused long-running
  processes to look alive but not be discoverable. With this release, a node
  will now retry connecting to the hub after recoverable errors.

## v0.8.2 — Connectivity robustness

Stability release focused on the `wconnect` proxy paths. The QUIC connection
pool now recovers when the underlying ICE path dies. Burst-load behavior under
the HTTP proxy is significantly improved.

### Proxy & connection robustness

- **Fix: Connection pool now drops and replaces dead connections.** When the
  underlying ICE path dies, the QUIC connection used to stay cached forever and
  starve every subsequent request. The pool now detects this on the first failed
  stream open, evicts the entry, and the same request transparently retries with
  a fresh connection.
- **Fix: Single-flight connection establishment.** When a burst of concurrent
  requests hits an empty pool entry for the same peer (typical for an HTTP proxy
  fanning out to dozens of hosts on page load), only one ICE handshake runs; the
  others share its result. Previously each request kicked off its own handshake,
  causing a thundering-herd effect.
- **Fix: Hub keepalive** on long-running serving sessions. Prevents the silent
  dying of hub connections that had been observed on otherwise-healthy idle
  nodes.
- **libjuice upgraded to v1.7.1**, picking up the recv-fairness fix — libjuice
  no longer kills its own ICE connection when it hits its per-poll recv cap
  under bursty incoming traffic — plus ICE-TCP fairness fixes.

### Miscellaneous

- **Code quality improvements** by @killerfoxi (thank you!)
- **Shipped Linux binaries now require glibc ≥ 2.35** instead of ≥
  2.39. Unblocks Ubuntu 22.04 LTS, Debian bookworm, and RHEL 9 derivatives.
- **`wconnect` logging migrated from `println!`/`eprintln!` to `tracing`.**
  Per-module verbosity control via the standard `RUST_LOG` environment variable,
  e.g. `RUST_LOG=wconnect=debug`. This reduces log spam when running a proxy and
  lets the user control what gets logged.
- **`build.rs`** now produces an actionable error when the libjuice submodule
  directory exists but is empty — the common state after `git pull` updates the
  submodule pointer without a follow-up `submodule update`.

## v0.8.1 — Platform coverage & easier installs

Polish release. Closes platform gaps from 0.8.0 and makes first-time setup
faster.

### Wider platform coverage

- **Windows** is now a first-class target for Go (cgo + Windows system libs)
  and Python (PyPI wheel `win_amd64`). The Rust crate itself already built on
  Windows previously.
- **`armeabi-v7a` ABI** added to the Android AAR. armv7 devices are no
  longer excluded.
- **Precompiled `wcadm` and `wconnect` binaries** for macOS (arm64, x86_64),
  Linux (amd64, arm64), and Windows. Distributed as `.tar.gz` / `.zip`
  archives on each release.

### Easier CLI install

The CLI tools now don't need to be built from source (which required
installing all the build dependencies) and can be installed as pre-built
binaries instead. The README's quick-start section was updated around this
change.

### Bug fixes

- **iOS xcframework deployment target**: object files were stamped with the
  SDK's default minimum iOS version (currently iOS 26.x on Xcode 26),
  causing "was built for newer iOS-simulator version" warnings on every
  linked object in consumer apps. Now correctly stamped at iOS 15.
- **`Package.swift`** no longer claims macOS support — the XCFramework only
  ships iOS slices, so the declaration was misleading.
- **`wconnect --version`** now works (was a missing clap attribute).

### Wrappers

- **Go**: `cmd/fetch-lib` gains `--output`, `--target`, and `--version`
  flags for build systems that need to control the output path (Bazel and
  similar). Default behavior unchanged.

## v0.8.0 — Open Beta

The first generally available release of Wispers Connect. Previously limited to
trusted testers with invite codes, this release opens the platform to everyone.

### Highlights

A lot of these changes were inspired by tester feedback. Thank you!

- **Open registration** — Invite codes are no longer required to create a
  Wispers Connect account. Anyone can sign up at https://connect.wispers.dev.

- **Security fixes**:
  - **Roster construction fix**: Fixed a vulnerability in roster construction
	and verification that had drifted from the original design.
  - **Protocol change**: Reworked StartConnection signing to be
	forward-compatible. The previous approach made every new proto field a
	wire-breaking change.
  - **Activation codes**: Changed from 10 to 11 base36 characters. Added
	activation code expiry (calibrated to the secret length to limit brute-force
	window). Allow up to 100 concurrent activations per node.

- **Better developer experience**:
  - **Nix**: Added `flake.nix` with development shells for each wrapper language.
  - **Published wrappers to package registries** — The library and wrappers are
	now available as standard dependencies in all supported languages.
  - **Tightened public API**: Removed unnecessary `pub` exports from the library
	to clarify the supported API surface. Added module-level documentation.
  - **CI**: Added GitHub Actions for linting, testing (Linux, macOS, Windows),
	and wrapper builds.

### Wrappers

- **New: Swift** wrapper. SPM package wrapping a prebuilt XCFramework, published
  via GitHub Releases.
- **Go**: Now published with prebuilt static libraries for macOS and Linux,
  downloaded automatically via `go run .../cmd/fetch-lib`.
- **Kotlin/Android**: Now published to Maven Central with bundled `.so` files.
  No Rust toolchain or cargo-ndk needed for consumers.
- **Python**: Now published to PyPI with platform-specific wheels (macOS arm64
  & x86, Linux x86 & arm64). `pip install` just works.

### Backend

- **Scalability improvements**: The backend infrastructure can now easily scale
  horizontally, so we should be able to react to more load by throwing more
  resources at the problem.
