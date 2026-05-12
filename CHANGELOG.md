# Changelog

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
