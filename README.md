<center>
  <img src="docs/images/wispers-connect-logo-and-text-trans.svg"
       width="256" alt="Wispers Connect logo"/>
</center>

## About Wispers Connect

Wispers is an application-level secure overlay network. It connects software
running on different devices with secure, NAT-traversing, peer-to-peer
connections.

A central rendezvous server coordinates connection setup, but unlike other
NAT-traversal systems, you don't have to trust it. Nodes verify each other using
a cryptographic roster, so neither the server nor any other infrastructure can
eavesdrop or tamper with traffic.

You just link the wispers-connect library (or run a sidecar process), and your
software can now connect to other instances, securely and directly. The library
is written in Rust and C and has wrappers for a growing set of other languages.

## Quick start

As an introduction to how things work, let's set up two nodes communicating over
a peer-to-peer connection.

### 0. Prerequisites

- A local clone of the `wispers-client` repository (this one)
- Initialise submodules: `git submodule update --init --recursive`
- The build prerequisites listed under [Building](#building) below

### 1. Get a Connect account & API key

Establishing connections using NAT-traversal requires a rendezvous server, which
we call the "hub" in Wispers. We need to tell the hub about you and your use
case. To do that,

1. Get an account at https://connect.wispers.dev. You'll get a personal account
   with a **domain** named "Default" already set up for you. Domains map to use
   cases — say you create a new app with Wispers Connect, you'd use a separate
   domain for that.
2. Create an **API key** for the "Default" domain. Click on the domain in the
   web UI and the form is right there. Give it a name like "test" and make sure
   to copy down the key! Wispers doesn't store it.

### 2. Create a connectivity group

At this point, we leave the web UI and take to the terminal to create our first
**connectivity group**. These groups are the basic unit of connectivity in
Wispers. All nodes in a connectivity group can talk to each other and (after
activation) trust each other. In [Wispers Files](https://files.wispers.dev) for
example, each user gets their own connectivity group to connect their devices to
each other.

For this introduction, we'll create a single group named "quick-start" using the
`wcadm` tool. From the root of the repository, run

```bash
export WC_API_KEY=$YOURKEY # Your API key, "wc_prod_..."
cargo run --bin wcadm add-group --name=quick-start
```

The output will show a UUID for your newly created connectivity group. You'll
need that to add nodes to the group.

Note that you don't _have_ to use the `wcadm` tool for this. When writing an
application that uses Wispers Connect, you'll often want to use the REST API at
https://connect.wispers.dev/api from your own code instead.

### 3. Register nodes

**Nodes** are the things that actually communicate in Wispers. You usually
create your own by linking the wispers-connect library, but we've also created a
command line tool that you can use as a sidecar or for testing,
`wconnect`. We'll use it here to demonstrate node registration & activation. If
you want to, you can do this from two different devices or two terminals, but a
single terminal is sufficient for this quick-start.

Let's start by registering a node with the connectivity group we've just
created. First, we need a registration token (make sure to set `YOUR_GROUP_ID`
to the connectivity group ID from step 2).

```bash
cargo run --bin wcadm -- \
    create-registration-token ${YOUR_GROUP_ID} \
    --name="first node"
```

This prints a registration token. Let's use it to actually register the node.

```bash
cargo run --bin wconnect -- \
    --profile="quick-start-1" \
    register ${YOUR_REGISTRATION_TOKEN}
```

In case you're wondering: The `--profile` parameter lets you register multiple
nodes on the same computer, under the same user — perfect for our quick-start.

Let's register another node, so we have two we can connect to each other.

```bash
cargo run --bin wcadm -- \
    create-registration-token ${YOUR_GROUP_ID} \
    --name="second node"

# Note the registration token and use it in the next command.

cargo run --bin wconnect -- \
    --profile="quick-start-2" \
    register ${YOUR_REGISTRATION_TOKEN}
```

At this point, the nodes can send each other messages through the hub, but it
still requires trusting the Wispers Connect backend not to eavesdrop on messages
or impersonate nodes. While we assure you the Wispers team is trustworthy, you
don't have to take our word for it. Enter activation.

### 4. Activate the nodes

Once nodes are registered, you **activate** them to establish peer-to-peer
trust. This is the step that makes it impossible for the hub to eavesdrop or
impersonate. The trick is simple: 1. one node generates an _activation
code_; 2. the user copies the code to the other node; 3. the two nodes exchange
public keys using this shared code to verify that the hub didn't interfere.

To do this with `wconnect`:

```bash
# Put one node into serving mode (it needs to stay online for the handshake)
# and generate an activation code.
cargo run --bin wconnect -- --profile="quick-start-1" serve -d
cargo run --bin wconnect -- --profile="quick-start-1" get-activation-code

# Use the code to activate the other node
cargo run --bin wconnect -- --profile="quick-start-2" \
    activate ${YOUR_ACTIVATION_CODE}
```

Done! Have a look at the nodes in the connectivity group. You should see
something like

```bash
$ cargo run --bin wconnect -- --profile="quick-start-1" nodes
# [... omitted cargo output...]
Nodes in connectivity group X (state: AllActivated):
  1: first node (you, activated) - online
  2: second node (activated) - never connected
```

To verify things work, send a peer-to-peer ping between the nodes:

```bash
cargo run --bin wconnect -- --profile="quick-start-2" ping 1
# [... omitted cargo output...]
Pinging node 1 via UDP...
  Connected in 854.116041ms
  Pong received in 1.055834ms
Ping successful! Total time: 855.485083ms
```

Congratulations, your nodes have just successfully established a secure
peer-to-peer connection!

## Documentation

- **[How it works](docs/HOW_IT_WORKS.md)** — Transport, security model,
  and protocol design
- **[How to use it](docs/HOW_TO_USE.md)** — Integration guide with
  example use cases.
- **[Internals](docs/INTERNALS.md)** — Code map, module responsibilities,
  and key types
- **[Frequently Asked Questions](docs/FAQ.md)** — Comparisons to other
  solutions, licensing questions, etc.
## Building

### Rust library & CLI tools

Prerequisites:

- A [Rust toolchain](https://rust-lang.org/tools/install/) (install via `rustup`)
- [CMake](https://cmake.org/) — builds the bundled libjuice ICE library and BoringSSL
- [LLVM/Clang](https://releases.llvm.org/) — `bindgen` needs `libclang` for FFI generation
- [protoc](https://github.com/protocolbuffers/protobuf/releases) — Protocol Buffers compiler (used by `tonic-build`)
- [Go](https://go.dev/) — required by the BoringSSL build
- [NASM](https://www.nasm.us/) — assembler for BoringSSL's optimised routines

Install these via your package manager (e.g. `apt` on Linux, `brew` on macOS, `winget` on Windows).

To build:

```bash
cargo build          # library + wconnect + wcadm
cargo test           # run all tests
```

The workspace produces three artifacts:

| Crate | Type | Description |
|-------|------|-------------|
| `wispers-connect` | lib (`rlib` + `cdylib`) | Core library; the `cdylib` output is the shared library used by language wrappers |
| `wcadm` | binary | Admin CLI for managing domains and groups via the REST API |
| `wconnect` | binary | CLI tool for node operations |

### Language wrappers

Wrappers live in `wrappers/` and link against the shared library built above.

**Go** (`wrappers/go/`) — uses CGo. Requires a Rust toolchain. From the wrapper directory:

```bash
cd wrappers/go
go generate ./...   # builds the Rust library (release profile)
go build ./...
```

**Kotlin/Android** (`wrappers/kotlin/`) — uses JNA. Build with Gradle; requires a pre-built `libwispers_connect.so` for your target ABI. Cross-compile the Rust library with the Android NDK (`ANDROID_NDK_HOME` environment variable) and [cargo-ndk](https://github.com/nickelc/cargo-ndk):

```bash
cargo ndk -t arm64-v8a build
```

**Swift** (`wrappers/swift/`) — Swift Package wrapping an XCFramework. Add as a dependency in Xcode using the repository URL `https://github.com/s-te-ch/wispers-client`. The prebuilt xcframework is downloaded automatically via SPM.

To rebuild the xcframework from source (for development):

```bash
cd wrappers/swift && scripts/build-xcframework.sh --release
```

**Python** (`wrappers/python/`) — uses ctypes. Requires Python 3.11+. Install from PyPI (includes the native library):

```bash
pip install wispers-connect
```

For development, build the wheel locally with [maturin](https://www.maturin.rs/):

```bash
cd wrappers/python
python3 -m venv .venv && source .venv/bin/activate
maturin develop          # builds the Rust library and installs into the venv
```

See **[How to use it](docs/HOW_TO_USE.md)** for wrapper-specific integration details.

### Examples

The `examples/` directory has small, runnable programs for several languages:

| Directory | Description |
|-----------|-------------|
| `examples/c/` | C FFI demo using the shared library directly |
| `examples/go/` | Go CLI using the Go wrapper (`make` to build) |
| `examples/kotlin/` | Android app using the Kotlin wrapper |
| `examples/python/` | Python CLI using the Python wrapper (`./run.sh` to run) |

## License

This project is licensed under the [MIT License](LICENSE).
