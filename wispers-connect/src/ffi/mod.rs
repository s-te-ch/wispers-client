//! FFI bindings for the wispers-connect library.
//!
//! Module structure:
//! - `types`: All FFI types, callbacks, handle wrappers, and memory management
//! - `node`: Storage and node lifecycle operations
//! - `serving`: Serving session operations
//! - `p2p`: P2P connection operations
//! - `runtime`: Tokio runtime management
//!
//! Each submodule declares its C-callable entry points as
//! `#[unsafe(no_mangle)] pub extern "C" fn …`. The linker picks those up into
//! the shared library (`.so` / `.dylib` / `.dll`) by exact name, so the
//! symbols' Rust module path is irrelevant to C consumers — the names in
//! `include/wispers_connect.h` are what defines the ABI.

// FFI functions necessarily dereference raw pointers from C callers.
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::mut_from_ref)]

mod node;
mod p2p;
pub(crate) mod runtime;
mod serving;
mod types;
