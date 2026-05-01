//! Library-managed tokio runtime for async FFI operations.
//!
//! The runtime is lazily initialized on first use and shared across all FFI calls.

use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Initialize logging for the platform.
///
/// On Android, this routes `log` crate output to logcat.
/// On other platforms, this is a no-op (use `RUST_LOG` env var with `env_logger` if needed).
fn init_logging() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("WispersNative"),
        );
    }
}

/// Get or initialize the library's tokio runtime.
///
/// The runtime is created lazily on first call and reused for all subsequent calls.
/// Uses a multi-threaded runtime to handle concurrent async operations.
pub(crate) fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        init_logging();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("wispers-ffi")
            .build()
            .expect("failed to create tokio runtime")
    })
}

/// Spawn an async task on the library runtime.
///
/// The task runs to completion on the runtime's thread pool.
/// Use this for fire-and-forget async operations with callbacks.
pub(crate) fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    get_runtime().spawn(future);
}

/// Block on an async operation using the library runtime.
///
/// This blocks the calling thread until the future completes.
/// Use sparingly - prefer `spawn` with callbacks for non-blocking behavior.
#[allow(dead_code)]
pub(crate) fn block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    get_runtime().block_on(future)
}
