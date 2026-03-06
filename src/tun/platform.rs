//! Platform-specific interface for TUN operations.
//!
//! This module provides traits and types for platform-specific functionality
//! required by the TUN server, particularly for mobile platforms (Android/iOS).
//!
//! # Android Socket Protection
//!
//! On Android, when a VPN is active, all outbound connections are routed through
//! the VPN tunnel. This creates a problem: connections to the upstream proxy server
//! would also be routed through the VPN, creating an infinite loop.
//!
//! To prevent this, Android's `VpnService` provides a `protect(fd)` method that
//! excludes a socket from VPN routing. The [`SocketProtector`] trait allows the
//! Android app to provide this functionality to the Rust code.
//!
//! # Example (Android via JNI)
//!
//! ```ignore
//! // In Kotlin, implement a callback that calls VpnService.protect()
//! class SocketProtectorImpl(private val vpnService: VpnService) {
//!     fun protect(fd: Int): Boolean {
//!         return vpnService.protect(fd)
//!     }
//! }
//!
//! // Pass to Rust via FFI
//! shoesStartTun(config, tunFd, socketProtector)
//! ```

use std::io;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::Arc;

/// Socket protection callback for Android VPN.
///
/// On Android, this trait is implemented by the app to call `VpnService.protect(fd)`
/// on outbound sockets, preventing them from being routed through the VPN tunnel.
///
/// On other platforms, this can be a no-op implementation.
pub trait SocketProtector: Send + Sync {
    /// Protect a socket from VPN routing.
    ///
    /// # Arguments
    /// * `fd` - The raw file descriptor of the socket to protect.
    ///
    /// # Returns
    /// * `Ok(())` if protection succeeded.
    /// * `Err(...)` if protection failed (connection should be aborted).
    #[cfg(unix)]
    fn protect(&self, fd: RawFd) -> io::Result<()>;

    /// Protect a socket from VPN routing (non-Unix stub).
    #[cfg(not(unix))]
    fn protect(&self, fd: i32) -> io::Result<()>;
}

/// A no-op socket protector for platforms that don't need protection.
///
/// Used on Linux desktop and other non-VPN platforms.
#[derive(Debug, Clone, Default)]
pub struct NoOpSocketProtector;

impl SocketProtector for NoOpSocketProtector {
    #[cfg(unix)]
    fn protect(&self, _fd: RawFd) -> io::Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn protect(&self, _fd: i32) -> io::Result<()> {
        Ok(())
    }
}

// On Android, sockets need protection from VPN routing. This global protector
// provides a callback for the connection infrastructure.
//
// TODO: For a cleaner design, pass SocketProtector through the connection
// chain (similar to shadowsocks-rust's ConnectOpts). This global approach
// is simpler but less elegant.

use std::sync::RwLock;

static GLOBAL_SOCKET_PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

/// Set the global socket protector for Android VPN protection.
///
/// This should be called before starting the TUN service on Android.
/// Can be called multiple times (e.g., on VPN reconnect) - replaces the previous protector.
/// On other platforms, this can be left unset (no-op behavior).
pub fn set_global_socket_protector(protector: Arc<dyn SocketProtector>) {
    *GLOBAL_SOCKET_PROTECTOR.write().unwrap() = Some(protector);
}

/// Get the global socket protector.
///
/// Returns the set protector, or a no-op protector if none was set.
fn get_global_socket_protector() -> Arc<dyn SocketProtector> {
    GLOBAL_SOCKET_PROTECTOR
        .read()
        .unwrap()
        .clone()
        .unwrap_or_else(|| Arc::new(NoOpSocketProtector))
}

/// Protect a socket using the global protector.
///
/// This is a convenience function for use in socket creation code.
///
/// # Arguments
/// * `fd` - The raw file descriptor to protect.
///
/// # Returns
/// * `Ok(())` if protection succeeded or no protector is set.
/// * `Err(...)` if protection failed.
#[cfg(unix)]
pub fn protect_socket(fd: RawFd) -> io::Result<()> {
    get_global_socket_protector().protect(fd)
}

/// Protect a socket using the global protector (non-Unix stub).
#[cfg(not(unix))]
pub fn protect_socket(fd: i32) -> io::Result<()> {
    get_global_socket_protector().protect(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_protector() {
        let protector = NoOpSocketProtector;
        assert!(protector.protect(42).is_ok());
    }
}
