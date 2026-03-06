// VLESS protocol implementation with VISION support

pub mod vless_client_handler;
pub mod vless_server_handler;

pub mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_unpad;
mod vless_message_stream;
mod vless_response_stream;
mod vless_util;

/// Trait for authenticating VLESS UUIDs.
///
/// Implement this to support multi-user VLESS servers. The default
/// single-user implementation ([`SingleUserAuthenticator`]) provides
/// backwards-compatible behavior with constant-time comparison.
pub trait VlessAuthenticator: Send + Sync + std::fmt::Debug {
    /// Check if the given 16-byte UUID is authorized.
    /// Returns `true` if the UUID is valid.
    ///
    /// Implementations should use constant-time comparison to prevent timing attacks.
    fn authenticate(&self, uuid: &[u8; 16]) -> bool;
}

/// Single-user authenticator for backwards compatibility.
#[derive(Debug, Clone)]
pub struct SingleUserAuthenticator {
    user_id: Box<[u8]>,
}

impl SingleUserAuthenticator {
    pub fn new(user_id: Box<[u8]>) -> Self {
        Self { user_id }
    }
}

impl VlessAuthenticator for SingleUserAuthenticator {
    fn authenticate(&self, uuid: &[u8; 16]) -> bool {
        use subtle::ConstantTimeEq;
        self.user_id.ct_eq(uuid.as_slice()).unwrap_u8() == 1
    }
}
