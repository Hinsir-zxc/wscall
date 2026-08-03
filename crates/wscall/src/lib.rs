//! WSCALL facade crate.
//!
//! This crate re-exports the shared protocol layer and, via feature flags,
//! the reusable server and client implementations.
//!
//! Common usage:
//!
//! ```toml
//! [dependencies]
//! wscall = { version = "0.6.0", features = ["full"] }
//! ```
//!
//! Use the `server` feature for `WscallServer`, the `client` feature for
//! `WscallClient`, or `full` to enable both.

/// Shared protocol types and frame codec.
pub mod protocol {
    pub use wscall_protocol::*;
}

pub use wscall_protocol::{
    ECDH_DOMAIN_TAG, ECDH_KEY_LEN, EcdhKeypair, EncryptionKind, ErrorPayload, FileAttachment,
    FrameCodec, MessageType, PacketBody, PacketEnvelope, ProtocolError, derive_session_key,
    parse_peer_public,
};

#[cfg(feature = "server")]
/// Server-side exports.
pub mod server {
    pub use wscall_server::*;
}

#[cfg(feature = "client")]
/// Client-side exports.
pub mod client {
    pub use wscall_client::*;
}

#[cfg(feature = "server")]
pub use wscall_server::{
    ApiContext, ApiError, AuthContext, AuthOutput, EventContext, ExceptionContext, RateLimitConfig,
    RateLimiter, ServerConnectionContext, ServerDisconnectContext, ServerError, ServerHandle,
    ValidateParams, WscallServer, rate_limiter, validation,
};

#[cfg(feature = "client")]
pub use wscall_client::{
    ClientConnectionEvent, ClientDisconnectEvent, ClientError, EventMessage, WscallClient,
    WscallClientConfig,
};
