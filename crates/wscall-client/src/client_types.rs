use std::time::Duration;

use serde_json::{Map, Value};
use thiserror::Error;
use wscall_protocol::{
    EncryptionKind, ErrorPayload, FileAttachment, FrameCodec, PacketEnvelope, ProtocolError,
};

pub(crate) enum ClientOutbound {
    Packet(PacketEnvelope),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// Configuration for establishing a [`WscallClient`](crate::WscallClient) connection.
///
/// Bundles all user-tunable connection parameters into a single value type.
/// Use [`WscallClientConfig::default()`] for the recommended secure defaults
/// (ECDH dynamic key agreement + ChaCha20-Poly1305 + auto-reconnect), or
/// construct a custom configuration with the builder-style `with_*` methods.
///
/// # Examples
///
/// ```rust
/// use wscall_client::WscallClientConfig;
///
/// // Default: ECDH + ChaCha20 + auto-reconnect
/// let config = WscallClientConfig::default();
///
/// // Pre-shared ChaCha20 key, no ECDH
/// let config = WscallClientConfig::psk_chacha20([0x42; 32]);
///
/// // Plaintext (no encryption, useful for development)
/// let config = WscallClientConfig::plaintext();
/// ```
#[derive(Clone, Debug)]
pub struct WscallClientConfig {
    /// Frame codec carrying encryption keys and size limits.
    pub codec: FrameCodec,
    /// Encryption mode applied to outbound frames.
    pub default_encryption: EncryptionKind,
    /// Whether the supervisor automatically reconnects after an unexpected
    /// disconnect (exponential backoff + jitter).
    pub auto_reconnect: bool,
    /// Whether to perform an ECDH X25519 handshake on connect. When `true`,
    /// the `codec` field is ignored for key material; a fresh session key is
    /// negotiated per connection.
    pub use_ecdh: bool,
    /// Failover server URLs tried in order when the primary URL (passed to
    /// [`WscallClient::connect`](crate::WscallClient::connect)) is unreachable.
    /// On each connection attempt the client iterates through
    /// `[primary] + failover_urls` starting from the last successfully
    /// connected index, providing automatic failover for multi-node deployments.
    pub failover_urls: Vec<String>,
    /// Optional credential string (e.g. a token) submitted to the server
    /// during the handshake phase. When the server has an `auth_handler`
    /// configured, it validates this credential before the connection is
    /// fully established. Leave as `None` when the server does not require
    /// authentication.
    pub credential: Option<String>,
}

impl Default for WscallClientConfig {
    /// Recommended secure defaults: ECDH dynamic key agreement (ChaCha20-Poly1305)
    /// with automatic reconnection enabled.
    fn default() -> Self {
        Self {
            codec: FrameCodec::plaintext(),
            default_encryption: EncryptionKind::ChaCha20,
            auto_reconnect: true,
            use_ecdh: true,
            failover_urls: Vec::new(),
            credential: None,
        }
    }
}

impl WscallClientConfig {
    /// Creates a configuration with the recommended secure defaults
    /// (identical to [`Default`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: ECDH dynamic key agreement (the default).
    pub fn ecdh() -> Self {
        Self::default()
    }

    /// Convenience: plaintext transport with no encryption.
    /// Suitable for local development and testing only.
    pub fn plaintext() -> Self {
        Self {
            codec: FrameCodec::plaintext(),
            default_encryption: EncryptionKind::None,
            auto_reconnect: true,
            use_ecdh: false,
            failover_urls: Vec::new(),
            credential: None,
        }
    }

    /// Convenience: pre-shared ChaCha20-Poly1305 key (no ECDH handshake).
    pub fn psk_chacha20(key: [u8; 32]) -> Self {
        Self {
            codec: FrameCodec::plaintext().with_chacha20_key(key),
            default_encryption: EncryptionKind::ChaCha20,
            auto_reconnect: true,
            use_ecdh: false,
            failover_urls: Vec::new(),
            credential: None,
        }
    }

    /// Convenience: pre-shared AES-256-GCM key (no ECDH handshake).
    pub fn psk_aes256(key: [u8; 32]) -> Self {
        Self {
            codec: FrameCodec::plaintext().with_aes256_key(key),
            default_encryption: EncryptionKind::Aes256,
            auto_reconnect: true,
            use_ecdh: false,
            failover_urls: Vec::new(),
            credential: None,
        }
    }

    /// Builder: override the frame codec.
    pub fn with_codec(mut self, codec: FrameCodec) -> Self {
        self.codec = codec;
        self
    }

    /// Builder: override the default outbound encryption mode.
    pub fn with_default_encryption(mut self, encryption: EncryptionKind) -> Self {
        self.default_encryption = encryption;
        self
    }

    /// Builder: enable or disable automatic reconnection.
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Builder: enable or disable ECDH dynamic key agreement.
    pub fn with_use_ecdh(mut self, enabled: bool) -> Self {
        self.use_ecdh = enabled;
        self
    }

    /// Builder: append a single failover URL (can be called multiple times).
    ///
    /// When the primary URL is unreachable, the client tries failover URLs
    /// in the order they were added.
    pub fn with_failover_url(mut self, url: impl Into<String>) -> Self {
        self.failover_urls.push(url.into());
        self
    }

    /// Builder: set the full failover URL list (replaces any previously added).
    pub fn with_failover_urls(mut self, urls: Vec<String>) -> Self {
        self.failover_urls = urls;
        self
    }

    /// Builder: set the credential string submitted to the server during the
    /// handshake phase.
    ///
    /// When the server has an `auth_handler` configured, it validates this
    /// credential (e.g. a bearer token) before the connection is fully
    /// established. Authentication failures surface as
    /// [`ClientError::AuthFailed`] from `connect`.
    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }
}

/// Lifecycle payload emitted when the client establishes a websocket session.
#[derive(Clone, Debug)]
pub struct ClientConnectionEvent {
    /// Connected websocket URL.
    pub url: String,
}

/// Lifecycle payload emitted when the client loses its websocket session.
#[derive(Clone, Debug)]
pub struct ClientDisconnectEvent {
    /// Disconnected websocket URL.
    pub url: String,
    /// Human-readable disconnect reason.
    pub reason: String,
    /// Whether the client will keep trying to reconnect.
    pub will_reconnect: bool,
    /// Delay before the next reconnect attempt when reconnect is enabled.
    pub retry_after: Option<Duration>,
}

/// Server-originated event delivered to a registered client event handler.
#[derive(Clone)]
pub struct EventMessage {
    /// Event correlation id (per-connection u64 counter).
    pub event_id: u64,
    /// Event name.
    pub name: String,
    /// Event data object.
    pub data: Map<String, Value>,
    /// Attachments sent with the event.
    pub attachments: Vec<FileAttachment>,
    /// Raw metadata payload.
    pub metadata: Value,
}

/// Errors produced by the reusable WSCALL client.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("client disconnected")]
    Disconnected,
    #[error("connection closed: {0}")]
    ConnectionClosed(String),
    #[error("connection idle timeout")]
    IdleTimeout,
    #[error("request timed out")]
    Timeout,
    #[error("remote error: {0:?}")]
    Remote(ErrorPayload),
    #[error("authentication failed: {0:?}")]
    AuthFailed(ErrorPayload),
}
