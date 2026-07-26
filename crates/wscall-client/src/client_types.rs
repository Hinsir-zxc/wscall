use std::time::Duration;

use serde_json::{Map, Value};
use thiserror::Error;
use wscall_protocol::{ErrorPayload, FileAttachment, PacketEnvelope, ProtocolError};

pub(crate) enum ClientOutbound {
    Packet(PacketEnvelope),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
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
}
