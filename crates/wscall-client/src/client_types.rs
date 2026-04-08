use serde_json::Value;
use thiserror::Error;
use wscall_protocol::{ErrorPayload, FileAttachment, PacketEnvelope, ProtocolError};

pub(crate) enum ClientOutbound {
    Packet(PacketEnvelope),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// Server-originated event delivered to a registered client event handler.
#[derive(Clone)]
pub struct EventMessage {
    /// Event correlation id.
    pub event_id: String,
    /// Event name.
    pub name: String,
    /// Raw JSON event data.
    pub data: Value,
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
