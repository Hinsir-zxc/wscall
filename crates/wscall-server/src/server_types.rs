use std::net::SocketAddr;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::{RwLock, mpsc};
use validator::Validate;
use wscall_protocol::{
    EncryptionKind, ErrorPayload, FileAttachment, PacketEnvelope, ProtocolError,
};

use crate::validation;

pub(crate) enum ServerOutbound {
    Packet(PacketEnvelope),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

pub(crate) struct ServerState {
    pub clients: RwLock<std::collections::HashMap<String, mpsc::Sender<ServerOutbound>>>,
}

/// Handle that can be cloned into request and event handlers for server push operations.
#[derive(Clone)]
pub struct ServerHandle {
    pub(crate) state: Arc<ServerState>,
    pub(crate) default_encryption: EncryptionKind,
}

/// Request context passed to API route handlers.
#[derive(Clone)]
pub struct ApiContext {
    pub(crate) connection_id: String,
    pub(crate) peer_addr: Option<SocketAddr>,
    pub(crate) request_id: String,
    pub(crate) route: String,
    pub(crate) params: Value,
    pub(crate) attachments: Vec<FileAttachment>,
    pub(crate) metadata: Value,
    pub(crate) server: ServerHandle,
}

/// Trait for custom parameter validation after JSON binding.
pub trait ValidateParams {
    fn validate(&self) -> Result<(), ApiError>;
}

impl ApiContext {
    /// Returns the logical connection id for the current client.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the peer socket address when available.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Returns the peer IP as a string when available.
    pub fn peer_ip(&self) -> Option<String> {
        self.peer_addr.map(|addr| addr.ip().to_string())
    }

    /// Returns the request correlation id.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the matched route name.
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Returns the raw JSON params payload.
    pub fn params(&self) -> &Value {
        &self.params
    }

    /// Looks up a single parameter by key.
    pub fn param(&self, key: &str) -> Option<&Value> {
        self.params.as_object()?.get(key)
    }

    /// Looks up a required parameter or returns a bad request error.
    pub fn require_param(&self, key: &str) -> Result<&Value, ApiError> {
        self.param(key)
            .ok_or_else(|| ApiError::bad_request(format!("missing required param: {key}")))
    }

    /// Binds the raw params payload into a strongly typed value.
    pub fn bind<T>(&self) -> Result<T, ApiError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(self.params.clone())
            .map_err(|source| ApiError::bad_request(format!("invalid params: {source}")))
    }

    /// Binds params and runs `ValidateParams` on the result.
    pub fn bind_and_validate<T>(&self) -> Result<T, ApiError>
    where
        T: DeserializeOwned + ValidateParams,
    {
        let params: T = self.bind()?;
        params.validate()?;
        Ok(params)
    }

    /// Binds params and runs `validator::Validate` on the result.
    pub fn bind_validated<T>(&self) -> Result<T, ApiError>
    where
        T: DeserializeOwned + Validate,
    {
        let params: T = self.bind()?;
        params.validate().map_err(|source| {
            ApiError::bad_request("params validation failed").with_details(json!({
                "validation_errors": validation::errors_to_details(&source),
            }))
        })?;
        Ok(params)
    }

    /// Returns all attachments that accompanied the request.
    pub fn attachments(&self) -> &[FileAttachment] {
        &self.attachments
    }

    /// Returns the raw metadata payload.
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Returns a server handle for outbound event operations.
    pub fn server(&self) -> &ServerHandle {
        &self.server
    }

    /// Returns a simplified JSON view of incoming attachments.
    pub fn attachment_summaries(&self) -> Vec<Value> {
        self.attachments
            .iter()
            .map(|attachment| {
                json!({
                    "id": attachment.id,
                    "name": attachment.name,
                    "content_type": attachment.content_type,
                    "size": attachment.size,
                })
            })
            .collect()
    }
}

/// Event context passed to event handlers.
#[derive(Clone)]
pub struct EventContext {
    pub(crate) connection_id: String,
    pub(crate) peer_addr: Option<SocketAddr>,
    pub(crate) event_id: String,
    pub(crate) name: String,
    pub(crate) data: Value,
    pub(crate) attachments: Vec<FileAttachment>,
    pub(crate) metadata: Value,
    pub(crate) server: ServerHandle,
}

impl EventContext {
    /// Returns the logical connection id for the current client.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Returns the peer socket address when available.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Returns the peer IP as a string when available.
    pub fn peer_ip(&self) -> Option<String> {
        self.peer_addr.map(|addr| addr.ip().to_string())
    }

    /// Returns the event correlation id.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the event name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the raw JSON event data.
    pub fn data(&self) -> &Value {
        &self.data
    }

    /// Returns attachments that accompanied the event.
    pub fn attachments(&self) -> &[FileAttachment] {
        &self.attachments
    }

    /// Returns the raw metadata payload.
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Returns a server handle for outbound event operations.
    pub fn server(&self) -> &ServerHandle {
        &self.server
    }
}

/// Context passed to the global exception handler.
#[derive(Clone)]
pub struct ExceptionContext {
    pub connection_id: String,
    pub request_id: Option<String>,
    pub target: String,
    pub message_kind: &'static str,
    pub error: ApiError,
}

/// Application-level error returned from handlers.
#[derive(Debug, Clone, Error)]
#[error("{code}: {message}")]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub status: u16,
    pub details: Option<Value>,
}

impl ApiError {
    /// Constructs a 400 bad request error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message, 400)
    }

    /// Constructs a 404 not found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message, 404)
    }

    /// Constructs a 500 internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal_error", message, 500)
    }

    /// Constructs an error with an explicit code and status.
    pub fn new(code: impl Into<String>, message: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
            details: None,
        }
    }

    /// Attaches structured details to the error.
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Converts the error into a transport payload.
    pub fn into_payload(self) -> ErrorPayload {
        ErrorPayload {
            code: self.code,
            message: self.message,
            status: self.status,
            details: self.details,
        }
    }
}

/// Errors produced by the reusable server runtime.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("api error: {0:?}")]
    Api(#[from] ApiError),
    #[error("connection idle timeout: {0}")]
    IdleTimeout(String),
    #[error("outbound queue is full for connection {0}")]
    OutboundQueueFull(String),
}
