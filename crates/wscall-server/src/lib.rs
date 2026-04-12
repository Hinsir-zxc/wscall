//! Reusable WSCALL server framework.
//!
//! This crate exposes `WscallServer` plus request and event context types,
//! validation helpers, and transport-facing attachment models.

mod server_runtime;
mod server_types;
pub mod validation;

/// Main server type used to register routes, filters, and event handlers.
pub use server_runtime::WscallServer;
pub use server_types::{
    ApiContext, ApiError, EventContext, ExceptionContext, ServerConnectionContext,
    ServerDisconnectContext, ServerError, ServerHandle, ValidateParams,
};
/// Shared attachment model used by API calls and events.
pub use wscall_protocol::FileAttachment;
