//! Reusable WSCALL server framework.
//!
//! This crate exposes `WscallServer` plus request and event context types,
//! validation helpers, rate limiting, and transport-facing attachment models.

pub mod rate_limiter;
mod server_runtime;
mod server_types;
pub mod validation;

/// Main server type used to register routes, filters, and event handlers.
pub use server_runtime::WscallServer;
pub use server_types::{
    ApiContext, ApiError, AuthContext, AuthOutput, EventContext, ExceptionContext,
    ServerConnectionContext, ServerDisconnectContext, ServerError, ServerHandle, ValidateParams,
};
/// Shared attachment model used by API calls and events.
pub use wscall_protocol::FileAttachment;

/// Re-export rate limiter types for convenience.
pub use rate_limiter::{RateLimitConfig, RateLimiter};
