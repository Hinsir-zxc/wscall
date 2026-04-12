//! Reusable WSCALL client SDK.
//!
//! This crate exposes `WscallClient`, event message types, client errors,
//! and the shared attachment model used in requests and events.

mod client_runtime;
mod client_types;

/// Main async client type used to connect to a WSCALL server.
pub use client_runtime::WscallClient;
pub use client_types::{ClientConnectionEvent, ClientDisconnectEvent, ClientError, EventMessage};
/// Shared attachment model used by API calls and events.
pub use wscall_protocol::FileAttachment;
