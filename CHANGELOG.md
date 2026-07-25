# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project follows Semantic Versioning.

## [Unreleased]

## [0.2.0] - 2026-07-25

### Breaking Changes

1. `PacketBody::ApiRequest.request_id` and `PacketBody::ApiResponse.request_id` changed from `String` to `u64`.
2. `PacketBody::EventEmit.event_id` and `PacketBody::EventAck.event_id` changed from `String` to `u64`.
3. `PacketBody::EventEmit` gained a new `storage_id: Option<u64>` field.
4. `ApiContext::request_id()` now returns `u64` instead of `&str`.
5. `EventContext::event_id()` now returns `u64` instead of `&str`.
6. `ExceptionContext.request_id` changed from `Option<String>` to `Option<u64>`.
7. `EventMessage.event_id` changed from `String` to `u64`.
8. `wscall-client` no longer depends on the `uuid` crate.

### Added

1. Compact JSON wire format with single-letter keys and numeric `k` discriminator (`0`=ApiRequest, `1`=EventEmit, `2`=ApiResponse, `3`=EventAck), reducing per-frame overhead.
2. Per-connection `AtomicU64` counters for `request_id`/`event_id`, serialized as JSON numbers (1–6 bytes) instead of 26-byte UUIDv7 strings.
3. Optional `si` (Storage ID) field on `EventEmit` for server-pushed persisted events (e.g. chat messages stored in a database).
4. `ServerHandle::broadcast_persisted_event(name, data, attachments, storage_id)` for broadcasting events with a storage ID.
5. `ServerHandle::send_persisted_event_to(connection_id, name, data, attachments, storage_id)` for targeted push with a storage ID.
6. `EventContext::storage_id()` accessor on the server side.
7. `EventMessage.storage_id` field on the client side.
8. `WscallClient::connect_with_auto_reconnect(url, auto_reconnect)` for explicit control over reconnection behavior.
9. `auto_reconnect` parameter (default `true`) governing whether the client supervisor retries after unexpected disconnects.
10. `framework-instruction.md` comprehensive framework documentation covering protocol, server, client, and performance model.

### Changed

1. `connection_id` now uses UUIDv7 (time-ordered) instead of UUIDv4, improving index locality.
2. Client reconnect strategy upgraded from linear (+1s per attempt) to exponential backoff (3s → 6s → 12s …, cap 30s) with random sub-second jitter to avoid thundering-herd reconnect storms.
3. Server request/event handling is now fully concurrent: each inbound API request or event spawns an independent `tokio::spawn` task with a per-connection semaphore (`max_in_flight`, default 64), eliminating head-of-line blocking.
4. `broadcast_event` encodes the frame exactly once and shares it as `Bytes` across all recipients (zero-copy broadcast).
5. All outbound frames are pre-encoded at dispatch time; the writer task only ships bytes.
6. Client pending map replaced `Mutex<HashMap>` with lock-free `DashMap<u64, PendingSender>`.
7. Client writer handle replaced `RwLock<Option<Sender>>` with `ArcSwapOption` for lockless reads.
8. Client event handlers now run concurrently via `join_all` instead of serially.
9. Protocol codec caches cipher instances (`Arc<Aes256Gcm>` / `Arc<ChaCha20Poly1305>`) to avoid repeated key schedules.
10. Frame decode borrows the plaintext payload slice directly (`Cow`) instead of cloning.
11. Server connection table uses `DashMap` for lock-free concurrent reads during broadcast.
12. Server sets `TCP_NODELAY` on accept for low-latency small-frame RPC.
13. Server supports `with_max_connections(n)` to cap concurrent connections with natural backpressure.
14. Hot-path logging migrated from `println!` to `tracing` to avoid stdout lock contention.

### Removed

1. `uuid` dependency removed from `wscall-client` (no longer needed after counter-based IDs).

## [0.1.1] - 2026-04-12

### Added

1. Explicit client lifecycle callbacks with `on_connected` and `on_disconnected`.
2. Explicit server lifecycle callbacks with `on_connected` and `on_disconnected`.
3. Integration tests covering lifecycle notifications and client reconnection recovery.

### Changed

1. Client connections now automatically reconnect after unexpected disconnects.
2. Reconnect retry delay now starts at 3 seconds, increases by 1 second per attempt, and caps at 30 seconds.
3. README, release guide, and crate usage examples now document the lifecycle APIs and `0.1.1` installation versions.

## [0.1.0] - 2026-04-09

### Added

1. Initial public WSCALL workspace release.
2. Cargo workspace with `wscall-protocol`, `wscall-server`, `wscall-client`, and facade crate `wscall`.
3. Shared protocol crate for frame codec, encryption, packet envelope, and attachment model.
4. Protocol support for plaintext, ChaCha20-Poly1305, and AES256-GCM frame transport.
5. API request-response and event emit-ack message flows.
6. Inline Base64 attachment transport with JSON file references.
7. Reusable server framework with routes, filters, validation helpers, exception mapping, and event broadcasting.
8. Reusable client SDK with request correlation, event acknowledgement handling, and event subscriptions.
9. Facade crate examples for demo server, demo client, and end-to-end quick start.
10. CI workflow for formatting, clippy, and tests.
11. Release documentation and publish-order guidance for the crate family.