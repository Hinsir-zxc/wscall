# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project follows Semantic Versioning.

## [0.5.1] - 2026-07-28

> **Protocol v3** (wire-format change): the per-frame `encryption` byte has been removed from the frame header. Encryption mode is now a connection-level property determined at connection setup (PSK config or ECDH handshake). Frame header shrinks from 6 bytes to 5 bytes (`frame_len:u32 | message_type:u8`). **0.5.1 nodes cannot interoperate with ≤0.5.0 nodes at the wire level.** The Rust public API signatures are unchanged.

### Changed

1. **Frame header reduced to 5 bytes** — removed the `encryption:u8` byte; the frame layout is now `frame_len:u32 | message_type:u8 | payload`. Every frame saves 1 byte of fixed overhead.
2. **`FrameCodec` gains `wire_encryption` field** — the connection-level encryption mode is stored in the codec instance. `with_chacha20_key()` / `with_aes256_key()` automatically set it. `encode()` and `decode()` use `self.wire_encryption` instead of a per-frame byte.
3. **`FrameCodec::wire_encryption()` accessor** added.
4. JS SDK `FrameCodec`: `encode(body)` no longer accepts an `encryption` parameter; the codec's `wireEncryption` property (set by `withChaCha20Key` / `withAes256Key`) governs encryption. `decode()` returns `{ messageType, body }` (no `encryption` field).
5. Documentation (README, framework-instruction, plan) updated to reference Protocol v3.

### Compatibility

- **Wire protocol**: breaking (v3 ≠ v2 frame offsets). All endpoints (Rust server, Rust client, JS client) must be upgraded together.
- **Rust public API**: non-breaking — `PacketEnvelope.encryption` field retained as metadata; all method signatures unchanged.
- **JS SDK API**: `FrameCodec.encode()` drops the second parameter (internal usage only; `WscallClient` callers unaffected).

## [0.5.0] - 2026-07-27

> **⚠️ BREAKING RELEASE**: This release introduces public API breaking changes (SemVer minor bump under 0.x). The wire protocol is **unchanged** — 0.5.0 nodes interoperate with 0.4.x nodes at the protocol level. However, the Rust public API and the JS SDK API have changed; downstream code must be updated. All four Rust crates must be upgraded **together**. The companion `wscall-client-js` SDK received matching changes.

### Breaking Changes

1. **`FileAttachment.data` is now `Bytes`** — changed from `Vec<u8>` to `bytes::Bytes` (reference-counted immutable buffer). Clone is a cheap refcount bump; `Bytes::slice()` enables zero-copy sub-range access. Manual `Serialize`/`Deserialize` impl (wire format unchanged).
2. **`FrameCodec::decode` accepts `Bytes` by value** — signature changed from `decode(&self, frame: &[u8])` to `decode(&self, frame: Bytes)`. The plaintext path uses `frame.slice(6..)` for zero-copy payload extraction (no allocation); the encrypted path decrypts into a fresh `Bytes`. Aligns with tungstenite 0.30's `Message::Binary(Bytes)`.
3. **`on_event` handler receives `Arc<EventMessage>`** — the event handler signature changed from `Fn(EventMessage)` to `Fn(Arc<EventMessage>)`. Multiple handlers share the same allocation via `Arc::clone` (refcount bump) instead of per-handler deep copies.
4. **Unified `WscallClient::connect(url, config)`** — a new `WscallClientConfig` struct bundles `codec`, `default_encryption`, `auto_reconnect`, and `use_ecdh`. The single `connect(url, config)` entry point replaces the previous six connect variants.
5. **Deprecated legacy connect methods** — `connect(url)`, `connect_with_auto_reconnect`, `connect_with_chacha20`, `connect_with_aes256`, `connect_with_ecdh`, and `connect_with_settings` are all `#[deprecated(since = "0.5.0")]` and forward to the new unified path.

### Added

1. `WscallClientConfig` struct with `Default` (ECDH + ChaCha20 + auto-reconnect), convenience constructors (`ecdh()`, `plaintext()`, `psk_chacha20(key)`, `psk_aes256(key)`), and builder methods (`with_codec`, `with_default_encryption`, `with_auto_reconnect`, `with_use_ecdh`).
2. **Client-side failover** — `WscallClientConfig.failover_urls` field (with `with_failover_url` / `with_failover_urls` builders) accepts backup server URLs. On connect and reconnect the client iterates through `[primary] + failover_urls` starting from the last successfully connected index (sticky failover), providing automatic failover for multi-node deployments without external load balancers.
3. `wscall-protocol` now depends on the `bytes` crate (workspace dependency).
4. `FileAttachment::inline_bytes` accepts `impl Into<Bytes>` for ergonomic construction.
5. JS SDK: `WscallClientConfig` class with static factories (`ecdh()`, `plaintext()`, `pskChaCha20(key)`, `pskAes256(key)`) and builder methods (including `withFailoverUrl` / `withFailoverUrls`); unified `WscallClient.connect(url, config)` entry point with matching failover support.

### Changed

1. Protocol decode path: plaintext frames use `Bytes::slice()` for zero-copy payload access; attachment binary sections use `data.slice(pos..pos+len)` instead of `to_vec()`.
2. Client `WscallClient` struct stores a single `config: WscallClientConfig` field instead of four separate fields.
3. `decode_frame` free function signature updated to accept `Bytes`.

## [0.4.1] - 2026-07-26

A non-breaking performance release. Fully compatible with `0.4.0` — no public API or wire-protocol changes; the four crates interoperate with `0.4.0` nodes and can be upgraded independently. The companion `wscall-client-js` received matching codec optimizations in its own repository.

### Changed

1. **Protocol single-pass deserialization** — `PacketBody::deserialize` parses the JSON object once and moves fields out directly, removing the previous `Value::deserialize` + `serde_json::from_value` double traversal of nested `params` / `data` / `metadata` / `receipt` trees.
2. **Protocol single-buffer frame encoding** — the plaintext path builds the final frame in one buffer (`serde_json::to_writer` straight into the frame with in-place length backpatching), eliminating the intermediate JSON buffer and repeated full-buffer copies; the encrypted path drops the intermediate JSON buffer as well.
3. **Zero-copy typed routes** — `typed_route` / `validated_route` now bind params by moving the `Value` out of the context (`mem::take`) instead of deep-cloning the whole params tree on every request. Public `bind` / `bind_and_validate` / `bind_validated` are unchanged.
4. **Concurrent server lifecycle handlers** — `on_connected` / `on_disconnected` handlers now run concurrently via `join_all`, so a slow handler no longer delays connection establishment or teardown.
5. **Stronger reconnect jitter** — client reconnect jitter now uses OS randomness (`getrandom`) instead of wall-clock nanoseconds, de-correlating clients that reconnect in the same instant.
6. **Spawned client event dispatch** — inbound `EventEmit` packets are handled in a dedicated task so a slow event handler cannot block the read loop; API responses / event acks stay inline.
7. **Static client metadata** — outbound request/event metadata is built once behind a `OnceLock` and cloned thereafter, avoiding repeated JSON object construction per call.

### Added

1. `wscall-client` now depends on `getrandom` (workspace dependency) for reconnect jitter randomness.

## [0.4.0] - 2026-07-27

> **⚠️ BREAKING RELEASE**: This release upgrades the wire protocol to "protocol v2" (binary composite frames) and reworks the on-wire format of event data and attachments. It is **incompatible** with 0.3.0 and earlier: old clients/servers cannot interoperate with 0.4.0 nodes. `wscall`, `wscall-server`, `wscall-client`, and `wscall-protocol` must all be upgraded **together**, and the companion JS SDK must be a `wscall-client-js` build that supports protocol v2. Read the breaking changes below before upgrading.

### Breaking Changes

1. **Protocol v2: binary composite frames** — the frame payload changed from plain JSON text to a composite layout of `meta_len:u32 + JSON bytes + att_count:u8 + raw binary attachment sections`, eliminating Base64 encoding overhead for attachments. The wire format is incompatible with 0.3.0.
2. **Attachments no longer use the JSON `a` field** — attachments travel as raw binary sections within the frame; the `a` key no longer appears in the JSON envelope. Parameters reference attachments via `{"$file": "<id>"}`.
3. **Removed the `si` (storage_id) field** — `PacketBody::EventEmit` drops the `storage_id: Option<u64>` field; the `si` key no longer appears in the JSON envelope.
4. **Event `d` (data) is now strictly a JSON object** — `PacketBody::EventEmit.data` changed from `serde_json::Value` to `Map<String, Value>`: it always serializes as a JSON object and rejects strings and other non-object types on deserialization.
5. **`m` (metadata) is now optional** — the field is omitted from serialization when metadata is empty (`null` or `{}`).
6. **Removed persisted-event push APIs** — `ServerHandle::broadcast_persisted_event` and `ServerHandle::send_persisted_event_to` are gone (their capability is folded into `broadcast_event` / `send_event_to`).
7. **Removed storage_id accessors** — the server-side `EventContext::storage_id()` accessor and the client-side `EventMessage.storage_id` field are removed.
8. **Event push signatures changed** — the `data` parameter of `ServerHandle::broadcast_event` / `send_event_to` and `WscallClient::send_event` changed from `Value` to `Map<String, Value>`; `EventContext::data()` now returns `&Map<String, Value>`.

### Added

1. `FrameCodec` binary composite-frame codec, built via `plaintext()` / `with_chacha20_key()` / `with_aes256_key()` and `with_max_frame_bytes()`.
2. `FileAttachment` type (`inline_text` / `inline_bytes` / `param_ref` / `size`) transmitted as raw binary sections.
3. `MessageType` / `EncryptionKind` enums and the attachment-carrying `PacketEnvelope` / `PacketBody` packet structures.
4. Dynamic frame size limit: `DEFAULT_MAX_FRAME_BYTES` (default 100 MiB), configurable on the server via `WscallServer::with_max_frame_bytes()`.
5. Oversized inbound frames now return a 413 error response frame (`request_id=0`, `code="frame_too_large"`) **without closing the connection**, so subsequent requests still work; the integration test `frame_size_limit.rs` covers this behavior.

### Changed

1. The WebSocket-layer `max_message_size` / `max_frame_size` is set to `max_frame_bytes + 1 MiB` of headroom so oversized frames reach the WSCALL-layer check.
2. Event data `d` is always a JSON object; internal events such as the `system.notice` connection notification now use object payloads.

## [0.3.0] - 2026-07-26

### Added

1. **ECDH dynamic key agreement** — X25519-based per-connection session key negotiation. No pre-shared key required; each connection derives a unique 32-byte ChaCha20-Poly1305 key via `SHA-256("wscall-ecdh-v1" || shared_secret)`.
2. `WscallServer::with_ecdh()` builder to enable ECDH mode on the server.
3. `WscallClient::connect_with_ecdh(url)` for ECDH client connections.
4. `EcdhKeypair` type in `wscall-protocol` for X25519 keypair generation and session key derivation.
5. `derive_session_key(shared_secret)` and `parse_peer_public(bytes)` helper functions in `wscall-protocol`.
6. `ECDH_DOMAIN_TAG` and `ECDH_KEY_LEN` constants in `wscall-protocol`.
7. `ServerOutbound::Packet` variant for per-connection codec encoding in ECDH mode.
8. `ClientEntry` struct in `wscall-server` storing per-connection codec and encryption kind.
9. `ProtocolError::InvalidEcdhPublicKey` and `ProtocolError::EcdhHandshake` error variants.
10. `--ecdh` command-line flag on `demo_server` and `demo_client` examples for ECDH mode.
11. ECDH re-export in the `wscall` facade crate (`EcdhKeypair`, `ECDH_DOMAIN_TAG`, `ECDH_KEY_LEN`, `derive_session_key`, `parse_peer_public`).

### Changed

1. Server connection table now stores `ClientEntry` (sender + optional per-connection codec + encryption) instead of bare `mpsc::Sender`.
2. In ECDH mode, `broadcast_event` and `send_event_to` dispatch `ServerOutbound::Packet` so the writer task encodes with the per-connection session codec.
3. New workspace dependencies: `x25519-dalek` (ECDH) and `sha2` (session key KDF).

### Security

1. ECDH mode provides forward secrecy: each connection uses a fresh X25519 keypair; reconnects generate new session keys automatically.
2. Session keys are never transmitted over the wire — only public keys are exchanged.

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