# wscall

WSCALL is a lightweight WebSocket API framework with a custom binary frame protocol, a reusable Rust server crate, a reusable Rust client crate, a JavaScript client SDK, and a facade crate for consumers that prefer a single dependency.

## When To Use WSCALL

WSCALL targets **real-time, bidirectional, connection-oriented** communication where a single long-lived WebSocket carries both request/response RPC and server-pushed events.

**Ideal project profiles:**

- **Real-time dashboards & monitoring** — server pushes metric/state updates over the same connection that the client uses for queries; no polling, no separate subscription transport.
- **Chat / collaboration backends** — message delivery, typing indicators, presence broadcasts, and file sharing all flow through one protocol with built-in event ACK.
- **IoT & device management** — persistent connections with heartbeat keep-alive, binary-efficient framing, and per-connection encryption suit constrained or mobile networks.
- **Game servers & live sessions** — low-latency bidirectional messaging with concurrent in-flight requests and zero-copy broadcast to many recipients.
- **Internal micro-service RPC** — teams that want typed routes, validation, and exception mapping without pulling in a heavy IDL/codegen toolchain.
- **Browser ↔ backend APIs** — the companion JS SDK (`wscall-client-js`) runs in both Node.js and browsers, making WSCALL a single-protocol choice for full-stack TypeScript/Rust architectures.

**You probably want WSCALL when:**

1. You need server push *and* client RPC on the same connection.
2. You value a compact binary wire format over human-readable HTTP/JSON.
3. You want built-in encryption (ChaCha20/AES-256-GCM/ECDH) without TLS termination complexity.
4. You prefer “routes + filters + events” framework ergonomics over raw WebSocket handling.
5. You need automatic reconnection with failover across multiple server nodes.

## Comparison With Traditional RPC Frameworks

| Dimension | WSCALL | gRPC | JSON-RPC over HTTP | REST |
|-----------|--------|------|--------------------|------|
| Transport | WebSocket (persistent, bidirectional) | HTTP/2 (streaming) | HTTP (request/response) | HTTP (request/response) |
| Per-message overhead | 5-byte frame header + compact JSON (single-letter keys, numeric IDs); attachments as raw binary (zero Base64 tax) | 5-byte gRPC frame + HTTP/2 HEADERS per stream; Protobuf varint fields | Full HTTP headers per request (~200–500 B) + verbose JSON keys (`"jsonrpc"`, `"method"`, `"params"`) | Full HTTP headers per request + verbose JSON; file uploads need multipart or Base64 |
| Server push | Native event broadcast & targeted push | Server streaming (per-call) | Not built-in | Not built-in (needs SSE/WS) |
| Wire format | Compact binary frame + JSON envelope | Protobuf (IDL-required) | JSON text | JSON text |
| Schema / IDL | None required (dynamic JSON params) | `.proto` + codegen | None | OpenAPI (optional) |
| Encryption | Built-in ChaCha20 / AES-256-GCM / ECDH at frame level | TLS (transport level) | TLS | TLS |
| Connection model | Long-lived, heartbeat keep-alive, auto-reconnect | Per-call or long-lived streams | Stateless per-request | Stateless per-request |
| Bidirectionality | Full-duplex on a single connection | Full-duplex via streams | Client-initiated only | Client-initiated only |
| Browser support | Native (WebSocket API + JS SDK) | Requires gRPC-Web proxy | Yes | Yes |
| Setup complexity | Low (no codegen, no proxy) | Medium (protoc, codegen, sometimes Envoy) | Low | Low |
| Best fit | Real-time bidirectional apps | High-throughput polyglot micro-services | Simple remote procedure calls | CRUD resource APIs |

**Key differentiators:**

1. **Zero-codegen developer experience** — define a route with a closure; no `.proto` files, no build-step code generation. Typed params are opt-in via `typed_route` / `validated_route`.
2. **Events as a first-class citizen** — `broadcast_event` / `send_event_to` / `on_event` / event ACK are protocol-level primitives, not an afterthought layered on top of streaming.
3. **Frame-level encryption without TLS** — useful for intranet deployments, WebSocket tunnels through plain proxies, or scenarios where TLS termination is impractical.
4. **Single dependency, small footprint** — the facade crate `wscall` with `features = ["full"]` pulls in the entire framework; no sidecar proxies, no external schema registry.
5. **Rust + JavaScript dual SDK** — the same binary protocol serves Rust backends and browser/Node.js frontends without a translation layer.

## Workspace Layout

The repository is now organized as a Cargo workspace:

```text
crates/
	wscall-protocol/
	wscall-server/
	wscall-client/
	wscall/
```

Each crate has a clear responsibility:

1. `wscall-protocol`: shared frame codec, envelope types, file attachment model, and protocol errors.
2. `wscall-server`: reusable WebSocket server framework with routes, filters, validation, exception mapping, and server push events.
3. `wscall-client`: reusable client SDK with request correlation, event ACK correlation, and server event subscriptions.
4. `wscall`: facade crate that re-exports protocol plus optional server and client APIs behind features.

## Protocol Summary

Each WebSocket binary message is encoded as (protocol v3, 5-byte header):

```text
| frame_len:u32 | message_type:u8 | payload |
```

The encryption mode is a connection-level property (determined by PSK config or ECDH handshake at connection time); it is not carried per-frame.

The `payload` is a binary composite frame:

```text
| meta_len:u32 | JSON envelope bytes | att_count:u8 | [attachment binary sections] |
```

Transport behavior:

1. Plaintext mode stores the composite frame directly in `payload`.
2. `ChaCha20` and `AES256` modes store `12-byte nonce + ciphertext` in `payload`.
3. The whole-frame size limit is configurable via `with_max_frame_bytes` (default `100 MiB`); oversized inbound frames get a `413` (`frame_too_large`) error response without closing the connection.
4. File parameters use `{"$file": "<id>"}` JSON references; attachment payloads travel as raw binary sections (no Base64 overhead).
5. The JSON envelope uses compact single-letter keys and a numeric `k` discriminator to minimize per-frame overhead.
6. `request_id`/`event_id` are per-connection `u64` counters serialized as JSON numbers (1–6 bytes).
7. `connection_id` uses UUIDv7 (time-ordered, generated once per connection).
8. Event `data` (`d`) is always a JSON object; `metadata` (`m`) is optional and omitted when empty.

### Key Agreement Modes

The framework supports two key modes, determined at connection time:

**PSK (Pre-Shared Key)** — all connections share a single `ChaCha20-Poly1305` or `AES-256-GCM` key configured on both sides. Suitable for trusted environments where keys can be pre-distributed.

**ECDH Dynamic Key Agreement** — based on X25519, each connection negotiates a unique 32-byte `ChaCha20-Poly1305` session key via an in-band handshake immediately after the WebSocket upgrade. The session key is never transmitted over the wire. This mode provides forward secrecy and is suitable for zero-trust deployments.

- Server: `WscallServer::new().with_ecdh()`
- Rust client: `WscallClient::connect(url, WscallClientConfig::ecdh())`
- JS client: `WscallClient.connect(url, WscallClientConfig.ecdh())`

The handshake exchanges 32-byte raw public keys as binary WebSocket messages, then derives `SHA-256("wscall-ecdh-v1" || shared_secret)` as the session key.

## Use As Crates

Depend on only what you need:

```toml
[dependencies]
wscall-server = "0.5.1"
wscall-client = "0.5.1"
```

Or use the facade crate:

```toml
[dependencies]
wscall = { version = "0.5.1", features = ["full"] }
```

## Quick Start

Minimal server:

```rust
use serde_json::json;
use wscall::WscallServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut server = WscallServer::new();

	server.route("system.echo", |ctx| async move {
		Ok(json!({
			"route": ctx.route(),
			"params": ctx.params(),
		}))
	});

	server.listen("127.0.0.1:9001").await?;
	Ok(())
}
```

Minimal client:

```rust
use serde_json::json;
use wscall::{WscallClient, WscallClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let client = WscallClient::connect(
		"ws://127.0.0.1:9001/socket",
		WscallClientConfig::plaintext(),
	).await?;
	client
		.on_connected(|event| async move {
			println!("connected: {}", event.url);
		})
		.await;
	client
		.on_disconnected(|event| async move {
			println!("disconnected: {}", event.reason);
		})
		.await;
	let response = client
		.call("system.echo", json!({ "message": "hello" }), Vec::new())
		.await?;

	println!("response: {response}");
	client.close().await?;
	Ok(())
}
```

ECDH client (recommended default, no pre-shared key needed):

```rust
let client = WscallClient::connect(url, WscallClientConfig::ecdh()).await?;
```

Failover across multiple servers:

```rust
let config = WscallClientConfig::ecdh()
    .with_failover_url("ws://backup1:9001/socket")
    .with_failover_url("ws://backup2:9001/socket");
let client = WscallClient::connect("ws://primary:9001/socket", config).await?;
```

Client reconnect behavior:

1. Unexpected disconnects trigger automatic reconnect attempts (controlled by `WscallClientConfig.auto_reconnect`, default `true`).
2. The first retry waits 3 seconds.
3. Each later retry doubles the delay (exponential backoff: 3s → 6s → 12s …).
4. The retry delay is capped at 30 seconds.
5. A random sub-second jitter is added to each retry to avoid thundering-herd reconnect storms.
6. Calling `close()` stops reconnect attempts.
7. Use `WscallClientConfig::default().with_auto_reconnect(false)` to disable automatic reconnection.
8. When `failover_urls` is configured, each reconnect cycle iterates through all URLs (starting from the last successful one) before applying backoff delay.

Runnable end-to-end quick start:

```bash
cargo run -p wscall --example quick_start --features full
```

## Run The Demos

Start the demo server:

```bash
# PSK (ChaCha20) mode
cargo run -p wscall --example demo_server --features server

# ECDH mode
cargo run -p wscall --example demo_server --features server -- --ecdh
```

In another terminal, run the demo client:

```bash
# PSK (ChaCha20) mode
cargo run -p wscall --example demo_client --features client

# ECDH mode
cargo run -p wscall --example demo_client --features client -- --ecdh
```

A JavaScript demo client is also available in the `wscall-client-js` repository:

```bash
# PSK mode
node demo/demo.js

# ECDH mode
node demo/demo.js --ecdh
```

The demos exercise:

1. `system.echo` API.
2. `files.inspect` API with inline attachment.
3. `chat.message` event emit and broadcast.
4. `chat.history` API query.
5. End-to-end ChaCha20 frame encryption using the demo key wired in both examples.
6. ECDH mode (`--ecdh` flag) demonstrates dynamic per-connection key agreement without any pre-shared key.

## Performance Highlights

1. **Concurrent request handling**: each inbound API request/event runs in its own `tokio::spawn` task with a per-connection semaphore (default 64 in-flight), eliminating head-of-line blocking.
2. **Zero-copy broadcast**: `broadcast_event` encodes the frame once and shares it as `Bytes` across all recipients.
3. **Pre-encoded outbound**: all frames are encoded at dispatch time; the writer task only ships bytes.
4. **Lock-free hot paths**: `DashMap` connection table, `ArcSwapOption` writer handle, `DashMap<u64>` pending correlation map.
5. **Cached ciphers**: AES-256-GCM and ChaCha20-Poly1305 key schedules are computed once and shared via `Arc`.
6. **Compact wire format**: single-letter JSON keys + numeric `k` tag + `u64` counters for IDs minimize per-frame byte overhead.
7. **Low latency**: `TCP_NODELAY` on accept, `tracing` instead of `println!` on hot paths.
8. **Forward secrecy via ECDH**: each connection negotiates a unique X25519 session key; reconnects generate fresh keys automatically.
9. **Zero-copy typed routing**: `typed_route` / `validated_route` move params out of the context instead of deep-cloning the JSON tree per request.
10. **Single-buffer codec**: frames are encoded in a single buffer and decoded in a single JSON pass, minimizing per-frame allocations and copies.
11. **Concurrent lifecycle hooks**: server `on_connected` / `on_disconnected` handlers run concurrently and never delay connection setup.

See `framework-instruction.md` for the full architecture and performance model documentation.

## Quality Gates

Recommended checks before publishing or merging:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
```

## Publishing Checklist

Before publishing the crates to crates.io:

1. Confirm the configured `repository` and `homepage` metadata still match the canonical repository.
2. Run the quality gates locally.
3. Update all workspace crate versions and internal dependency pins to the target release version.
4. Run `cargo package` for `wscall-protocol` to validate the root dependency crate.
5. Publish in dependency order: `wscall-protocol`, `wscall-server`, `wscall-client`, then `wscall`.
6. After each publish, wait for the crates.io index to catch up before packaging or publishing the next dependent crate.

For any release that introduces a new unpublished dependency version, downstream crates such as `wscall-server`, `wscall-client`, and `wscall` must still be published in dependency order so crates.io can resolve the freshly published versions.

See `RELEASE.md` for a release sequence that matches this dependency chain.

Version history is tracked in `CHANGELOG.md`.

## Current Constraints

1. `ChaCha20` and `AES256-GCM` are implemented in `FrameCodec`; the demos default to `ChaCha20`.
2. `ECDH` mode uses X25519 via `x25519-dalek` (Rust) and `@noble/curves` (JS); session keys are always `ChaCha20-Poly1305`.
3. Attachments are inline binary sections (protocol v3) suited to small and medium files.
4. Large-file chunking is not part of the current core protocol.
5. The published crate and code identifiers have been renamed to `wscall`.
6. JavaScript client SDK is available at `wscall-client-js`; it supports PSK and ECDH modes.
