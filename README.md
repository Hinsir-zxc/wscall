# wscall

WSCALL is a lightweight WebSocket API framework with a custom binary frame protocol, a reusable Rust server crate, a reusable Rust client crate, a JavaScript client SDK, and a facade crate for consumers that prefer a single dependency.

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

Each WebSocket binary message is encoded as:

```text
| frame_len:u32 | message_type:u8 | encryption:u8 | payload |
```

Transport behavior:

1. Plaintext mode stores JSON directly in `payload`.
2. `ChaCha20` and `AES256` modes store `12-byte nonce + ciphertext` in `payload`.
3. The payload limit is `10 * 1024 * 1024 - 6`, which keeps the full WSCALL frame within `10 MiB`.
4. File parameters use JSON references plus inline Base64 attachments.
5. The JSON envelope uses compact single-letter keys and a numeric `k` discriminator to minimize per-frame overhead.
6. `request_id`/`event_id` are per-connection `u64` counters serialized as JSON numbers (1–6 bytes).
7. `connection_id` uses UUIDv7 (time-ordered, generated once per connection).
8. Events may carry an optional `si` (Storage ID) field for server-pushed persisted messages.

### Key Agreement Modes

The framework supports two key modes, determined at connection time:

**PSK (Pre-Shared Key)** — all connections share a single `ChaCha20-Poly1305` or `AES-256-GCM` key configured on both sides. Suitable for trusted environments where keys can be pre-distributed.

**ECDH Dynamic Key Agreement** — based on X25519, each connection negotiates a unique 32-byte `ChaCha20-Poly1305` session key via an in-band handshake immediately after the WebSocket upgrade. The session key is never transmitted over the wire. This mode provides forward secrecy and is suitable for zero-trust deployments.

- Server: `WscallServer::new().with_ecdh()`
- Rust client: `WscallClient::connect_with_ecdh(url)`
- JS client: `WscallClient.connectWithEcdh(url)`

The handshake exchanges 32-byte raw public keys as binary WebSocket messages, then derives `SHA-256("wscall-ecdh-v1" || shared_secret)` as the session key.

## Use As Crates

Depend on only what you need:

```toml
[dependencies]
wscall-server = "0.2.0"
wscall-client = "0.2.0"
```

Or use the facade crate:

```toml
[dependencies]
wscall = { version = "0.2.0", features = ["full"] }
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
use wscall::WscallClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let client = WscallClient::connect("ws://127.0.0.1:9001/socket").await?;
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

ECDH client (no pre-shared key needed):

```rust
let client = WscallClient::connect_with_ecdh("ws://127.0.0.1:9001/socket").await?;
```

Client reconnect behavior:

1. Unexpected disconnects trigger automatic reconnect attempts (controlled by `auto_reconnect`, default `true`).
2. The first retry waits 3 seconds.
3. Each later retry doubles the delay (exponential backoff: 3s → 6s → 12s …).
4. The retry delay is capped at 30 seconds.
5. A random sub-second jitter is added to each retry to avoid thundering-herd reconnect storms.
6. Calling `close()` stops reconnect attempts.
7. Use `WscallClient::connect_with_auto_reconnect(url, false)` to disable automatic reconnection.

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
3. Attachments are inline Base64 and suited to small files.
4. Large-file chunking is not part of the current core protocol.
5. The published crate and code identifiers have been renamed to `wscall`.
6. JavaScript client SDK is available at `wscall-client-js`; it supports PSK and ECDH modes.
