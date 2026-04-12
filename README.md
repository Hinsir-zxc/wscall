# wscall

WSCALL is a lightweight WebSocket API framework with a custom binary frame protocol, a reusable Rust server crate, a reusable Rust client crate, and a facade crate for consumers that prefer a single dependency.

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

## Use As Crates

Depend on only what you need:

```toml
[dependencies]
wscall-server = "0.1"
wscall-client = "0.1"
```

Or use the facade crate:

```toml
[dependencies]
wscall = { version = "0.1", features = ["full"] }
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

Client reconnect behavior:

1. Unexpected disconnects trigger automatic reconnect attempts.
2. The first retry waits 3 seconds.
3. Each later retry increases the delay by 1 second.
4. The retry delay is capped at 30 seconds.
5. Calling `close()` stops reconnect attempts.

Runnable end-to-end quick start:

```bash
cargo run -p wscall --example quick_start --features full
```

## Run The Demos

Start the demo server:

```bash
cargo run -p wscall --example demo_server --features server
```

In another terminal, run the demo client:

```bash
cargo run -p wscall --example demo_client --features client
```

The demos exercise:

1. `system.echo` API.
2. `files.inspect` API with inline attachment.
3. `chat.message` event emit and broadcast.
4. `chat.history` API query.
5. End-to-end ChaCha20 frame encryption using the demo key wired in both examples.

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
3. Run `cargo package` for `wscall-protocol` to validate the root dependency crate.
4. Publish in dependency order: `wscall-protocol`, `wscall-server`, `wscall-client`, then `wscall`.
5. After each publish, wait for the crates.io index to catch up before packaging or publishing the next dependent crate.

For the first release of this crate family, dependent crates such as `wscall-server` and `wscall-client` cannot complete a full standalone `cargo package` verification until `wscall-protocol` is already available on crates.io.

See `RELEASE.md` for a release sequence that matches this dependency chain.

Version history is tracked in `CHANGELOG.md`.

## Current Constraints

1. `ChaCha20` and `AES256-GCM` are implemented in `FrameCodec`; the demos still default to `ChaCha20`.
2. Attachments are inline Base64 and suited to small files.
3. Large-file chunking is not part of the current core protocol.
4. The published crate and code identifiers have been renamed to `wscall`.
