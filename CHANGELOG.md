# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project follows Semantic Versioning.

## [Unreleased]

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