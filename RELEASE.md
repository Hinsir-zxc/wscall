# WSCALL Release Guide

This workspace publishes a crate family with dependency ordering:

1. `wscall-protocol`
2. `wscall-server`
3. `wscall-client`
4. `wscall`

## Pre-release checks

Run the standard quality gates from the workspace root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
```

Validate the protocol crate package first:

```bash
cargo package -p wscall-protocol
```

Update release-facing documents before publishing:

1. Move relevant items from `Unreleased` to the target version in `CHANGELOG.md`.
2. Confirm `README.md` still reflects the current examples and feature flags.
3. Confirm the version number is aligned across the workspace.

## First release caveat

For the first release, `cargo package` for `wscall-server`, `wscall-client`, and `wscall`
cannot fully verify until their lower-level dependencies are already available on crates.io.

That means:

1. Publish `wscall-protocol` first.
2. Wait for crates.io index propagation.
3. Then run `cargo package -p wscall-server` and publish it.
4. Repeat for `wscall-client`.
5. Finally package and publish `wscall`.

## Suggested command sequence

```bash
cargo publish -p wscall-protocol
# wait for crates.io index update

cargo package -p wscall-server
cargo publish -p wscall-server
# wait for crates.io index update

cargo package -p wscall-client
cargo publish -p wscall-client
# wait for crates.io index update

cargo package -p wscall
cargo publish -p wscall
```

## Release preflight checklist

Run through this list before the first `cargo publish`:

1. Working tree is clean or intentionally dirty for a local dry run.
2. `CHANGELOG.md` includes the target version notes.
3. `README.md` quick-start commands still work.
4. Workspace quality gates pass.
5. `wscall-protocol` packages successfully.
6. The crates.io names you intend to publish are still available.

## Post-release checklist

After publishing the full crate family:

1. Verify the docs.rs pages build for all four crates.
2. Tag the release in git if you use version tags.
3. Add a new empty `Unreleased` section to `CHANGELOG.md` if needed.
4. Re-run the quick-start example against the published dependency versions in a separate scratch project.

## Before the public release

Make sure each crate manifest has final values for:

1. `repository`
2. `homepage`
3. `documentation` if it changes from the docs.rs default
4. any additional `include` or `exclude` rules if you want tighter package contents

Current configured repository:

```text
https://github.com/Hinsir-zxc/wscall
```