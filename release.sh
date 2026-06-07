#!/bin/sh
cargo test --release && cargo clippy && cargo release patch --no-publish --execute
