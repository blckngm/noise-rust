#!/bin/bash

set -ex

cargo fmt -- --check

cd noise-protocol && cargo check --no-default-features && cd ..

cd noise-rust-crypto
cargo check --no-default-features --features=use-x25519,use-chacha20poly1305,use-blake2
cargo check --no-default-features --features=use-aes-256-gcm,use-chacha20poly1305,use-blake2,use-sha2
cd ..

NOISE_RUST_TEST_IN_PLACE=1 cargo test --all --verbose
