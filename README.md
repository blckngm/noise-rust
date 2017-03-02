# Noise-Rust

[![Crates.io](https://img.shields.io/crates/v/noise-protocol.svg)](https://crates.io/crates/noise-protocol)
[![Docs.rs](https://docs.rs/noise-protocol/badge.svg)](https://docs.rs/noise-protocol)
[![Build Status](https://travis-ci.org/sopium/noise-rust.svg?branch=master)](https://travis-ci.org/sopium/noise-rust)

Implementation of the [Noise Protocol
Framework](http://noiseprotocol.org) in Rust. A continuation of
trevp's [screech](https://github.com/trevp/screech).

## Status

All basic patterns and `XXfallback` are implemented. Vectors from
noise-c and cacophony are passed.

Please test and review.

Perhaps don't use for security critical purposes (yet)!

## Crates

The `noise-protocol` crate contains the abstract implementation of the
protocol framework. Several sibling crates, namely
`noise-sodiumoxide`, `noise-ring` and `noise-rust-crypto`, provide
implementations of the crypto primitives needed by
`noise-protocol`. They are wrappers around `sodiumoxide`, _ring_ and
`rust-crypto`, respectively.

The following table shows what primitives each of these crates
supports:

|             | X25519 | AES-256-GCM | Chacha20-Poly1305 | SHA-256 | SHA-512 | BLAKE2s | BLAKE2b |
|-------------|:------:|:-----------:|:-----------------:|:-------:|:-------:|:-------:|:-------:|
| _ring_      |        | ✔           | ✔                 | ✔       | ✔       |         |         |
| sodiumoxide | ✔      |             |                   | ✔       | ✔       |         | ✔       |
| rust-crypto | ✔      | ✔           | ✔                 | ✔       | ✔       | ✔       | ✔       |

Although `rust-crypto` supports all primitives, it “has not been
thoroughly audited for correctness”, “so any use where security is
important is not recommended at this time”.

And you are not restricted to these libraries. You can easily plug in
other libraries by implementing the `DH`, `Cipher` and `Hash` traits.
