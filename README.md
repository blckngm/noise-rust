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

## Crypto Primitives

Wrappers for _ring_, sodiumoxide and rust-crypto are implemented,
providing the crypto primitives needed by `noise-protocol`.

Not all primitives are supported by all libraries. The following
table shows which primitives each wrapper supports:

|             | X25519 | AES-256-GCM | Chacha20-Poly1305 | SHA-256 | SHA-512 | BLAKE2s | BLAKE2b |
|-------------|:------:|:-----------:|:-----------------:|:-------:|:-------:|:-------:|:-------:|
| _ring_      |        | ✔           | ✔                 | ✔       | ✔       |         |         |
| sodiumoxide | ✔      |             |                   | ✔       | ✔       |         |         |
| rust-crypto | ✔      |             |                   | ✔       | ✔       | ✔       | ✔       |

You can also plug in other implementations by implementing the `DH`,
`Cipher` or `Hash` traits.
