# Noise-Rust

[![Crates.io](https://img.shields.io/crates/v/noise-protocol.svg)](https://crates.io/crates/noise-protocol)
[![Docs.rs](https://docs.rs/noise-protocol/badge.svg)](https://docs.rs/noise-protocol)

Implementation of the [Noise Protocol
Framework](http://noiseprotocol.org) in Rust. A continuation of
trevp's [screech](https://github.com/trevp/screech).

## Status

All basic patterns are implemented. Vectors from noise-c and cacophony
are passed.

Please test and review.

The API is not considered stable yet, and may still change
non-trivially.

And perhaps don't use for security critical purposes (yet)!

## Crypto wrappers

The most notable Rust crypto libraries are probably _ring_,
`rust-crypto` and `sodiumoxide`. But there is no clear winner among
them. So wrappers for different libraries are provided in different
crates.

|             | X25519 | AES-256-GCM | Chacha20-Poly1305 | SHA-256 | SHA-512 | BLAKE2s | BLAKE2b |
|-------------|:------:|:-----------:|:-----------------:|:-------:|:-------:|:-------:|:-------:|
| ring        |        | ✔           | ✔                 | ✔       | ✔       |         |         |
| sodiumoxide | ✔      |             |                   | ✔       | ✔       |         |         |
| rust-crypto | ✔      |             |                   | ✔       | ✔       | ✔       | ✔       |

You can also plug in other implementations of various primitives by
implementing the `DH`, `Cipher` or `Hash` traits.
