# Noise-Rust

[![Crates.io](https://img.shields.io/crates/v/noise-protocol.svg)](https://crates.io/crates/noise-protocol)
[![Docs.rs](https://docs.rs/noise-protocol/badge.svg)](https://docs.rs/noise-protocol)
[![Build Status](https://travis-ci.org/sopium/noise-rust.svg?branch=master)](https://travis-ci.org/sopium/noise-rust)

Implementation of the [Noise Protocol
Framework](http://noiseprotocol.org) in Rust. A continuation of
trevp's [screech](https://github.com/trevp/screech).

## Status

Protocol revision: 31.

All basic patterns and `XXfallback` are implemented. Vectors from
`noise-c` and `cacophony` are successfully verified.

## Crates

This repository contains several crates. The `noise-protocol` crate
contains the abstract implementation of the protocol
framework. Several sibling crates, namely `noise-sodiumoxide`,
`noise-ring` and `noise-rust-crypto`, provide concrete implementations
of the needed crypto primitives. They are wrappers around
`sodiumoxide`, _ring_ and `rust-crypto`, respectively.

The following table shows what primitives each of these crates
supports:

|             | X25519 | AES-256-GCM | Chacha20-Poly1305 | SHA-256 | SHA-512 | BLAKE2s | BLAKE2b |
|-------------|:------:|:-----------:|:-----------------:|:-------:|:-------:|:-------:|:-------:|
| _ring_      |        | ✔           | ✔                 | ✔       | ✔       |         |         |
| sodiumoxide | ✔      |             |                   | ✔       | ✔       |         | ✔       |
| rust-crypto | ✔      | ✔           | ✔                 | ✔       | ✔       | ✔       | ✔       |

You can also plug in other primitive implementations by implementing the `DH`,
`Cipher` and `Hash` traits.

## `no_std` usage

The `noise-protocol` crate supports `no_std`, if default features are
disabled.

The `noise-ring` crate supports `no_std`.
