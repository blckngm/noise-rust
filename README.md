# Noise-Rust

Implementation of the [Noise Protocol
Framework](http://noiseprotocol.org) in Rust.

Uses [rust-crypto](https://github.com/DaGenix/rust-crypto) but has pluggable
support for other crypto libraries.

Based on trevp's [screech](https://github.com/trevp/screech), but
uses more idiomatic Rust, e.g.:
* Uses `Option` instead of `has_something`,
* Uses a more straightforward ownership model,
* Uses `Vec`,
* Static dispatching.
