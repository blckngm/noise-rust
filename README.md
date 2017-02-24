# Noise-Rust

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

You can also plug in other implementations of various primitives by
implementing the `DH`, `Cipher` or `Hash` traits.
