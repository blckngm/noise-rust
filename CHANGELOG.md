# noise-protocol 0.1.2

* Support `Vec` based APIs in no-std via the `alloc` crate. (#19)

# noise-rust-crypto 0.2.1

* Support for no-std. (#16, #18)

# noise-rust-crypto 0.2.0

* Use x25519-dalek and RustCrypto crates instead of rust-crypto.

* There is a feature for each primitive, you can pick exactly what you need.

# noise-protocol 0.1.1

* Update dependency arrayvec to 0.5

# noise-sodiumoxide 0.1.1

* Add `Eq` and `PartialEq` implementations.

# 0.1.0

## `noise-protocol`

No API change.

## `noise-sodiumoxide`

* Update to use sodiumoxide 0.2.

* Add wrapper for AES-256-GCM.

* Fix alignment of Blake2b state.

## `noise-ring`

Removed.

## `noise-rust-crypto`

No API change.

* Update to use rand 0.6.

* No longer depends on byteorder.
