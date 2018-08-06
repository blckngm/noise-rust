//! Rust implementation of the [Noise Protocol
//! Framework](http://www.noiseprotocol.org/).
//!
//! Typically, you use `HandshakeState::new()` or
//! `HandshakeStateBuilder` to initialize a `HandshakeState`, then
//! call `write_message` and `read_message` to complete the
//! handshake. Once the handshake is `completed`, you call
//! `get_ciphers` to get ciphers that you can use to
//! encrypt/decrypt further messages.
//!
//! This crate only contains an abstract implementation of the
//! protocol. Concrete implementations of the crypo primitives,
//! wrapping around some popular libraries, are provided in sibling
//! crates, e.g., `noise-ring`, `noise-sodiumoxide` and
//! `noise-rust-crypto`.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "use_std"), no_std)]

mod cipherstate;
mod handshakepattern;
mod handshakestate;
mod symmetricstate;
mod traits;

pub use cipherstate::CipherState;
pub use traits::{Cipher, Hash, U8Array, DH};

/// Handshake patterns.
pub mod patterns {
    pub use handshakepattern::*;
}

pub use handshakestate::{HandshakeState, HandshakeStateBuilder};
