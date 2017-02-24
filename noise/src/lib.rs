//! Rust implementation of the [Noise Protocol Framework](http://www.noiseprotocol.org/).
//!
//! Typically, you call `HandshakeState::new()` to initialize a `HandshakeState`, then call
//! `write_message` and `read_message` to complete the handshake. Once the handshake is completed,
//! you call `get_ciphers` to get ciphers that you can use to encryption/decrypt further messages.
//!
//! Supports most crypto algorithms specified in the spec, expect curve448 key exchange. Supports
//! all basic patterns. Also supports pre-shared key.
//!
//! You can use other implementations of the various crypto primitives by implementing the `DH`,
//! `Cipher`, or `Hash` traits.

mod traits;
pub mod rand;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod handshakepattern;
mod error;

pub use cipherstate::CipherState;
pub use error::NoiseError;
pub use traits::{U8Array, RandomGen, DH, Cipher, Hash};

/// Handshake patterns.
pub mod patterns {
    pub use handshakepattern::*;
}

pub use handshakestate::HandshakeState;
