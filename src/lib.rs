mod crypto_types;
mod wrappers;
mod constants;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod handshakepattern;
mod error;

pub use cipherstate::CipherState;
pub use constants::MAXMSGLEN;
pub use crypto_types::{RandomGen, DH, Cipher, Hash};
pub use error::{NoiseError, Result};

pub mod patterns {
    pub use handshakepattern::*;
}

pub use handshakestate::HandshakeState;

pub mod algorithms {
    pub use wrappers::crypto_wrapper::*;
    pub use wrappers::rand_wrapper::RandomOs;
}
