extern crate crypto;
extern crate rand;
extern crate noise_protocol as noise;

use self::crypto::{blake2b, blake2s, sha2};
use self::crypto::curve25519::{curve25519, curve25519_base};
use self::crypto::digest::Digest;
use self::rand::{OsRng, Rng};
use noise::*;

pub enum X25519 {}

pub struct Sha256 {
    hasher: sha2::Sha256,
}

pub struct Sha512 {
    hasher: sha2::Sha512,
}

pub struct Blake2b {
    hasher: blake2b::Blake2b,
}

pub struct Blake2s {
    hasher: blake2s::Blake2s,
}

impl DH for X25519 {
    type Key = [u8; 32];
    type Pubkey = [u8; 32];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        let mut k = [0u8; 32];

        OsRng::new().unwrap().fill_bytes(&mut k);

        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        curve25519_base(k.as_slice())
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        curve25519(k.as_slice(), pk.as_slice())
    }
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256 { hasher: sha2::Sha256::new() }
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        self.hasher.result(&mut out);
        out
    }
}

impl Default for Sha512 {
    fn default() -> Sha512 {
        Sha512 { hasher: sha2::Sha512::new() }
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        self.hasher.result(&mut out);
        out
    }
}

impl Default for Blake2b {
    fn default() -> Blake2b {
        Blake2b { hasher: blake2b::Blake2b::new(64) }
    }
}

impl Hash for Blake2b {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2b"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        self.hasher.result(&mut out);
        out
    }
}

impl Default for Blake2s {
    fn default() -> Blake2s {
        Blake2s { hasher: blake2s::Blake2s::new(32) }
    }
}

impl Hash for Blake2s {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "BLAKE2s"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        self.hasher.result(&mut out);
        out
    }
}
