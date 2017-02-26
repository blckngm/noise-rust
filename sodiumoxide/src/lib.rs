extern crate noise_protocol as noise;
extern crate sodiumoxide;

// TODO Add AEADs, after
// [https://github.com/dnaq/sodiumoxide/pull/149] is merged.

// TODO BLAKE2b. After sodiumoxide supports it.
// [https://github.com/dnaq/sodiumoxide/issues/101]

// TODO Use stream hasher, after this is fixed:
// [https://github.com/dnaq/sodiumoxide/issues/119]

use noise::*;
use sodiumoxide::crypto::hash::{sha256, sha512};
use sodiumoxide::crypto::scalarmult::curve25519;

pub enum X25519 {}

#[derive(Default)]
pub struct Sha256 {
    buf: Vec<u8>,
}

#[derive(Default)]
pub struct Sha512 {
    buf: Vec<u8>,
}

impl DH for X25519 {
    type Key = [u8; 32];
    type Pubkey = [u8; 32];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "25519"
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        let s = curve25519::Scalar(*k);
        curve25519::scalarmult_base(&s).0
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        let s = curve25519::Scalar(*k);
        let pk = curve25519::GroupElement(*pk);
        // Libsodium returns error when DH result is all-zero, but noise explicitly permits that.
        // See section 9.1 of the spec:
        // http://www.noiseprotocol.org/noise.html#dummy-static-public-keys
        curve25519::scalarmult(&s, &pk).map(|x| x.0).unwrap_or([0u8; 32])
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn result(&mut self) -> Self::Output {
        sha256::hash(&self.buf).0
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn result(&mut self) -> Self::Output {
        sha512::hash(&self.buf).0
    }
}
