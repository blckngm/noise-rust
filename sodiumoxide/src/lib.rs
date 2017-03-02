extern crate noise_protocol as noise;
extern crate libsodium_sys;
extern crate sodiumoxide;

// TODO Add AEADs, after
// [https://github.com/dnaq/sodiumoxide/pull/149] is merged.

// TODO Use stream hasher, after this is fixed:
// [https://github.com/dnaq/sodiumoxide/issues/119]

use libsodium_sys::crypto_generichash_blake2b;
use noise::*;
use sodiumoxide::crypto::hash::{sha256, sha512};
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::init as sodium_init;
use sodiumoxide::randombytes::randombytes_into;
use sodiumoxide::utils::memzero;
use std::mem::uninitialized;
use std::ptr::null;

/// Sodiumoxide init.
///
/// This will make some operations potentially faster, and make `genkey` thread safe.
pub fn init() {
    sodium_init();
}

// TODO Just newtype wrap sodiumoxide types. They will zero out memory at Drop.
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl U8Array for SecretKey {
    fn new() -> Self {
        SecretKey([0u8; 32])
    }

    fn new_with(v: u8) -> Self {
        SecretKey([v; 32])
    }

    fn from_slice(s: &[u8]) -> Self {
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        SecretKey(a)
    }

    fn len() -> usize {
        32
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}

pub enum X25519 {}

#[derive(Default)]
pub struct Sha256 {
    buf: Vec<u8>,
}

#[derive(Default)]
pub struct Sha512 {
    buf: Vec<u8>,
}

// It seems `crypto_generichash_blake2b_state` is not really usable...
#[derive(Default)]
pub struct Blake2b {
    buf: Vec<u8>,
}

impl DH for X25519 {
    type Key = SecretKey;
    type Pubkey = [u8; 32];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        let mut k = [0u8; 32];
        randombytes_into(&mut k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        SecretKey(k)
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        let s = curve25519::Scalar(k.0);
        curve25519::scalarmult_base(&s).0
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        let s = curve25519::Scalar(k.0);
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

impl Hash for Blake2b {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2b"
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn result(&mut self) -> Self::Output {
        unsafe {
            let mut out: Self::Output = uninitialized();
            crypto_generichash_blake2b(out.as_mut_ptr(),
                                       64,
                                       self.buf.as_ptr(),
                                       self.buf.len() as u64,
                                       null(),
                                       0);
            out
        }
    }
}
