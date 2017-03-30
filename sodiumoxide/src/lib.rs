extern crate noise_protocol as noise;
extern crate libsodium_sys;
extern crate sodiumoxide;

// TODO Add AEADs, after
// [https://github.com/dnaq/sodiumoxide/pull/149] is merged.

// TODO Use stream hasher, after this is fixed:
// [https://github.com/dnaq/sodiumoxide/issues/119]

use libsodium_sys::*;
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

pub struct X25519Key(curve25519::Scalar);

impl U8Array for X25519Key {
    fn new() -> Self {
        X25519Key(curve25519::Scalar([0u8; 32]))
    }

    fn new_with(v: u8) -> Self {
        X25519Key(curve25519::Scalar([v; 32]))
    }

    fn from_slice(s: &[u8]) -> Self {
        X25519Key(curve25519::Scalar::from_slice(s).unwrap())
    }

    fn len() -> usize {
        32
    }

    fn as_slice(&self) -> &[u8] {
        & (self.0).0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut (self.0).0
    }
}

pub struct Sensitive<A: U8Array>(A);

impl<A> Drop for Sensitive<A>
    where A: U8Array
{
    fn drop(&mut self) {
        memzero(self.0.as_mut())
    }
}

impl<A> U8Array for Sensitive<A>
    where A: U8Array
{
    fn new() -> Self {
        Sensitive(A::new())
    }

    fn new_with(v: u8) -> Self {
        Sensitive(A::new_with(v))
    }

    fn from_slice(s: &[u8]) -> Self {
        Sensitive(A::from_slice(s))
    }

    fn len() -> usize {
        A::len()
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
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

pub struct Blake2b {
    // TODO: 64-byte alignment.
    // crypto_generichash_statebytes() is 384, as of libsodium 1.0.8.
    state: [u8; 384],
}

#[cfg(test)]
#[test]
fn test_blake2b_state_size() {
    assert!(::std::mem::size_of::<Blake2b>() >= unsafe { crypto_generichash_statebytes() });
}

impl DH for X25519 {
    type Key = X25519Key;
    type Pubkey = [u8; 32];
    type Output = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        let mut k = [0u8; 32];
        randombytes_into(&mut k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        X25519Key(curve25519::Scalar(k))
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        curve25519::scalarmult_base(&k.0).0
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        let pk = curve25519::GroupElement(*pk);
        // Libsodium returns error when DH result is all-zero, but noise explicitly permits that.
        // See section 9.1 of the spec:
        // http://www.noiseprotocol.org/noise.html#dummy-static-public-keys
        Sensitive(curve25519::scalarmult(&k.0, &pk).map(|x| x.0).unwrap_or([0u8; 32]))
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn result(&mut self) -> Self::Output {
        Sensitive(sha256::hash(&self.buf).0)
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = Sensitive<[u8; 64]>;

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn result(&mut self) -> Self::Output {
        Sensitive(sha512::hash(&self.buf).0)
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        unsafe {
            let mut b: Blake2b = uninitialized();
            crypto_generichash_init(b.state.as_mut_ptr() as *mut _,
                                    null(), 0,
                                    64);
            b
        }
    }
}

impl Hash for Blake2b {
    type Block = [u8; 128];
    type Output = Sensitive<[u8; 64]>;

    fn name() -> &'static str {
        "BLAKE2b"
    }

    fn input(&mut self, data: &[u8]) {
        unsafe {
            crypto_generichash_update(self.state.as_mut_ptr() as *mut _,
                                      data.as_ptr(),
                                      data.len() as u64);
        }
    }

    fn result(&mut self) -> Self::Output {
        unsafe {
            let mut out: Self::Output = uninitialized();
            crypto_generichash_final(self.state.as_mut_ptr() as *mut _,
                                     out.as_mut().as_mut_ptr(), 64);
            out
        }
    }
}
