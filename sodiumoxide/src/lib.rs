extern crate byteorder;
extern crate libsodium_sys;
extern crate noise_protocol as noise;
extern crate sodiumoxide;

use byteorder::{ByteOrder, LittleEndian};
use libsodium_sys::*;
use noise::*;
use sodiumoxide::crypto::hash::{sha256, sha512};
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::init as sodium_init;
use sodiumoxide::randombytes::randombytes_into;
use sodiumoxide::utils::memzero;
use std::mem::{swap, uninitialized};
use std::ptr::{null, null_mut};

/// Sodiumoxide init.
///
/// This will make some operations potentially faster, and make `genkey` thread safe.
pub fn init() -> Result<(), ()> {
    sodium_init()
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
        &(self.0).0
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut (self.0).0
    }
}

pub struct Sensitive<A: U8Array>(A);

impl<A> Drop for Sensitive<A>
where
    A: U8Array,
{
    fn drop(&mut self) {
        memzero(self.0.as_mut())
    }
}

impl<A> U8Array for Sensitive<A>
where
    A: U8Array,
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

pub enum ChaCha20Poly1305 {}

#[derive(Default)]
pub struct Sha256 {
    state: sha256::State,
}

#[derive(Default)]
pub struct Sha512 {
    state: sha512::State,
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

    /// Returns `Err(())` if DH output is all-zero.
    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Result<Self::Output, ()> {
        let pk = curve25519::GroupElement(*pk);
        curve25519::scalarmult(&k.0, &pk).map(|x| Sensitive(x.0))
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Key = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "ChaChaPoly"
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), plaintext.len() + 16);

        let mut n = [0u8; 12];
        LittleEndian::write_u64(&mut n[4..], nonce);

        unsafe {
            crypto_aead_chacha20poly1305_ietf_encrypt(
                out.as_mut_ptr(),
                null_mut(),
                plaintext.as_ptr(),
                plaintext.len() as u64,
                ad.as_ptr(),
                ad.len() as u64,
                null(),
                n.as_ptr(),
                k.0.as_ptr(),
            );
        }
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert_eq!(out.len() + 16, ciphertext.len());

        let mut n = [0u8; 12];
        LittleEndian::write_u64(&mut n[4..], nonce);

        let ret = unsafe {
            crypto_aead_chacha20poly1305_ietf_decrypt(
                out.as_mut_ptr(),
                null_mut(),
                null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad.as_ptr(),
                ad.len() as u64,
                n.as_ptr(),
                k.0.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut state = sha256::State::new();
        swap(&mut state, &mut self.state);
        Sensitive(state.finalize().0)
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = Sensitive<[u8; 64]>;

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut state = sha512::State::new();
        swap(&mut state, &mut self.state);
        Sensitive(state.finalize().0)
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        unsafe {
            let mut b: Blake2b = uninitialized();
            crypto_generichash_init(b.state.as_mut_ptr() as *mut _, null(), 0, 64);
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
            crypto_generichash_update(
                self.state.as_mut_ptr() as *mut _,
                data.as_ptr(),
                data.len() as u64,
            );
        }
    }

    fn result(&mut self) -> Self::Output {
        unsafe {
            let mut out: Self::Output = uninitialized();
            crypto_generichash_final(
                self.state.as_mut_ptr() as *mut _,
                out.as_mut().as_mut_ptr(),
                64,
            );
            out
        }
    }
}
