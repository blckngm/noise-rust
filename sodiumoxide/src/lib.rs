use libsodium_sys::*;
use noise_protocol::*;
use sodiumoxide::crypto::hash::{sha256, sha512};
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::init as sodium_init;
use sodiumoxide::randombytes::randombytes_into;
use sodiumoxide::utils::memzero;
use std::mem::{swap, MaybeUninit};
use std::ptr::{null, null_mut};

/// Initialize the library. Call the `sodium_init` function.
///
/// `sodium_init()` initializes the library and should be called before any other function provided by Sodium. It is safe to call this function more than once and from different threads -- subsequent calls won't have any effects.
/// After this function returns, all of the other functions provided by Sodium will be thread-safe.
///
/// Libsodium doc: <https://libsodium.gitbook.io/doc/usage>.
pub fn init() -> Result<(), ()> {
    sodium_init()
}

#[derive(Debug)]
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

#[derive(Debug)]
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

/// The AES-256-GCM AEAD.
///
/// # Portability Warning
///
/// The current implementation of this construction is hardware-accelerated and requires the Intel SSSE3 extensions, as well as the `aesni` and `pclmul` instructions.
///
/// Intel Westmere processors (introduced in 2010) and newer meet the requirements.
///
/// There are no plans to support non hardware-accelerated implementations of AES-GCM. If portability is a concern, use ChaCha20-Poly1305 instead.
///
/// Before using the functions below, hardware support for AES can be checked with <Aes256Gcm::available>.
///
/// The function returns `true` if the current CPU supports the AES256-GCM implementation, and `false` if it doesn't.
///
/// The library must have been initialized with [init](init) prior to calling this function.
///
/// Libsodium doc: <https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm#limitations>.
pub enum Aes256Gcm {}

impl Aes256Gcm {
    /// Check for hardware support of AES-GCM.
    ///
    /// The function returns `true` if the current CPU supports the AES256-GCM implementation, and `false` if it doesn't.
    pub fn available() -> bool {
        unsafe { crypto_aead_aes256gcm_is_available() != 0 }
    }
}

#[derive(Default)]
pub struct Sha256 {
    state: sha256::State,
}

#[derive(Default)]
pub struct Sha512 {
    state: sha512::State,
}

#[repr(transparent)]
pub struct Blake2b {
    state: crypto_generichash_state,
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
        n[4..].copy_from_slice(&nonce.to_le_bytes());

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
        n[4..].copy_from_slice(&nonce.to_le_bytes());

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

impl Cipher for Aes256Gcm {
    type Key = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "AESGCM"
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), plaintext.len() + 16);

        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce.to_be_bytes());

        unsafe {
            crypto_aead_aes256gcm_encrypt(
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
        n[4..].copy_from_slice(&nonce.to_be_bytes());

        let ret = unsafe {
            crypto_aead_aes256gcm_decrypt(
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
            let mut b: MaybeUninit<crypto_generichash_state> = MaybeUninit::uninit();
            crypto_generichash_init(b.as_mut_ptr(), null(), 0, 64);
            Blake2b {
                state: b.assume_init(),
            }
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
            crypto_generichash_update(&mut self.state, data.as_ptr(), data.len() as u64);
        }
    }

    fn result(&mut self) -> Self::Output {
        unsafe {
            let mut out: MaybeUninit<[u8; 64]> = MaybeUninit::uninit();
            crypto_generichash_final(&mut self.state, out.as_mut_ptr() as *mut u8, 64);
            Sensitive(out.assume_init())
        }
    }
}
