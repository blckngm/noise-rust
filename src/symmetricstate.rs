use cipherstate::CipherState;
use crypto_types::{Cipher, Hash};
use std::marker::PhantomData;

use utils::copy_memory;

pub struct SymmetricState<C, H> {
    // Instead of `has_key`, use an `Option`.
    cipherstate: Option<CipherState<C>>,
    // Doesn't actually need an H.
    hasher: PhantomData<*const H>,
    // Use Vec, until this is solved:
    // https://github.com/rust-lang/rust/issues/34344
    h: Vec<u8>,
    ck: Vec<u8>,
    has_preshared_key: bool,
}

impl<C, H> SymmetricState<C, H>
    where C: Cipher,
          H: Hash
{
    /// Initialize a `SymmetricState` with a handshake name.
    pub fn new(handshake_name: &[u8]) -> SymmetricState<C, H> {
        let mut h = vec![0u8; H::hash_len()];

        if handshake_name.len() <= H::hash_len() {
            copy_memory(handshake_name, &mut h);
        } else {
            H::hash(handshake_name, &mut h);
        }

        SymmetricState {
            cipherstate: None,
            hasher: Default::default(),
            ck: h.clone(),
            h: h,
            has_preshared_key: false,
        }
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let (k1, k2) = H::hkdf_vec(&self.ck, data);
        self.ck = k1;
        self.cipherstate = Some(CipherState::new(&k2[..C::key_len()], 0));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut h: H = Default::default();
        h.input(&self.h);
        h.input(data);
        h.result(&mut self.h);
    }

    pub fn mix_preshared_key(&mut self, psk: &[u8]) {
        let (k1, k2) = H::hkdf_vec(&self.ck, psk);
        self.ck = k1;
        self.mix_hash(&k2);
        self.has_preshared_key = true;
    }

    pub fn has_key(&self) -> bool {
        self.cipherstate.is_some()
    }

    pub fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let output_len = if let Some(ref mut c) = self.cipherstate {
            c.encrypt_ad(&self.h, plaintext, out);
            plaintext.len() + C::tag_len()
        } else {
            copy_memory(plaintext, out)
        };
        self.mix_hash(&out[..output_len]);
        output_len
    }

    pub fn encrypt_and_hash_vec(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out =
            vec![0u8; if self.has_key() { plaintext.len() + 16 } else { plaintext.len() } ];
        let out_len = self.encrypt_and_hash(plaintext, &mut out);
        assert_eq!(out.len(), out_len);
        out
    }

    pub fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
        if let Some(ref mut c) = self.cipherstate {
            c.decrypt_ad(&self.h, data, out)?;
        } else {
            copy_memory(data, out);
        }
        self.mix_hash(data);
        Ok(())
    }

    pub fn decrypt_and_hash_vec(&mut self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = vec![0u8; if self.has_key() { data.len() - 16 } else { data.len() } ];
        self.decrypt_and_hash(data, &mut out)?;
        Ok(out)
    }

    pub fn split(&self) -> (CipherState<C>, CipherState<C>) {
        let (k1, k2) = H::hkdf_vec(&self.ck, &[]);
        let c1 = CipherState::new(&k1[..C::key_len()], 0);
        let c2 = CipherState::new(&k2[..C::key_len()], 0);
        (c1, c2)
    }

    pub fn get_hash(&self) -> &[u8] {
        self.h.as_slice()
    }
}
