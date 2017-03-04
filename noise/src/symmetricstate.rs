use cipherstate::CipherState;
use traits::{Cipher, Hash, U8Array};

#[derive(Clone)]
pub struct SymmetricState<C: Cipher, H: Hash> {
    // Instead of `has_key`, use an `Option`.
    cipherstate: Option<CipherState<C>>,
    h: H::Output,
    ck: H::Output,
    has_preshared_key: bool,
}

impl<C, H> SymmetricState<C, H>
    where C: Cipher,
          H: Hash
{
    /// Initialize a `SymmetricState` with a handshake name.
    pub fn new(handshake_name: &[u8]) -> SymmetricState<C, H> {
        let mut h = H::Output::new();

        if handshake_name.len() <= H::hash_len() {
            h.as_mut()[..handshake_name.len()].copy_from_slice(handshake_name);
        } else {
            h = H::hash(handshake_name);
        }

        SymmetricState {
            cipherstate: None,
            ck: h,
            h: h,
            has_preshared_key: false,
        }
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let (k1, k2) = H::hkdf(self.ck.as_slice(), data);
        self.ck = k1;
        self.cipherstate = Some(CipherState::new(&k2.as_slice()[..C::key_len()], 0));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut h: H = Default::default();
        h.input(self.h.as_slice());
        h.input(data);
        self.h = h.result();
    }

    pub fn mix_preshared_key(&mut self, psk: &[u8]) {
        let (k1, k2) = H::hkdf(self.ck.as_slice(), psk);
        self.ck = k1;
        self.mix_hash(k2.as_slice());
        self.has_preshared_key = true;
    }

    pub fn has_key(&self) -> bool {
        self.cipherstate.is_some()
    }

    pub fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) {
        if let Some(ref mut c) = self.cipherstate {
            c.encrypt_ad(self.h.as_slice(), plaintext, out);
        } else {
            out.copy_from_slice(plaintext);
        };
        self.mix_hash(out);
    }

    pub fn encrypt_and_hash_vec(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out =
            vec![0u8; if self.has_key() { plaintext.len() + 16 } else { plaintext.len() } ];
        self.encrypt_and_hash(plaintext, &mut out);
        out
    }

    pub fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
        if let Some(ref mut c) = self.cipherstate {
            c.decrypt_ad(self.h.as_slice(), data, out)?;
        } else {
            out.copy_from_slice(data)
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
        let (k1, k2) = H::hkdf(self.ck.as_slice(), &[]);
        let c1 = CipherState::new(&k1.as_slice()[..C::key_len()], 0);
        let c2 = CipherState::new(&k2.as_slice()[..C::key_len()], 0);
        (c1, c2)
    }

    pub fn get_hash(&self) -> &[u8] {
        self.h.as_slice()
    }
}
