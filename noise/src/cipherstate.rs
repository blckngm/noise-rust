use traits::{Cipher, U8Array};

/// A `CipherState` can encrypt and decrypt data.
///
/// Mostly like `CipherState` in the spec, but must be created with a key.
pub struct CipherState<C: Cipher> {
    key: C::Key,
    n: u64,
}

impl<C> CipherState<C>
    where C: Cipher
{
    /// Name of cipher, e.g. “ChaChaPoly”.
    pub fn name() -> &'static str {
        C::name()
    }

    /// Create a new `CipherState` with a `key` and a nonce `n`.
    pub fn new(key: &[u8], n: u64) -> Self {
        CipherState {
            key: C::Key::from_slice(key),
            n: n,
        }
    }

    /// AEAD encryption.
    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        C::encrypt(&self.key, self.n, authtext, plaintext, out);
        // This will fails when n == 2 ^ 64 - 1, complying to the spec.
        self.n = self.n.checked_add(1).unwrap();
    }

    /// AEAD decryption.
    pub fn decrypt_ad(&mut self,
                      authtext: &[u8],
                      ciphertext: &[u8],
                      out: &mut [u8])
                      -> Result<(), ()> {
        C::decrypt(&self.key, self.n, authtext, ciphertext, out)?;
        self.n = self.n.checked_add(1).unwrap();
        Ok(())
    }

    /// Encryption.
    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) {
        self.encrypt_ad(&[0u8; 0], plaintext, out)
    }

    /// Encryption, returns ciphertext as `Vec<u8>`.
    pub fn encrypt_vec(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plaintext.len() + 16];
        self.encrypt(plaintext, &mut out);
        out
    }

    /// Decryption.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), ()> {
        self.decrypt_ad(&[0u8; 0], ciphertext, out)
    }

    /// Decryption, returns plaintext as `Vec<u8>`.
    pub fn decrypt_vec(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = vec![0u8; ciphertext.len() - 16];
        self.decrypt(ciphertext, &mut out)?;
        Ok(out)
    }

    /// Get underlying cipher and nonce.
    ///
    /// This is useful for e.g. WireGuard. Because packets may be lost or arrive out of order,
    /// they would likely want to deal with nonces themselves.
    pub fn extract(self) -> (C::Key, u64) {
        (self.key, self.n)
    }
}
