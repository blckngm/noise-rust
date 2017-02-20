use crypto_types::Cipher;

/// A `CipherState` can encrypt and decrypt data. It keeps a secret key and a nonce.
///
/// Mostly like `CipherState` in the spec, but must be created with a key.
pub struct CipherState<C> {
    cipher: C,
    n: u64,
}

impl<C> CipherState<C>
    where C: Cipher
{
    pub fn name() -> &'static str {
        C::name()
    }

    pub fn new(key: &[u8], n: u64) -> Self {
        CipherState {
            cipher: C::new(key),
            n: n,
        }
    }

    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        self.cipher.encrypt(self.n, authtext, plaintext, out);
        // This will fails when n == 2 ^ 64 - 1, complying to the spec.
        self.n = self.n.checked_add(1).unwrap();
    }

    pub fn decrypt_ad(&mut self,
                      authtext: &[u8],
                      ciphertext: &[u8],
                      out: &mut [u8])
                      -> Result<(), ()> {
        self.cipher.decrypt(self.n, authtext, ciphertext, out)?;
        self.n = self.n.checked_add(1).unwrap();
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) {
        self.encrypt_ad(&[0u8; 0], plaintext, out)
    }

    pub fn encrypt_vec(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plaintext.len() + 16];
        self.encrypt(plaintext, &mut out);
        out
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), ()> {
        self.decrypt_ad(&[0u8; 0], ciphertext, out)
    }

    pub fn decrypt_vec(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = vec![0u8; ciphertext.len() - 16];
        self.decrypt(ciphertext, &mut out)?;
        Ok(out)
    }

    /// Get underlying cipher.
    pub fn get_cipher(self) -> C {
        self.cipher
    }
}
