#![no_std]

extern crate byteorder;
extern crate noise_protocol as noise;
extern crate ring;

use self::byteorder::{BigEndian, ByteOrder, LittleEndian};
use noise::{Cipher, Hash, U8Array};
use ring::aead;
use ring::digest;

pub enum Aes256Gcm {}

pub enum ChaCha20Poly1305 {}

pub struct Sha256 {
    context: digest::Context,
}

pub struct Sha512 {
    context: digest::Context,
}

impl Cipher for Aes256Gcm {
    type Key = [u8; 32];

    fn name() -> &'static str {
        "AESGCM"
    }

    fn encrypt(k: &Self::Key, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(plaintext.len() + 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        out[..plaintext.len()].copy_from_slice(plaintext);

        let key = aead::SealingKey::new(&aead::AES_256_GCM, k.as_slice()).unwrap();
        aead::seal_in_place(&key, &nonce_bytes, authtext, out, 16).unwrap();
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert_eq!(ciphertext.len() - 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        // Eh, ring API is ... weird.
        let mut in_out = ciphertext.to_vec();

        let k = aead::OpeningKey::new(&aead::AES_256_GCM, k.as_slice()).unwrap();
        let out0 =
            aead::open_in_place(&k, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;
        assert_eq!(out0.len(), out.len());

        out.copy_from_slice(out0);
        Ok(())
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Key = [u8; 32];

    fn name() -> &'static str {
        "ChaChaPoly"
    }

    fn encrypt(k: &Self::Key, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(plaintext.len() + 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        out[..plaintext.len()].copy_from_slice(plaintext);

        let k = aead::SealingKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap();
        aead::seal_in_place(&k, &nonce_bytes, authtext, out, 16).unwrap();
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert_eq!(ciphertext.len() - 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut in_out = ciphertext.to_vec();

        let k = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap();
        let out0 =
            aead::open_in_place(&k, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;

        out.copy_from_slice(out0);
        Ok(())
    }
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256 {
            context: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        // XXX have to clone becuase finish() moves Context.
        out.copy_from_slice(self.context.clone().finish().as_ref());
        out
    }
}

impl Default for Sha512 {
    fn default() -> Sha512 {
        Sha512 {
            context: digest::Context::new(&digest::SHA512),
        }
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.context.clone().finish().as_ref());
        out
    }
}
