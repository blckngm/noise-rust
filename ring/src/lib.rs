extern crate byteorder;
extern crate noise;
extern crate ring;

use self::byteorder::{ByteOrder, BigEndian, LittleEndian};
use noise::{Cipher, U8Array};

use ring::aead;

pub enum Aes256Gcm {}

pub enum ChaCha20Poly1305 {}

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

    fn decrypt(k: &Self::Key,
               nonce: u64,
               authtext: &[u8],
               ciphertext: &[u8],
               out: &mut [u8])
               -> Result<(), ()> {
        assert_eq!(ciphertext.len() - 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        // Eh, ring API is ... weird.
        let mut in_out = ciphertext.to_vec();

        let k = aead::OpeningKey::new(&aead::AES_256_GCM, k.as_slice()).unwrap();
        let out0 = aead::open_in_place(&k, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;
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

    fn decrypt(k: &Self::Key,
               nonce: u64,
               authtext: &[u8],
               ciphertext: &[u8],
               out: &mut [u8])
               -> Result<(), ()> {
        assert_eq!(ciphertext.len() - 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut in_out = ciphertext.to_vec();

        let k = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap();
        let out0 = aead::open_in_place(&k, &nonce_bytes, authtext, 0, &mut in_out).map_err(|_| ())?;

        out.copy_from_slice(out0);
        Ok(())
    }
}
