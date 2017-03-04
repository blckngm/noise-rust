extern crate byteorder;
extern crate crypto;
extern crate rand;
extern crate noise_protocol as noise;

use byteorder::{BigEndian, LittleEndian, ByteOrder};
use crypto::{blake2b, blake2s, sha2};
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::chacha20::ChaCha20;
use crypto::curve25519::{curve25519, curve25519_base};
use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::poly1305::Poly1305;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::util::{fixed_time_eq, secure_memset};
use noise::*;
use rand::{OsRng, Rng};

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
        secure_memset(&mut self.0, 0);
    }
}

#[derive(Clone)]
pub enum X25519 {}

#[derive(Clone)]
pub enum Aes256Gcm {}

#[derive(Clone)]
pub enum ChaCha20Poly1305 {}

#[derive(Clone)]
pub struct Sha256 {
    hasher: sha2::Sha256,
}

#[derive(Clone)]
pub struct Sha512 {
    hasher: sha2::Sha512,
}

#[derive(Clone)]
pub struct Blake2b {
    hasher: blake2b::Blake2b,
}

#[derive(Clone)]
pub struct Blake2s {
    hasher: blake2s::Blake2s,
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

        OsRng::new().unwrap().fill_bytes(&mut k);

        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        SecretKey(k)
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        curve25519_base(k.as_slice())
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        curve25519(k.as_slice(), pk.as_slice())
    }
}

impl Cipher for Aes256Gcm {
    type Key = SecretKey;

    fn name() -> &'static str {
        "AESGCM"
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(plaintext.len() + 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, k.as_slice(), &nonce_bytes, ad);
        let (c, t) = out.split_at_mut(plaintext.len());
        cipher.encrypt(plaintext, c, t);
    }

    fn decrypt(k: &Self::Key,
               nonce: u64,
               ad: &[u8],
               ciphertext: &[u8],
               out: &mut [u8])
               -> Result<(), ()> {
        assert_eq!(ciphertext.len(), out.len() + 16);

        let mut nonce_bytes = [0u8; 12];
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let mut cipher = AesGcm::new(KeySize::KeySize256, k.as_slice(), &nonce_bytes, ad);
        let text_len = ciphertext.len() - 16;
        if cipher.decrypt(&ciphertext[..text_len],
                          &mut out[..text_len],
                          &ciphertext[text_len..]) {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Key = SecretKey;

    fn name() -> &'static str {
        "ChaChaPoly"
    }

    // This is taken from trevp's original screech.
    //
    // Rust-crypto only provides original ChaCha20-Poly1305, not the IETF variant. So we
    // have to implement it ourselves, in terms ChaCha20 and Poly1305.

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert_eq!(plaintext.len() + 16, out.len());

        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut cipher = ChaCha20::new(k.as_slice(), &nonce_bytes);
        let zeros = [0u8; 64];
        let mut poly_key = [0u8; 64];
        cipher.process(&zeros, &mut poly_key);
        cipher.process(plaintext, &mut out[..plaintext.len()]);

        let mut poly = Poly1305::new(&poly_key[..32]);
        poly.input(ad);
        let mut padding = [0u8; 16];
        poly.input(&padding[..(16 - (ad.len() % 16)) % 16]);
        poly.input(&out[..plaintext.len()]);
        poly.input(&padding[..(16 - (plaintext.len() % 16)) % 16]);
        LittleEndian::write_u64(&mut padding, ad.len() as u64);
        poly.input(&padding[..8]);
        LittleEndian::write_u64(&mut padding, plaintext.len() as u64);
        poly.input(&padding[..8]);
        poly.raw_result(&mut out[plaintext.len()..]);
    }

    fn decrypt(k: &Self::Key,
               nonce: u64,
               ad: &[u8],
               ciphertext: &[u8],
               out: &mut [u8])
               -> Result<(), ()> {
        assert_eq!(ciphertext.len(), out.len() + 16);

        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut cipher = ChaCha20::new(k.as_slice(), &nonce_bytes);
        let zeros = [0u8; 64];
        let mut poly_key = [0u8; 64];
        cipher.process(&zeros, &mut poly_key);

        let mut poly = Poly1305::new(&poly_key[..32]);
        let mut padding = [0u8; 15];
        let text_len = ciphertext.len() - 16;
        poly.input(ad);
        poly.input(&padding[..(16 - (ad.len() % 16)) % 16]);
        poly.input(&ciphertext[..text_len]);
        poly.input(&padding[..(16 - (text_len % 16)) % 16]);
        LittleEndian::write_u64(&mut padding, ad.len() as u64);
        poly.input(&padding[..8]);
        LittleEndian::write_u64(&mut padding, text_len as u64);
        poly.input(&padding[..8]);
        let mut tag = [0u8; 16];
        poly.raw_result(&mut tag);
        if !fixed_time_eq(&tag, &ciphertext[text_len..]) {
            return Err(());
        }
        cipher.process(&ciphertext[..text_len], &mut out[..text_len]);
        Ok(())
    }
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256 { hasher: sha2::Sha256::new() }
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        self.hasher.result(&mut out);
        out
    }
}

impl Default for Sha512 {
    fn default() -> Sha512 {
        Sha512 { hasher: sha2::Sha512::new() }
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        self.hasher.result(&mut out);
        out
    }
}

impl Default for Blake2b {
    fn default() -> Blake2b {
        Blake2b { hasher: blake2b::Blake2b::new(64) }
    }
}

impl Hash for Blake2b {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2b"
    }

    fn input(&mut self, data: &[u8]) {
        Digest::input(&mut self.hasher, data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        Digest::result(&mut self.hasher, &mut out);
        out
    }
}

impl Default for Blake2s {
    fn default() -> Blake2s {
        Blake2s { hasher: blake2s::Blake2s::new(32) }
    }
}

impl Hash for Blake2s {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "BLAKE2s"
    }

    fn input(&mut self, data: &[u8]) {
        Digest::input(&mut self.hasher, data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        Digest::result(&mut self.hasher, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::{FromHex, ToHex};
    use super::*;

    #[test]
    fn chacha20poly1305_round_trip() {
        // Empty plaintext.
        let key = SecretKey([0u8; 32]);
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        ChaCha20Poly1305::encrypt(&key, nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 0];
        assert!(ChaCha20Poly1305::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext)
            .is_ok());
        ciphertext[0] ^= 1;
        assert!(ChaCha20Poly1305::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext)
            .is_err());

        // Non-empty plaintext.

        let plaintext = [0x34u8; 117];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 133];
        ChaCha20Poly1305::encrypt(&key, nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [0u8; 117];
        assert!(ChaCha20Poly1305::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext)
            .is_ok());
        assert_eq!(resulttext.to_hex(), plaintext.to_hex());
    }

    #[test]
    fn chacha20poly1305_known_answer() {
        // RFC 7539
        let key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
            .from_hex()
            .unwrap();
        let key = SecretKey::from_slice(&key);
        let nonce = 0x0807060504030201u64;
        let ciphertext = "64a0861575861af460f062c79be643bd\
                          5e805cfd345cf389f108670ac76c8cb2\
                          4c6cfc18755d43eea09ee94e382d26b0\
                          bdb7b73c321b0100d4f03b7f355894cf\
                          332f830e710b97ce98c8a84abd0b9481\
                          14ad176e008d33bd60f982b1ff37c855\
                          9797a06ef4f0ef61c186324e2b350638\
                          3606907b6a7c02b0f9f6157b53c867e4\
                          b9166c767b804d46a59b5216cde7a4e9\
                          9040c5a40433225ee282a1b0a06c523e\
                          af4534d7f83fa1155b0047718cbc546a\
                          0d072b04b3564eea1b422273f548271a\
                          0bb2316053fa76991955ebd63159434e\
                          cebb4e466dae5a1073a6727627097a10\
                          49e617d91d361094fa68f0ff77987130\
                          305beaba2eda04df997b714d6c6f2c29\
                          a6ad5cb4022b02709b"
            .from_hex()
            .unwrap();
        let tag = "eead9d67890cbb22392336fea1851f38".from_hex().unwrap();
        let authtext = "f33388860000000000004e91".from_hex().unwrap();
        let mut combined_text = [0u8; 1024];
        let mut out = [0u8; 1024];
        combined_text[..ciphertext.len()].copy_from_slice(&ciphertext);
        combined_text[ciphertext.len()..ciphertext.len() + 16].copy_from_slice(&tag);

        assert!(ChaCha20Poly1305::decrypt(&key,
                                          nonce,
                                          &authtext,
                                          &combined_text[..ciphertext.len() + 16],
                                          &mut out[..ciphertext.len()])
            .is_ok());
        let desired_plaintext = "496e7465726e65742d44726166747320\
                                 61726520647261667420646f63756d65\
                                 6e74732076616c696420666f72206120\
                                 6d6178696d756d206f6620736978206d\
                                 6f6e74687320616e64206d6179206265\
                                 20757064617465642c207265706c6163\
                                 65642c206f72206f62736f6c65746564\
                                 206279206f7468657220646f63756d65\
                                 6e747320617420616e792074696d652e\
                                 20497420697320696e617070726f7072\
                                 6961746520746f2075736520496e7465\
                                 726e65742d4472616674732061732072\
                                 65666572656e6365206d617465726961\
                                 6c206f7220746f206369746520746865\
                                 6d206f74686572207468616e20617320\
                                 2fe2809c776f726b20696e2070726f67\
                                 726573732e2fe2809d";
        assert_eq!(out[..ciphertext.len()].to_hex(), desired_plaintext);
    }
}
