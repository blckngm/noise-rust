//! Crypto algorithms.

extern crate byteorder;
extern crate crypto;
extern crate ring;

use self::byteorder::{ByteOrder, BigEndian, LittleEndian};
use self::crypto::{blake2b, blake2s, sha2};
use self::crypto::curve25519::{curve25519, curve25519_base};
use self::crypto::digest::Digest;
use self::ring::aead;

use traits::{DH, Cipher, Hash, U8Array};

// TODO zero out secrets in `Drop`.

pub enum X25519 {}

pub enum Aes256Gcm {}

pub enum ChaCha20Poly1305 {}

pub struct Sha256 {
    hasher: sha2::Sha256,
}

pub struct Sha512 {
    hasher: sha2::Sha512,
}

pub struct Blake2b {
    hasher: blake2b::Blake2b,
}

pub struct Blake2s {
    hasher: blake2s::Blake2s,
}

impl DH for X25519 {
    type Key = [u8; 32];
    type Pubkey = [u8; 32];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "25519"
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        curve25519_base(k.as_slice())
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        curve25519(k.as_slice(), pk.as_slice())
    }
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
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 64];
        self.hasher.result(&mut out);
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
        self.hasher.input(data);
    }

    fn result(&mut self) -> Self::Output {
        let mut out = [0u8; 32];
        self.hasher.result(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::{FromHex, ToHex};
    use super::*;
    use traits::{DH, Cipher, Hash, U8Array};

    #[test]
    fn sha256() {
        assert_eq!(Sha256::hash(b"abc").as_slice().to_hex(),
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn hmac_sha256() {
        // RFC 4231
        let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".from_hex().unwrap();
        let data = "dddddddddddddddddddddddddddddddddddddddddddddddddd\
                    dddddddddddddddddddddddddddddddddddddddddddddddddd"
            .from_hex()
            .unwrap();
        assert_eq!(Sha256::hmac(&key, &data).as_slice().to_hex(),
                   "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    #[test]
    fn hmac_sha512() {
        // RFC 4231
        let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".from_hex().unwrap();
        let data = "dddddddddddddddddddddddddddddddddddddddddddddddddd\
                    dddddddddddddddddddddddddddddddddddddddddddddddddd"
            .from_hex()
            .unwrap();
        assert_eq!(Sha512::hmac(&key, &data).as_slice().to_hex(),
                   "fa73b0089d56a284efb0f0756c890be9\
                    b1b5dbdd8ee81a3655f83e33b2279d39\
                    bf3e848279a722c806b485a47e67c807\
                    b946a337bee8942674278859e13292fb");
    }

    #[test]
    fn blake2b() {
        // BLAKE2b test - draft-saarinen-blake2-06
        assert_eq!(Blake2b::hash(b"abc").as_slice().to_hex(),
                   "ba80a53f981c4d0d6a2797b69f12f6e9\
                    4c212f14685ac4b74b12bb6fdbffa2d1\
                    7d87c5392aab792dc252d5de4533cc95\
                    18d38aa8dbf1925ab92386edd4009923");
    }

    #[test]
    fn blake2s() {
        // BLAKE2s test - draft-saarinen-blake2-06
        assert_eq!(Blake2s::hash(b"abc").as_slice().to_hex(),
                   "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn x25519() {
        // Curve25519 test - draft-curves-10
        let scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
            .from_hex()
            .unwrap();
        let key = <X25519 as DH>::Key::from_slice(&scalar);
        let public = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
            .from_hex()
            .unwrap();
        let output = X25519::dh(&key, &<X25519 as DH>::Pubkey::from_slice(&public));
        assert_eq!(output.to_hex(),
                   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    #[test]
    fn aes256gcm() {
        //AES256-GCM tests - gcm-spec.pdf
        // Test Case 13
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];

        Aes256Gcm::encrypt(&key, nonce, &authtext, &plaintext, &mut ciphertext);
        assert_eq!(ciphertext.to_hex(), "530f8afbc74536b9a963b4f1c4cb738b");

        let mut resulttext = [];
        assert!(Aes256Gcm::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext).is_ok());
        ciphertext[0] ^= 1;
        assert!(Aes256Gcm::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext).is_err());

        // Test Case 14
        let plaintext2 = [0u8; 16];
        let mut ciphertext2 = [0u8; 32];
        Aes256Gcm::encrypt(&key, nonce, &authtext, &plaintext2, &mut ciphertext2);
        assert_eq!(ciphertext2.to_hex(),
                   "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        let mut resulttext2 = [1u8; 16];
        assert!(Aes256Gcm::decrypt(&key, nonce, &authtext, &ciphertext2, &mut resulttext2).is_ok());
        assert!(plaintext2 == resulttext2);
        ciphertext2[0] ^= 1;
        assert!(Aes256Gcm::decrypt(&key, nonce, &authtext, &ciphertext2, &mut resulttext2)
            .is_err());
    }

    #[test]
    fn chacha20poly1305_round_trip() {
        // Empty plaintext.
        let key = [0u8; 32];
        let nonce = 0u64;
        let plaintext = [0u8; 0];
        let authtext = [0u8; 0];
        let mut ciphertext = [0u8; 16];
        ChaCha20Poly1305::encrypt(&key, nonce, &authtext, &plaintext, &mut ciphertext);

        let mut resulttext = [];
        assert!(ChaCha20Poly1305::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext)
            .is_ok());
        ciphertext[0] ^= 1;
        assert!(ChaCha20Poly1305::decrypt(&key, nonce, &authtext, &ciphertext, &mut resulttext)
            .is_err());

        // Non-empty plaintext.

        let key = [0u8; 32];
        let nonce = 0u64;
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
        let key = <ChaCha20Poly1305 as Cipher>::Key::from_slice(&key);
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
