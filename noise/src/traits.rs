/// A trait for fixed size u8 array.

// Inspired by ArrayVec and SmallVec, but no unsafe.
pub trait U8Array: Copy {
    fn new() -> Self;
    fn new_with(u8) -> Self;
    fn from_slice(&[u8]) -> Self;
    fn len() -> usize;
    fn as_slice(&self) -> &[u8];
    fn as_mut(&mut self) -> &mut [u8];
}

macro_rules! impl_array {
    ($len:expr) => {
        impl U8Array for [u8; $len] {
            fn new() -> Self {
                [0u8; $len]
            }

            fn new_with(x: u8) -> Self {
                [x; $len]
            }

            fn from_slice(data: &[u8]) -> Self {
                let mut a = [0u8; $len];
                a.copy_from_slice(data);
                a
            }

            fn len() -> usize {
                $len
            }

            fn as_slice(&self) -> &[u8] {
                self
            }

            fn as_mut(&mut self) -> &mut [u8] {
                self
            }
        }
    }
}

impl_array!(32);
impl_array!(64);
impl_array!(128);

/// A random number generator.
pub trait RandomGen {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

/// A DH.
pub trait DH {
    // XXX For X25519 private keys, should we “clamp” when generating
    // them or when using them?
    type Key: U8Array;
    type Pubkey: U8Array;
    type Output: U8Array;

    fn name() -> &'static str;

    fn pub_len() -> usize {
        Self::Pubkey::len()
    }

    fn pubkey(&Self::Key) -> Self::Pubkey;

    fn dh(&Self::Key, &Self::Pubkey) -> Self::Output;
}

/// An AEAD.
pub trait Cipher {
    fn name() -> &'static str;
    type Key: U8Array;

    fn key_len() -> usize {
        Self::Key::len()
    }

    fn tag_len() -> usize {
        16
    }

    /// AEAD encryption.
    ///
    /// out.len() == plaintext.len() + Self::tag_len()
    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]);

    /// AEAD decryption.
    ///
    /// out.len() == ciphertext.len() - Self::tag_len()
    fn decrypt(k: &Self::Key,
               nonce: u64,
               ad: &[u8],
               ciphertext: &[u8],
               out: &mut [u8])
               -> Result<(), ()>;
}

/// A hash function.
pub trait Hash: Default {
    fn name() -> &'static str;

    type Block: U8Array;
    type Output: U8Array;

    fn block_len() -> usize {
        Self::Block::len()
    }

    fn hash_len() -> usize {
        Self::Output::len()
    }

    fn reset(&mut self) {
        *self = Default::default();
    }

    fn input(&mut self, data: &[u8]);
    fn result(&mut self) -> Self::Output;

    fn hash(data: &[u8]) -> Self::Output {
        let mut h: Self = Default::default();
        h.input(data);
        h.result()
    }

    fn hmac_many(key: &[u8], data: &[&[u8]]) -> Self::Output {
        assert!(key.len() <= Self::block_len());

        let mut ipad = Self::Block::new_with(0x36u8);
        let mut opad = Self::Block::new_with(0x5cu8);

        for count in 0..key.len() {
            ipad.as_mut()[count] ^= key[count];
            opad.as_mut()[count] ^= key[count];
        }

        let mut hasher: Self = Default::default();
        hasher.input(ipad.as_slice());
        for d in data {
            hasher.input(d);
        }
        let inner_output = hasher.result();

        hasher.reset();
        hasher.input(opad.as_slice());
        hasher.input(inner_output.as_slice());
        hasher.result()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Self::Output {
        Self::hmac_many(key, &[data])
    }

    fn hkdf(chaining_key: &[u8], input_key_material: &[u8]) -> (Self::Output, Self::Output) {
        let temp_key = Self::hmac(chaining_key, input_key_material);
        let out1 = Self::hmac(temp_key.as_slice(), &[1u8]);
        let out2 = Self::hmac_many(temp_key.as_slice(), &[out1.as_slice(), &[2u8]]);
        (out1, out2)
    }
}
