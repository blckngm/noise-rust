pub trait RandomGen {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

/// Represents a DH private key.
pub trait DH {
    fn name() -> &'static str;
    // Really should be an associated constant!
    fn pub_len() -> usize;

    fn new(privkey: &[u8]) -> Self;
    fn generate(rng: &mut RandomGen) -> Self;

    fn get_pubkey(&self, out: &mut [u8]);

    fn get_pubkey_vec(&self) -> Vec<u8> {
        let mut pubkey = vec![0u8; Self::pub_len()];
        self.get_pubkey(&mut pubkey);
        pubkey
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]);

    fn dh_vec(&self, pubkey: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Self::pub_len()];
        self.dh(pubkey, &mut out);
        out
    }
}

pub trait Cipher {
    fn name() -> &'static str;
    fn key_len() -> usize;
    fn tag_len() -> usize;

    fn new(key: &[u8]) -> Self;

    fn set(&mut self, key: &[u8]);
    fn encrypt(&self, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]);
    fn decrypt(&self, nonce: u64, ad: &[u8], ciphertext: &[u8], out: &mut [u8]) -> bool;
}

pub trait Hash: Default {
    fn name() -> &'static str;
    fn block_len() -> usize;
    fn hash_len() -> usize;

    fn reset(&mut self) {
        *self = Default::default();
    }

    fn input(&mut self, data: &[u8]);
    fn result(&mut self, out: &mut [u8]);

    fn result_vec(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; Self::hash_len()];
        self.result(&mut out);
        out
    }

    fn hash(data: &[u8], out: &mut [u8]) {
        let mut h: Self = Default::default();
        h.input(data);
        h.result(out);
    }

    fn hash_vec(data: &[u8]) -> Vec<u8> {
        let mut h: Self = Default::default();
        h.input(data);
        h.result_vec()
    }

    fn hmac(key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= Self::block_len());
        let block_len = Self::block_len();
        let mut ipad = vec![0x36u8; Self::block_len()];
        let mut opad = vec![0x5cu8; Self::block_len()];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }

        let mut hasher: Self = Default::default();
        hasher.input(&ipad[..block_len]);
        hasher.input(data);
        let inner_output = hasher.result_vec();

        hasher.reset();
        hasher.input(&opad[..block_len]);
        hasher.input(&inner_output);
        hasher.result(out);
    }

    fn hmac_vec(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Self::hash_len()];
        Self::hmac(key, data, &mut out);
        out
    }

    fn hkdf(chaining_key: &[u8], input_key_material: &[u8], out1: &mut [u8], out2: &mut [u8]) {
        let temp_key = Self::hmac_vec(chaining_key, input_key_material);
        let mut in2 = Self::hmac_vec(&temp_key, &[1u8]);
        out1.copy_from_slice(&in2);
        in2.push(2);
        Self::hmac(&temp_key, &in2, out2);
    }

    fn hkdf_vec(chaining_key: &[u8], input_key_material: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut k1 = vec![0u8; Self::hash_len()];
        let mut k2 = vec![0u8; Self::hash_len()];

        Self::hkdf(chaining_key, input_key_material, &mut k1, &mut k2);
        (k1, k2)
    }
}
