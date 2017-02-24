extern crate noise;
extern crate sodiumoxide;

// TODO Add AEADs, after
// [https://github.com/dnaq/sodiumoxide/pull/149] is merged.

// TODO BLAKE2b?

// TODO Add streaming hash interface for sodiumoxide.

use noise::*;
use sodiumoxide::crypto::scalarmult::curve25519;

// TODO
pub enum X25519 {}

impl DH for X25519 {
    type Key = [u8; 32];
    type Pubkey = [u8; 32];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "25519"
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        let s = curve25519::Scalar(*k);
        curve25519::scalarmult_base(&s).0
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Self::Output {
        let s = curve25519::Scalar(*k);
        let pk = curve25519::GroupElement(*pk);
        // XXX DoS???
        curve25519::scalarmult(&s, &pk).unwrap().0
    }
}
