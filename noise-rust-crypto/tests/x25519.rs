#![cfg(feature = "x25519")]

use noise_protocol::{U8Array, DH};
use noise_rust_crypto::{sensitive::Sensitive, X25519};

#[test]
fn test_dh_non_contributory() {
    let private_key = Sensitive::from_slice(&[0x42; 32]);
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut public_key = [0; 32];
        hex::decode_to_slice(encoded, &mut public_key).unwrap();
        for high_bit in [0, 0x80] {
            // X25519 ignores the high bit, so also check the equivalent encoding.
            public_key[31] |= high_bit;
            assert!(
                X25519::dh(&private_key, &public_key).is_err(),
                "{public_key:02x?}"
            );
        }
    }
}
