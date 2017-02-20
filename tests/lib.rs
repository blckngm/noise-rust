extern crate noise;
extern crate rustc_serialize;

use self::rustc_serialize::hex::{FromHex, ToHex};
use noise::*;

// TODO verify and generate vectors automatically, like noise-c and cacophony.

// Noise_IK_25519_ChaChaPoly_BLAKE2s. From noise-c.

#[test]
fn noise_ik_vectors() {
    type HS = HandshakeState<X25519, ChaCha20Poly1305, Blake2s>;

    let init_s = X25519::new("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
        .from_hex()
        .unwrap()
        .as_slice());
    let init_e = X25519::new("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
        .from_hex()
        .unwrap()
        .as_slice());
    let resp_s = X25519::new("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
        .from_hex()
        .unwrap()
        .as_slice());
    let resp_e = X25519::new("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
        .from_hex()
        .unwrap()
        .as_slice());
    let init_rs = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"
        .from_hex()
        .unwrap();

    assert_eq!(init_rs, resp_s.get_pubkey_vec());

    let prologue = "50726f6c6f677565313233".from_hex().unwrap();

    let mut h_i = HS::new(noise_ik(),
                          true,
                          &prologue,
                          None,
                          Some(init_s),
                          Some(init_e),
                          Some(init_rs),
                          None);

    let mut h_r = HS::new(noise_ik(),
                          false,
                          &prologue,
                          None,
                          Some(resp_s),
                          Some(resp_e),
                          None,
                          None);

    let m0 = "4c756477696720766f6e204d69736573".from_hex().unwrap();
    let c0 = h_i.write_message(&m0);
    assert_eq!(c0.to_hex(),
               "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440b03\
                ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adb78f20587\
                71dfd4229fbdc85c5fba3b587b1d171ce368229c7b752ac25b8faf4e7b2fab7326f0\
                d6fa1fdbef58de623245");

    let m0_1 = h_r.read_message(&c0);
    assert_eq!(m0_1.unwrap(), m0);

    let m1 = "4d757272617920526f746862617264".from_hex().unwrap();
    let c1 = h_r.write_message(&m1);
    assert_eq!(c1.to_hex(),
               "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d9b\
                5a8927f0ac9655ef76833bc7e55269c081ec38c61031f76fe15b2aaaad5");
    let m1_1 = h_i.read_message(&c1);
    assert_eq!(m1_1.unwrap(), m1);

    assert!(h_i.completed());
    assert!(h_r.completed());

    let hash = h_i.get_hash();
    let hash1 = h_r.get_hash();
    assert_eq!(hash, hash1);
    assert_eq!(hash.to_hex(),
               "45e34c56ca0de9c348e104edcf503035e5559ceed661ac22916f6f171696d994");

    let (mut i_send, mut i_recv) = h_i.get_ciphers();
    let (mut r_recv, mut r_send) = h_r.get_ciphers();

    {
        let payload = "462e20412e20486179656b".from_hex().unwrap();
        let ciphertext = i_send.encrypt_vec(&payload);
        assert_eq!(ciphertext.to_hex(),
                   "2c256ed08fcd08c2980f954ee4beaccb61c9581340f5dd2fd1cf3b");
        let payload1 = r_recv.decrypt_vec(&ciphertext);
        assert_eq!(payload1, Some(payload));
    }

    {
        let payload = "4361726c204d656e676572".from_hex().unwrap();
        let ciphertext = r_send.encrypt_vec(&payload);
        assert_eq!(ciphertext.to_hex(),
                   "d6033f70eee20945c7c9dba304e397ee3b284ff5e00fd9efb095d3");
        let payload1 = i_recv.decrypt_vec(&ciphertext);
        assert_eq!(payload1, Some(payload));
    }

    {
        let payload = "4a65616e2d426170746973746520536179".from_hex().unwrap();
        let ciphertext = i_send.encrypt_vec(&payload);
        assert_eq!(ciphertext.to_hex(),
                   "a9c068ca5d8babf72560652d8e851adbfac35c8a66e810d560863173e96adf4cfe");
        let payload1 = r_recv.decrypt_vec(&ciphertext);
        assert_eq!(payload1, Some(payload));
    }

    {
        let payload = "457567656e2042f6686d20766f6e2042617765726b".from_hex().unwrap();
        let ciphertext = r_send.encrypt_vec(&payload);
        assert_eq!(ciphertext.to_hex(),
                   "2a09d8f459e5927e40fdd2eddc99bdafb04e13a26f145cb5cfe9e6ba34c94331ebc17d5156");
        let payload1 = i_recv.decrypt_vec(&ciphertext);
        assert_eq!(payload1, Some(payload));
    }
}
