// Program to verify the vectors.

extern crate noise_protocol as noise;
extern crate noise_sodiumoxide;
extern crate noise_ring;
extern crate noise_rust_crypto;
extern crate serde;
extern crate rustc_serialize;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use noise::*;
use noise::patterns::*;
use noise_ring as ring;
use noise_rust_crypto as crypto;
use noise_sodiumoxide as sodium;

use rustc_serialize::hex::FromHex;
use serde_json as json;

#[derive(Serialize, Deserialize)]
struct HexString(String);

impl HexString {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.from_hex().unwrap()
    }
}

#[derive(Serialize, Deserialize)]
struct Vector {
    name: String,
    pattern: String,
    dh: String,
    cipher: String,
    hash: String,
    init_prologue: HexString,
    init_psk: Option<HexString>,
    init_static: Option<HexString>,
    init_ephemeral: HexString,
    init_remote_static: Option<HexString>,
    resp_prologue: HexString,
    resp_psk: Option<HexString>,
    resp_static: Option<HexString>,
    resp_ephemeral: Option<HexString>,
    resp_remote_static: Option<HexString>,
    handshake_hash: Option<HexString>,
    messages: Vec<Message>,
    fallback: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct Message {
    payload: HexString,
    ciphertext: HexString,
}

fn get_pattern_by_name(name: &str) -> Option<HandshakePattern> {
    match name {
        "N" => Some(noise_n()),
        "K" => Some(noise_k()),
        "X" => Some(noise_x()),
        "NN" => Some(noise_nn()),
        "NK" => Some(noise_nk()),
        "NX" => Some(noise_nx()),
        "KN" => Some(noise_kn()),
        "KK" => Some(noise_kk()),
        "KX" => Some(noise_kx()),
        "XN" => Some(noise_xn()),
        "XK" => Some(noise_xk()),
        "XX" => Some(noise_xx()),
        "IN" => Some(noise_in()),
        "IK" => Some(noise_ik()),
        "IX" => Some(noise_ix()),
        _ => None,
    }
}

fn to_dh<D>(k: &HexString) -> D::Key
    where D: DH
{
    D::Key::from_slice(k.to_bytes().as_slice())
}

fn to_pubkey<D>(k: &HexString) -> D::Pubkey
    where D: DH
{
    D::Pubkey::from_slice(k.to_bytes().as_slice())
}

fn verify_vector_with<D, C, H>(v: &Vector)
    where D: DH,
          C: Cipher,
          H: Hash
{
    if v.fallback.unwrap_or(false) {
        verify_vector_fallback::<D, C, H>(v);
        return;
    }

    let pattern = get_pattern_by_name(v.pattern.as_str());
    if pattern.is_none() {
        println!("Unknown pattern {}", v.pattern);
        return;
    }
    let pattern = pattern.unwrap();

    // Wow, that's quite some dancing to get to the right type...
    let ipsk = v.init_psk.as_ref().map(HexString::to_bytes);
    let ipsk = ipsk.as_ref().map(|x| x.as_slice());
    let rpsk = v.resp_psk.as_ref().map(HexString::to_bytes);
    let rpsk = rpsk.as_ref().map(|x| x.as_slice());

    let mut h_i = HandshakeState::<D, C, H>::new(pattern.clone(),
                                                 true,
                                                 v.init_prologue.to_bytes().as_slice(),
                                                 ipsk,
                                                 v.init_static.as_ref().map(to_dh::<D>),
                                                 Some(to_dh::<D>(&v.init_ephemeral)),
                                                 v.init_remote_static.as_ref().map(to_pubkey::<D>),
                                                 None);
    let mut h_r = HandshakeState::<D, C, H>::new(pattern,
                                                 false,
                                                 v.resp_prologue.to_bytes().as_slice(),
                                                 rpsk,
                                                 v.resp_static.as_ref().map(to_dh::<D>),
                                                 v.resp_ephemeral.as_ref().map(to_dh::<D>),
                                                 v.resp_remote_static.as_ref().map(to_pubkey::<D>),
                                                 None);

    let mut init_send = true;
    let mut handshake_completed = false;

    let mut init_ciphers = None;
    let mut resp_ciphers = None;

    for m in &v.messages {
        let payload = m.payload.to_bytes();
        let payload = payload.as_slice();
        let expected_ciphertext = m.ciphertext.to_bytes();
        let expected_ciphertext = expected_ciphertext.as_slice();

        if !handshake_completed {
            {
                let (h_send, h_recv) = if init_send {
                    (&mut h_i, &mut h_r)
                } else {
                    (&mut h_r, &mut h_i)
                };
                let c = h_send.write_message(payload);
                assert_eq!(c, expected_ciphertext);
                let p1 = h_recv.read_message(&c).unwrap();
                assert_eq!(p1, payload);
            }
            if h_i.completed() {
                assert!(h_r.completed());
                init_ciphers = Some(h_i.get_ciphers());
                resp_ciphers = Some(h_r.get_ciphers());
                if v.handshake_hash.is_some() {
                    assert_eq!(v.handshake_hash.as_ref().unwrap().to_bytes(),
                               h_i.get_hash());
                }
                handshake_completed = true;
            }
        } else {
            if init_send {
                let c = init_ciphers.as_mut().unwrap().0.encrypt_vec(payload);
                assert_eq!(c, expected_ciphertext);
                let p1 = resp_ciphers.as_mut().unwrap().0.decrypt_vec(&c).unwrap();
                assert_eq!(p1, payload);
            } else {
                let c = resp_ciphers.as_mut().unwrap().1.encrypt_vec(payload);
                assert_eq!(c, expected_ciphertext);
                let p1 = init_ciphers.as_mut().unwrap().1.decrypt_vec(&c).unwrap();
                assert_eq!(p1, payload);
            }
        }
        // Let the peer send if not a one-way pattern.
        if v.pattern.len() != 1 {
            init_send = !init_send;
        }
    }
}

fn verify_vector_fallback<D, C, H>(v: &Vector)
    where D: DH,
          C: Cipher,
          H: Hash
{
    assert_eq!(v.pattern, "IK");

    let iprologue = v.init_prologue.to_bytes();
    let ie = to_dh::<D>(&v.init_ephemeral);
    let is = to_dh::<D>(v.init_static.as_ref().unwrap());
    let irs = to_pubkey::<D>(v.init_remote_static.as_ref().unwrap());

    let rprologue = v.resp_prologue.to_bytes();
    let re = to_dh::<D>(v.resp_ephemeral.as_ref().unwrap());
    let rs = to_dh::<D>(v.resp_static.as_ref().unwrap());

    let ipsk = v.init_psk.as_ref().map(HexString::to_bytes);
    let ipsk = ipsk.as_ref().map(|x| x.as_slice());
    let rpsk = v.resp_psk.as_ref().map(HexString::to_bytes);
    let rpsk = rpsk.as_ref().map(|x| x.as_slice());

    // Build init handshake state.
    let mut ibuilder = HandshakeStateBuilder::<D>::new();
    ibuilder.set_is_initiator(true);
    ibuilder.set_pattern(noise_ik());
    ibuilder.set_prologue(&iprologue);
    if ipsk.is_some() {
        ibuilder.set_psk(ipsk.unwrap());
    }
    ibuilder.set_e(&ie);
    ibuilder.set_s(&is);
    ibuilder.set_rs(&irs);
    let mut ih0 = ibuilder.build_handshake_state::<C, H>();

    // Build resp handshake state.
    let mut rbuilder = HandshakeStateBuilder::<D>::new();
    rbuilder.set_is_initiator(false);
    rbuilder.set_pattern(noise_ik());
    rbuilder.set_prologue(&rprologue);
    if rpsk.is_some() {
        ibuilder.set_psk(rpsk.unwrap());
    }
    rbuilder.set_s(&rs);
    rbuilder.set_e(&re);
    let mut rh0 = rbuilder.build_handshake_state::<C, H>();

    // Abbreviated handshake (IK), should fail.
    let m0 = ih0.write_message(v.messages[0].payload.to_bytes().as_slice());
    assert_eq!(m0, v.messages[0].ciphertext.to_bytes().as_slice());

    assert!(rh0.read_message(&m0).is_err());

    // Build init handshake state.
    let mut ibuilder = HandshakeStateBuilder::<D>::new();
    ibuilder.set_is_initiator(true);
    ibuilder.set_pattern(noise_xx_fallback());
    ibuilder.set_prologue(&rprologue);
    if rpsk.is_some() {
        ibuilder.set_psk(rpsk.unwrap());
    }
    ibuilder.set_e(&re);
    ibuilder.set_s(&rs);
    ibuilder.set_re(&rh0.get_re().unwrap());
    let mut ih1 = ibuilder.build_handshake_state::<C, H>();

    // Build resp handshake state.
    let mut rbuilder = HandshakeStateBuilder::<D>::new();
    rbuilder.set_is_initiator(false);
    rbuilder.set_pattern(noise_xx_fallback());
    rbuilder.set_prologue(&iprologue);
    if ipsk.is_some() {
        rbuilder.set_psk(ipsk.unwrap());
    }
    rbuilder.set_s(&is);
    rbuilder.set_e(&ie);
    let mut rh1 = rbuilder.build_handshake_state::<C, H>();

    // Fallback handshake.
    let m1 = ih1.write_message(v.messages[1].payload.to_bytes().as_slice());
    assert_eq!(m1, v.messages[1].ciphertext.to_bytes());
    rh1.read_message(&m1).unwrap();

    let m2 = rh1.write_message(v.messages[2].payload.to_bytes().as_slice());
    assert_eq!(m2, v.messages[2].ciphertext.to_bytes());
    ih1.read_message(&m2).unwrap();

    assert!(ih1.completed());
    assert!(rh1.completed());

    if v.handshake_hash.is_some() {
        let h = v.handshake_hash.as_ref().unwrap().to_bytes();
        assert_eq!(h, ih1.get_hash());
        assert_eq!(h, rh1.get_hash());
    }

    // Transport messages.
    let mut i_should_send = true;
    let (mut isend, mut irecv) = ih1.get_ciphers();
    let (mut rrecv, mut rsend) = rh1.get_ciphers();

    for m in &v.messages[3..] {
        let (send, recv) = if i_should_send {
            (&mut isend, &mut rrecv)
        } else {
            (&mut rsend, &mut irecv)
        };

        let payload = m.payload.to_bytes();

        let c = send.encrypt_vec(&payload);
        assert_eq!(c, m.ciphertext.to_bytes());

        let m1 = recv.decrypt_vec(&c).unwrap();
        assert_eq!(m1, payload);

        i_should_send = !i_should_send;
    }
}

fn verify_vector(v: Vector) {
    match (v.dh.clone().as_ref(), v.cipher.clone().as_ref(), v.hash.clone().as_ref()) {
        // Poor man's dynamic dispatch?
        // XXX Someone please write a macro for this...
        ("25519", "ChaChaPoly", "SHA256") => {
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, crypto::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, crypto::Sha256>(&v);
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, ring::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, ring::Sha256>(&v);
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, sodium::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, sodium::Sha256>(&v);
        }
        ("25519", "ChaChaPoly", "SHA512") => {
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, crypto::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, crypto::Sha512>(&v);
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, ring::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, ring::Sha512>(&v);
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, sodium::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, sodium::Sha512>(&v);
        }
        ("25519", "ChaChaPoly", "BLAKE2s") => {
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, crypto::Blake2s>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, crypto::Blake2s>(&v);
        }
        ("25519", "ChaChaPoly", "BLAKE2b") => {
            verify_vector_with::<sodium::X25519, ring::ChaCha20Poly1305, crypto::Blake2b>(&v);
            verify_vector_with::<crypto::X25519, ring::ChaCha20Poly1305, crypto::Blake2b>(&v);
        }
        ("25519", "AESGCM", "SHA256") => {
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, crypto::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, crypto::Sha256>(&v);
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, ring::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, ring::Sha256>(&v);
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, sodium::Sha256>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, sodium::Sha256>(&v);
        }
        ("25519", "AESGCM", "SHA512") => {
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, crypto::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, crypto::Sha512>(&v);
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, ring::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, ring::Sha512>(&v);
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, sodium::Sha512>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, sodium::Sha512>(&v);
        }
        ("25519", "AESGCM", "BLAKE2s") => {
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, crypto::Blake2s>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, crypto::Blake2s>(&v);
        }
        ("25519", "AESGCM", "BLAKE2b") => {
            verify_vector_with::<sodium::X25519, ring::Aes256Gcm, crypto::Blake2b>(&v);
            verify_vector_with::<crypto::X25519, ring::Aes256Gcm, crypto::Blake2b>(&v);
        }
        // Curve448 is not supported (yet).
        ("448", _, _) => (),
        (dh, cipher, hash) => println!("Unknown combination: {}_{}_{}", dh, cipher, hash),
    }
}

#[test]
fn noise_c_basic_vectors() {
    let v: json::Value = json::from_str(include_str!("vectors/noise-c-basic.txt")).unwrap();
    let vectors: Vec<Vector> =
        json::from_value(v.as_object().unwrap().get("vectors").unwrap().clone()).unwrap();

    for v in vectors {
        verify_vector(v);
    }
}

#[test]
fn noise_c_fallback_vectors() {
    let v: json::Value = json::from_str(include_str!("vectors/noise-c-fallback.txt")).unwrap();
    let vectors: Vec<Vector> =
        json::from_value(v.as_object().unwrap().get("vectors").unwrap().clone()).unwrap();

    for v in vectors {
        verify_vector(v);
    }
}

#[test]
fn cacophony_vectors() {
    let v: json::Value = json::from_str(include_str!("vectors/cacophony.txt")).unwrap();
    let vectors: Vec<Vector> =
        json::from_value(v.as_object().unwrap().get("vectors").unwrap().clone()).unwrap();

    for v in vectors {
        verify_vector(v);
    }
}
