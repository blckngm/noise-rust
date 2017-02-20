// Program to verify the vectors.

extern crate noise;
extern crate serde;
extern crate rustc_serialize;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use noise::*;
use noise::algorithms::*;
use noise::patterns::*;
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

fn to_dh<D>(k: &HexString) -> D
    where D: DH
{
    D::new(k.to_bytes().as_slice())
}

fn verify_vector_with<D, C, H>(v: Vector)
    where D: DH,
          C: Cipher,
          H: Hash
{
    let pattern = get_pattern_by_name(v.pattern.as_str());
    if pattern.is_none() {
        println!("Unknown pattern {}", v.pattern);
        return;
    }
    let pattern = pattern.unwrap();

    let mut h_i =
        HandshakeState::<D, C, H>::new(pattern.clone(),
                                       true,
                                       v.init_prologue.to_bytes().as_slice(),
                                       v.init_psk.as_ref().map(HexString::to_bytes),
                                       v.init_static.as_ref().map(to_dh),
                                       Some(to_dh(&v.init_ephemeral)),
                                       v.init_remote_static.as_ref().map(HexString::to_bytes),
                                       None);
    let mut h_r =
        HandshakeState::<D, C, H>::new(pattern,
                                       false,
                                       v.resp_prologue.to_bytes().as_slice(),
                                       v.resp_psk.as_ref().map(HexString::to_bytes),
                                       v.resp_static.as_ref().map(to_dh),
                                       v.resp_ephemeral.as_ref().map(to_dh),
                                       v.resp_remote_static.as_ref().map(HexString::to_bytes),
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
        if v.pattern.len() == 2 {
            init_send = !init_send;
        }
    }
}

fn verify_vector(v: Vector) {
    match (v.dh.clone().as_ref(), v.cipher.clone().as_ref(), v.hash.clone().as_ref()) {
        // Poor man's dynamic dispatch?
        ("25519", "ChaChaPoly", "SHA256") => {
            verify_vector_with::<X25519, ChaCha20Poly1305, Sha256>(v)
        }
        ("25519", "ChaChaPoly", "SHA512") => {
            verify_vector_with::<X25519, ChaCha20Poly1305, Sha512>(v)
        }
        ("25519", "ChaChaPoly", "BLAKE2s") => {
            verify_vector_with::<X25519, ChaCha20Poly1305, Blake2s>(v)
        }
        ("25519", "ChaChaPoly", "BLAKE2b") => {
            verify_vector_with::<X25519, ChaCha20Poly1305, Blake2b>(v)
        }
        ("25519", "AESGCM", "SHA256") => verify_vector_with::<X25519, Aes256Gcm, Sha256>(v),
        ("25519", "AESGCM", "SHA512") => verify_vector_with::<X25519, Aes256Gcm, Sha512>(v),
        ("25519", "AESGCM", "BLAKE2s") => verify_vector_with::<X25519, Aes256Gcm, Blake2s>(v),
        ("25519", "AESGCM", "BLAKE2b") => verify_vector_with::<X25519, Aes256Gcm, Blake2b>(v),
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
fn cacophony_vectors() {
    let v: json::Value = json::from_str(include_str!("vectors/cacophony.txt")).unwrap();
    let vectors: Vec<Vector> =
        json::from_value(v.as_object().unwrap().get("vectors").unwrap().clone()).unwrap();

    for v in vectors {
        verify_vector(v);
    }
}
