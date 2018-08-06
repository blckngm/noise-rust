// Program to verify the vectors.

// Recommanded to run with:
// $ RUST_BACKTRACE=1 cargo test  -- --nocapture --test-threads=1

extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate noise_protocol as noise;
extern crate noise_ring;
extern crate noise_rust_crypto;
extern crate noise_sodiumoxide;
extern crate rayon;
extern crate regex;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use noise::patterns::*;
use noise::*;
use noise_ring as ring;
use noise_rust_crypto as crypto;
use noise_sodiumoxide as sodium;

use hex::{decode, encode};
use rayon::prelude::*;
use regex::Regex;
use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json as json;
use std::ops::Deref;

struct HexString(Vec<u8>);

impl Deref for HexString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl AsRef<[u8]> for HexString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(d)?;
        let v = decode(&s)
            .map_err(|_e| D::Error::invalid_value(Unexpected::Str(&s), &"string in hex "))?;
        Ok(HexString(v))
    }
}

impl Serialize for HexString {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        encode(&self.0).serialize(s)
    }
}

fn fn_false() -> bool {
    false
}

fn fn_empty_vec<T>() -> Vec<T> {
    vec![]
}

// See <https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors> for test
// vectors format spec.
#[derive(Serialize, Deserialize)]
struct Vector {
    name: Option<String>,
    protocol_name: String,
    hybrid: Option<String>,
    #[serde(default = "fn_false")]
    fail: bool,

    // pattern: String,
    // dh: String,
    // cipher: String,
    // hash: String,
    #[serde(default = "fn_false")]
    fallback: bool,
    fallback_pattern: Option<String>,

    init_prologue: HexString,
    #[serde(default = "fn_empty_vec")]
    init_psks: Vec<HexString>,
    init_static: Option<HexString>,
    init_ephemeral: HexString,
    init_remote_static: Option<HexString>,
    resp_prologue: HexString,
    #[serde(default = "fn_empty_vec")]
    resp_psks: Vec<HexString>,
    resp_static: Option<HexString>,
    resp_ephemeral: Option<HexString>,
    resp_remote_static: Option<HexString>,
    handshake_hash: Option<HexString>,
    messages: Vec<Message>,
}

impl Vector {
    /// Parse protocol name and returns pattern, dh, cipher and hash names.
    fn parse_protocol_name<'a>(&'a self) -> (&'a str, &'a str, &'a str, &'a str) {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"Noise_([[:alnum:]\+]+)_([[:alnum:]]+)_([[:alnum:]]+)_([[:alnum:]]+)")
                    .unwrap();
        }
        let caps = RE.captures(&self.protocol_name).unwrap();
        (
            caps.get(1).unwrap().as_str(),
            caps.get(2).unwrap().as_str(),
            caps.get(3).unwrap().as_str(),
            caps.get(4).unwrap().as_str(),
        )
    }
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
where
    D: DH,
{
    D::Key::from_slice(k.as_ref())
}

fn to_pubkey<D>(k: &HexString) -> D::Pubkey
where
    D: DH,
{
    D::Pubkey::from_slice(k.as_ref())
}

fn verify_vector_with<D, C, H>(v: &Vector) -> bool
where
    D: DH,
    C: Cipher,
    H: Hash,
{
    if v.fallback {
        return verify_vector_fallback::<D, C, H>(v);
    }

    let (pattern_name, _, _, _) = v.parse_protocol_name();
    let pattern = get_pattern_by_name(pattern_name);
    if pattern.is_none() {
        // println!("Unknown pattern {}", pattern_name);
        return false;
    }
    let pattern = pattern.unwrap();

    let mut h_i = HandshakeState::<D, C, H>::new(
        pattern.clone(),
        true,
        v.init_prologue.as_ref(),
        v.init_static.as_ref().map(to_dh::<D>),
        Some(to_dh::<D>(&v.init_ephemeral)),
        v.init_remote_static.as_ref().map(to_pubkey::<D>),
        None,
    );
    let mut h_r = HandshakeState::<D, C, H>::new(
        pattern,
        false,
        v.resp_prologue.as_ref(),
        v.resp_static.as_ref().map(to_dh::<D>),
        v.resp_ephemeral.as_ref().map(to_dh::<D>),
        v.resp_remote_static.as_ref().map(to_pubkey::<D>),
        None,
    );

    let mut init_send = true;
    let mut handshake_completed = false;

    let mut init_ciphers = None;
    let mut resp_ciphers = None;

    for m in &v.messages {
        let payload = m.payload.as_ref();
        let expected_ciphertext = m.ciphertext.as_ref();

        if !handshake_completed {
            {
                let (h_send, h_recv) = if init_send {
                    (&mut h_i, &mut h_r)
                } else {
                    (&mut h_r, &mut h_i)
                };
                let overhead = h_send.get_next_message_overhead();
                assert_eq!(payload.len() + overhead, expected_ciphertext.len());
                let c = h_send.write_message_vec(payload).unwrap();
                assert_eq!(c, expected_ciphertext);
                let p1 = h_recv.read_message_vec(&c).unwrap();
                assert_eq!(p1, payload);
            }
            if h_i.completed() {
                assert!(h_r.completed());
                init_ciphers = Some(h_i.get_ciphers());
                resp_ciphers = Some(h_r.get_ciphers());
                if v.handshake_hash.is_some() {
                    assert_eq!(v.handshake_hash.as_ref().unwrap().as_ref(), h_i.get_hash());
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
        if pattern_name.len() != 1 {
            init_send = !init_send;
        }
    }

    true
}

fn verify_vector_fallback<D, C, H>(v: &Vector) -> bool
where
    D: DH,
    C: Cipher,
    H: Hash,
{
    assert_eq!(v.parse_protocol_name().0, "IK");

    let iprologue = v.init_prologue.as_ref();
    let ie = to_dh::<D>(&v.init_ephemeral);
    let is = to_dh::<D>(v.init_static.as_ref().unwrap());
    let irs = to_pubkey::<D>(v.init_remote_static.as_ref().unwrap());

    let rprologue = v.resp_prologue.as_ref();
    let re = to_dh::<D>(v.resp_ephemeral.as_ref().unwrap());
    let rs = to_dh::<D>(v.resp_static.as_ref().unwrap());

    // Build init handshake state.
    let mut ibuilder = HandshakeStateBuilder::<D>::new();
    ibuilder.set_is_initiator(true);
    ibuilder.set_pattern(noise_ik());
    ibuilder.set_prologue(&iprologue);
    ibuilder.set_e(ie.clone());
    ibuilder.set_s(is.clone());
    ibuilder.set_rs(irs);
    let mut ih0 = ibuilder.build_handshake_state::<C, H>();

    // Build resp handshake state.
    let mut rbuilder = HandshakeStateBuilder::<D>::new();
    rbuilder.set_is_initiator(false);
    rbuilder.set_pattern(noise_ik());
    rbuilder.set_prologue(&rprologue);
    rbuilder.set_s(rs.clone());
    rbuilder.set_e(re.clone());
    let mut rh0 = rbuilder.build_handshake_state::<C, H>();

    // Abbreviated handshake (IK), should fail.
    let m0 = ih0
        .write_message_vec(v.messages[0].payload.as_ref())
        .unwrap();
    assert_eq!(m0, v.messages[0].ciphertext.as_ref());

    assert!(rh0.read_message_vec(&m0).is_err());

    // Build init handshake state.
    let mut ibuilder = HandshakeStateBuilder::<D>::new();
    ibuilder.set_is_initiator(true);
    ibuilder.set_pattern(noise_xx_fallback());
    ibuilder.set_prologue(&rprologue);
    ibuilder.set_e(re);
    ibuilder.set_s(rs);
    ibuilder.set_re(rh0.get_re().unwrap());
    let mut ih1 = ibuilder.build_handshake_state::<C, H>();

    // Build resp handshake state.
    let mut rbuilder = HandshakeStateBuilder::<D>::new();
    rbuilder.set_is_initiator(false);
    rbuilder.set_pattern(noise_xx_fallback());
    rbuilder.set_prologue(&iprologue);
    rbuilder.set_s(is);
    rbuilder.set_e(ie);
    let mut rh1 = rbuilder.build_handshake_state::<C, H>();

    // Fallback handshake.
    let m1 = ih1
        .write_message_vec(v.messages[1].payload.as_ref())
        .unwrap();
    assert_eq!(m1, v.messages[1].ciphertext.as_ref());
    rh1.read_message_vec(&m1).unwrap();

    let m2 = rh1
        .write_message_vec(v.messages[2].payload.as_ref())
        .unwrap();
    assert_eq!(m2, v.messages[2].ciphertext.as_ref());
    ih1.read_message_vec(&m2).unwrap();

    assert!(ih1.completed());
    assert!(rh1.completed());

    if v.handshake_hash.is_some() {
        let h = v.handshake_hash.as_ref().unwrap().as_ref();
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

        let payload = m.payload.as_ref();

        let c = send.encrypt_vec(&payload);
        assert_eq!(c, m.ciphertext.as_ref());

        let m1 = recv.decrypt_vec(&c).unwrap();
        assert_eq!(m1, payload);

        i_should_send = !i_should_send;
    }

    true
}

include!(concat!(env!("OUT_DIR"), "/crypto_impls.rs"));

fn verify_vectors(json_vectors: &str) {
    let v: json::Value = json::from_str(json_vectors).unwrap();
    let vectors: Vec<Vector> =
        json::from_value(v.as_object().unwrap().get("vectors").unwrap().clone()).unwrap();
    let vectors_len = vectors.len();

    let (verified, skipped): (Vec<_>, Vec<_>) = vectors.into_par_iter().partition_map(|v| {
        let n = v.protocol_name.clone();
        if verify_vector(v) {
            ::rayon::iter::Either::Left(n)
        } else {
            ::rayon::iter::Either::Right(n)
        }
    });

    println!(
        "Verified {}/{}, {:.2}%.\n",
        verified.len(),
        vectors_len,
        verified.len() as f32 / vectors_len as f32 * 100f32
    );
    println!("Verified:");
    for v in &verified {
        println!("  {:?}", v)
    }
    println!("\nSkipped:");
    for s in &skipped {
        println!("  {:?}", s)
    }
}

#[test]
fn cacophony_vectors() {
    println!("Verifying cacophony.txt:\n");
    verify_vectors(include_str!("vectors/cacophony.txt"));
}

#[test]
fn snow_multipsk() {
    println!("Verifying snow-multipsk.txt:\n");
    verify_vectors(include_str!("vectors/snow-multipsk.txt"));
}
