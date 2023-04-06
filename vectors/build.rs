// build.rs

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate the crypto implementations dispatch function.
fn gen<O: Write>(mut out: O) -> ::std::io::Result<()> {
    let mut dhs = HashMap::new();
    dhs.insert("25519", vec!["crypto::X25519"]);

    let mut ciphers = HashMap::new();
    ciphers.insert(
        "ChaChaPoly",
        vec!["crypto::ChaCha20Poly1305", "ring_crypto::ChaCha20Poly1305"],
    );
    ciphers.insert(
        "AESGCM",
        vec!["crypto::Aes256Gcm", "ring_crypto::Aes256Gcm"],
    );

    let mut hashes: HashMap<&str, Vec<&str>> = HashMap::new();
    hashes.insert("SHA256", vec!["crypto::Sha256", "ring_crypto::Sha256"]);
    hashes.insert("SHA512", vec!["crypto::Sha512", "ring_crypto::Sha512"]);
    hashes.insert("BLAKE2s", vec!["crypto::Blake2s"]);
    hashes.insert("BLAKE2b", vec!["crypto::Blake2b"]);

    writeln!(out, "fn verify_vector(v: Vector) -> bool {{")?;
    writeln!(
        out,
        "    let (_, dh, cipher, hash) = v.parse_protocol_name();"
    )?;
    writeln!(out, "    match (dh, cipher, hash) {{")?;

    for d in dhs.keys() {
        for c in ciphers.keys() {
            for h in hashes.keys() {
                writeln!(out, r#"        ("{}", "{}", "{}") => {{"#, d, c, h)?;
                writeln!(out, r#"        ["#)?;
                for hh in hashes.get(h).unwrap() {
                    for cc in ciphers.get(c).unwrap() {
                        for dd in dhs.get(d).unwrap() {
                            writeln!(
                                out,
                                "            verify_vector_with::<{}, {}, {}>(&v),",
                                dd, cc, hh
                            )?;
                        }
                    }
                }
                writeln!(out, r#"        ].iter().any(|x| *x)"#)?;
                writeln!(out, "        }}")?;
            }
        }
    }

    writeln!(
        out,
        r#"        _ => false,
    }}
}}"#
    )?;

    Ok(())
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("crypto_impls.rs");
    let out_file = File::create(&dest_path).unwrap();

    gen(out_file).unwrap();
}
