#!/usr/bin/python3

# This should probably be implemented as a Rust macro...

# And even if using python, it should be called from build.rs...

# For now, you have to run this manually...

# Sorry.

DHs = {
    "25519": ["sodium::X25519", "crypto::X25519"],
}

Ciphers = {
    "ChaChaPoly": ["ring::ChaCha20Poly1305"],
    "AESGCM": ["ring::Aes256Gcm"],
}

Hashes = {
    "SHA256": ["crypto::Sha256", "ring::Sha256", "sodium::Sha256"],
    "SHA512": ["crypto::Sha512", "ring::Sha512", "sodium::Sha512"],
    "BLAKE2s": ["crypto::Blake2s"],
    "BLAKE2b": ["crypto::Blake2b", "sodium::Blake2b"],
}

print("""fn verify_vector(v: Vector) {
    match (v.dh.clone().as_ref(), v.cipher.clone().as_ref(), v.hash.clone().as_ref()) {
        // Poor man's dynamic dispatch?
        // XXX Someone please write a macro for this...""")

for d in DHs:
    for c in Ciphers:
        for h in Hashes:
            print('        ("{}", "{}", "{}") => {{'.format(d, c, h))
            for hh in Hashes[h]:
                for cc in Ciphers[c]:
                    for dd in DHs[d]:
                        print('            verify_vector_with::<{}, {}, {}>(&v);'.format(dd, cc, hh))
            print('        }')

print("""        // Curve448 is not supported (yet).
        ("448", _, _) => (),
        (dh, cipher, hash) => println!("Unknown combination: {}_{}_{}", dh, cipher, hash),
    }
}""")
