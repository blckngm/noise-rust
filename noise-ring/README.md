This crate is deprecated.

Although *ring* contains implementations of X25519, AES-256-GCM and
ChaCha20-Poly1305, it does not expose compatible APIs for them: the
agreement API for X25519 only supports ephemeral keys; and the AEAD
APIs only supports in-place encryption/decryption.

The only remaining useful primitives are sha-256 and sha-512.
