use cipherstate::CipherState;
use error::NoiseError;
use handshakepattern::{Token, HandshakePattern};
use symmetricstate::SymmetricState;
use traits::{DH, Cipher, Hash};

/// Noise handshake state.
///
/// Typically, you call `HandshakeState::new()` to initialize a `HandshakeState`, then call
/// `write_message` and `read_message` to complete the handshake. Once the handshake is `completed`,
/// you call `get_ciphers` to get ciphers that can be used to encrypt/decrypt further messages.
pub struct HandshakeState<D, C, H> {
    symmetric: SymmetricState<C, H>,
    s: Option<D>,
    e: Option<D>,
    rs: Option<Vec<u8>>,
    re: Option<Vec<u8>>,
    is_initiator: bool,
    pattern: HandshakePattern,
    message_index: usize,
}

impl<D, C, H> HandshakeState<D, C, H>
    where D: DH,
          C: Cipher,
          H: Hash
{
    /// Get protocol name, e.g. Noise_IK_25519_ChaChaPoly_BLAKE2s.
    pub fn get_name(has_psk: bool, pattern_name: &str) -> String {
        format!("Noise{}_{}_{}_{}_{}",
                if has_psk { "PSK" } else { "" },
                pattern_name,
                D::name(),
                C::name(),
                H::name())
    }

    /// Initialize a handshake state.
    ///
    /// `HandshakeState` does not generate a new ephemeral key when seeing a `E` toekn (for now?).
    pub fn new(pattern: HandshakePattern,
               is_initiator: bool,
               prologue: &[u8],
               psk: Option<Vec<u8>>,
               s: Option<D>,
               e: Option<D>,
               rs: Option<Vec<u8>>,
               re: Option<Vec<u8>>)
               -> Self {
        let mut symmetric = SymmetricState::new(Self::get_name(psk.is_some(), pattern.get_name())
            .as_bytes());

        // Mix in prologue.
        symmetric.mix_hash(prologue);

        // Mix in pre-shared key.
        if let Some(psk) = psk {
            assert_eq!(psk.len(), 32);
            symmetric.mix_preshared_key(&psk);
        }

        // Mix in static keys known ahead of time.
        for t in pattern.get_pre_i() {
            match *t {
                Token::S => {
                    if is_initiator {
                        symmetric.mix_hash(s.as_ref().unwrap().get_pubkey_vec().as_slice());
                    } else {
                        symmetric.mix_hash(rs.as_ref().unwrap().as_slice());
                    }
                }
                _ => panic!("Unexpected token in pre message"),
            }
        }
        for t in pattern.get_pre_r() {
            match *t {
                Token::S => {
                    if is_initiator {
                        symmetric.mix_hash(rs.as_ref().unwrap().as_slice());
                    } else {
                        symmetric.mix_hash(s.as_ref().unwrap().get_pubkey_vec().as_slice());
                    }
                }
                _ => panic!("Unexpected token in pre message"),
            }
        }

        HandshakeState {
            symmetric: symmetric,
            s: s,
            e: e,
            rs: rs,
            re: re,
            is_initiator: is_initiator,
            pattern: pattern,
            message_index: 0,
        }
    }

    /// Takes a payload and return a packet that you should send to the peer.
    pub fn write_message(&mut self, payload: &[u8]) -> Vec<u8> {
        // Check that it is our turn to send.
        assert!(self.message_index % 2 == if self.is_initiator { 0 } else { 1 });

        // Get the message pattern.
        // Clone to make the borrow check happy.
        let m = self.pattern.get_message_patterns()[self.message_index].clone();
        self.message_index += 1;

        let mut out = Vec::new();

        // Process tokens.
        for t in m {
            match t {
                Token::E => {
                    // Spec says that we should generate new ephemeral key, but that would make
                    // testing very difficult.
                    let e_pk = self.e.as_ref().unwrap().get_pubkey_vec();
                    self.symmetric.mix_hash(&e_pk);
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(&e_pk);
                    }
                    out.extend_from_slice(&e_pk);
                }
                Token::S => {
                    let encrypted_s = self.symmetric
                        .encrypt_and_hash_vec(self.s.as_ref().unwrap().get_pubkey_vec().as_slice());
                    out.extend_from_slice(&encrypted_s);
                }
                t => self.perform_dh(t),
            }
        }

        let encrypted_payload = self.symmetric.encrypt_and_hash_vec(payload);
        out.extend_from_slice(&encrypted_payload);

        out
    }

    /// Update handshake state and get payload, given a packet.
    ///
    /// If the packet fails to decrypt, the whole HandshakeState may be in invalid state, and
    /// should not be used any more.
    pub fn read_message(&mut self, data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        // Check that it is our turn to recv.
        assert!(self.message_index % 2 == if self.is_initiator { 1 } else { 0 });

        // Get the message pattern.
        let m = self.pattern.get_message_patterns()[self.message_index].clone();
        self.message_index += 1;

        let mut data = data;
        // Consume the next `n` bytes of data.
        let mut get = |n| if data.len() >= n {
            let ret = &data[..n];
            data = &data[n..];
            Ok(ret)
        } else {
            Err(NoiseError::TooShort)
        };

        // Process tokens.
        for t in m {
            match t {
                Token::E => {
                    let re: Vec<_> = get(D::pub_len())?.iter().cloned().collect();
                    self.symmetric.mix_hash(&re);
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(&re);
                    }
                    self.re = Some(re);
                }
                Token::S => {
                    let temp = get(if self.symmetric.has_key() {
                        D::pub_len() + 16
                    } else {
                        D::pub_len()
                    })?;
                    self.rs = Some(self.symmetric.decrypt_and_hash_vec(temp)?);
                }
                t => self.perform_dh(t),
            }
        }

        Ok(self.symmetric.decrypt_and_hash_vec(data)?)
    }

    /// Whether handshake has completed.
    pub fn completed(&self) -> bool {
        self.message_index == self.pattern.get_message_patterns().len()
    }

    /// Get handshake hash. Useful for e.g., channel binding.
    ///
    /// Should be called after handshake is `completed()`.
    pub fn get_hash(&self) -> &[u8] {
        self.symmetric.get_hash()
    }

    /// Get ciphers that can be used to encrypt/decrypt furthur messages.
    /// The first `CiperState` is for initiator to responder, and the second for responder
    /// to initiator.
    ///
    /// Should be called after handshake is `completed()`.
    pub fn get_ciphers(&self) -> (CipherState<C>, CipherState<C>) {
        self.symmetric.split()
    }

    fn perform_dh(&mut self, t: Token) {
        match t {
            Token::EE => {
                let k = self.e.as_ref().unwrap().dh_vec(self.re.as_ref().unwrap().as_slice());
                self.symmetric.mix_key(&k);
            }
            Token::ES => {
                let k = if self.is_initiator {
                    self.e.as_ref().unwrap().dh_vec(self.rs.as_ref().unwrap().as_slice())
                } else {
                    self.s.as_ref().unwrap().dh_vec(self.re.as_ref().unwrap().as_slice())
                };
                self.symmetric.mix_key(&k);
            }
            Token::SE => {
                let k = if self.is_initiator {
                    self.s.as_ref().unwrap().dh_vec(self.re.as_ref().unwrap().as_slice())
                } else {
                    self.e.as_ref().unwrap().dh_vec(self.rs.as_ref().unwrap().as_slice())
                };
                self.symmetric.mix_key(&k);
            }
            Token::SS => {
                let k = self.s.as_ref().unwrap().dh_vec(self.rs.as_ref().unwrap().as_slice());
                self.symmetric.mix_key(&k);
            }
            _ => unreachable!(),
        }
    }
}
