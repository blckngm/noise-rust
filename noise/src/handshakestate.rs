use cipherstate::CipherState;
use error::NoiseError;
use handshakepattern::{Token, HandshakePattern};
use symmetricstate::SymmetricState;
use traits::{DH, Cipher, Hash, U8Array};

/// Noise handshake state.
///
/// # Panics
///
/// `HandshakeState` must be used correctly, or its methods will likely panic:
///
/// Keys required by the handshake pattern must be set;
///
/// `write_message` and `read_message` must be called in right turns;
///
/// `write_message` and `read_message` must not be called after `completed`.
pub struct HandshakeState<D: DH, C: Cipher, H: Hash> {
    symmetric: SymmetricState<C, H>,
    s: Option<D::Key>,
    e: Option<D::Key>,
    rs: Option<D::Pubkey>,
    re: Option<D::Pubkey>,
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
               psk: Option<&[u8]>,
               s: Option<D::Key>,
               e: Option<D::Key>,
               rs: Option<D::Pubkey>,
               re: Option<D::Pubkey>)
               -> Self {
        let mut symmetric = SymmetricState::new(Self::get_name(psk.is_some(), pattern.get_name())
            .as_bytes());

        // Mix in prologue.
        symmetric.mix_hash(prologue);

        // Mix in pre-shared key.
        if let Some(psk) = psk {
            assert_eq!(psk.len(), 32);
            symmetric.mix_preshared_key(psk);
        }

        // Mix in static keys known ahead of time.
        for t in pattern.get_pre_i() {
            match *t {
                Token::S => {
                    if is_initiator {
                        symmetric.mix_hash(D::pubkey(s.as_ref().unwrap()).as_slice());
                    } else {
                        symmetric.mix_hash(rs.as_ref().unwrap().as_slice());
                    }
                }
                Token::E => {
                    if is_initiator {
                        let e = D::pubkey(e.as_ref().unwrap());
                        symmetric.mix_hash(e.as_slice());
                        if symmetric.has_preshared_key() {
                            symmetric.mix_key(e.as_slice());
                        }
                    } else {
                        let re = re.as_ref().unwrap().as_slice();
                        symmetric.mix_hash(re);
                        if symmetric.has_preshared_key() {
                            symmetric.mix_key(re);
                        }
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
                        symmetric.mix_hash(D::pubkey(s.as_ref().unwrap()).as_slice());
                    }
                }
                Token::E => {
                    if is_initiator {
                        let re = re.as_ref().unwrap().as_slice();
                        symmetric.mix_hash(re);
                        if symmetric.has_preshared_key() {
                            symmetric.mix_key(re);
                        }
                    } else {
                        let e = D::pubkey(e.as_ref().unwrap());
                        symmetric.mix_hash(e.as_slice());
                        if symmetric.has_preshared_key() {
                            symmetric.mix_key(e.as_slice());
                        }
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
                    let e_pk = D::pubkey(self.e.as_ref().unwrap());
                    self.symmetric.mix_hash(e_pk.as_slice());
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(e_pk.as_slice());
                    }
                    out.extend_from_slice(e_pk.as_slice());
                }
                Token::S => {
                    let encrypted_s = self.symmetric
                        .encrypt_and_hash_vec(D::pubkey(self.s.as_ref().unwrap()).as_slice());
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
    /// should not be used any more. Expect to `get_re` before falling back to `XXfallback`.
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
                    let mut re = D::Pubkey::new();
                    re.as_mut().copy_from_slice(get(D::pub_len())?);
                    self.symmetric.mix_hash(re.as_slice());
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(re.as_slice());
                    }
                    self.re = Some(re);
                }
                Token::S => {
                    let temp = get(if self.symmetric.has_key() {
                        D::pub_len() + 16
                    } else {
                        D::pub_len()
                    })?;
                    let mut rs = D::Pubkey::new();
                    self.symmetric.decrypt_and_hash(temp, rs.as_mut())?;
                    self.rs = Some(rs);
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

    /// Get remote static pubkey, if available.
    pub fn get_rs(&self) -> Option<D::Pubkey> {
        self.rs
    }

    /// Get remote semi-ephemeral pubkey.
    ///
    /// Returns `None` if we do not know.
    ///
    /// Useful for noise-pipes.
    pub fn get_re(&self) -> Option<D::Pubkey> {
        self.re
    }

    fn perform_dh(&mut self, t: Token) {
        let dh = |a: Option<&D::Key>, b: Option<&D::Pubkey>| D::dh(a.unwrap(), b.unwrap());

        let k = match t {
            Token::EE => dh(self.e.as_ref(), self.re.as_ref()),
            Token::ES => {
                if self.is_initiator {
                    dh(self.e.as_ref(), self.rs.as_ref())
                } else {
                    dh(self.s.as_ref(), self.re.as_ref())
                }
            }
            Token::SE => {
                if self.is_initiator {
                    dh(self.s.as_ref(), self.re.as_ref())
                } else {
                    dh(self.e.as_ref(), self.rs.as_ref())
                }
            }
            Token::SS => dh(self.s.as_ref(), self.rs.as_ref()),
            _ => unreachable!(),
        };

        self.symmetric.mix_key(k.as_slice());
    }
}

/// Builder for `HandshakeState`.
pub struct HandshakeStateBuilder<'a, D: DH> {
    pattern: Option<HandshakePattern>,
    is_initiator: Option<bool>,
    prologue: Option<&'a [u8]>,
    psk: Option<&'a [u8]>,
    s: Option<D::Key>,
    e: Option<D::Key>,
    rs: Option<D::Pubkey>,
    re: Option<D::Pubkey>,
}

impl<'a, D> HandshakeStateBuilder<'a, D>
    where D: DH
{
    pub fn new() -> Self {
        HandshakeStateBuilder {
            pattern: None,
            is_initiator: None,
            prologue: None,
            psk: None,
            s: None,
            e: None,
            rs: None,
            re: None,
        }
    }

    pub fn set_pattern(&mut self, p: HandshakePattern) -> &mut Self {
        self.pattern = Some(p);
        self
    }

    pub fn set_is_initiator(&mut self, is: bool) -> &mut Self {
        self.is_initiator = Some(is);
        self
    }

    pub fn set_prologue(&mut self, prologue: &'a [u8]) -> &mut Self {
        self.prologue = Some(prologue);
        self
    }

    pub fn set_psk(&mut self, psk: &'a [u8]) -> &mut Self {
        self.psk = Some(psk);
        self
    }

    pub fn set_e(&mut self, e: &D::Key) -> &mut Self {
        self.e = Some(*e);
        self
    }

    pub fn set_s(&mut self, s: &D::Key) -> &mut Self {
        self.s = Some(*s);
        self
    }

    pub fn set_re(&mut self, re: &D::Pubkey) -> &mut Self {
        self.re = Some(*re);
        self
    }

    pub fn set_rs(&mut self, rs: &D::Pubkey) -> &mut Self {
        self.rs = Some(*rs);
        self
    }

    /// Build `HandshakeState`.
    ///
    /// # Panics
    ///
    /// `pattern`, `prologue` and `is_initiator` must be set.
    pub fn build_handshake_state<C, H>(&self) -> HandshakeState<D, C, H>
        where C: Cipher,
              H: Hash
    {
        HandshakeState::new(self.pattern.as_ref().unwrap().clone(),
                            self.is_initiator.unwrap(),
                            self.prologue.unwrap(),
                            self.psk,
                            self.s,
                            self.e,
                            self.rs,
                            self.re)
    }
}
