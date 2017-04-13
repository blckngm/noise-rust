extern crate arrayvec;
extern crate core;

use self::arrayvec::ArrayString;
use self::core::fmt::Write;
use cipherstate::CipherState;
use handshakepattern::{Token, HandshakePattern};
use symmetricstate::SymmetricState;
use traits::{DH, Cipher, Hash, U8Array};

/// Noise handshake state.
///
/// # Panics
///
/// `HandshakeState` must be used correctly, or its methods will likely panic:
///
/// Static keys required by the handshake pattern must be set;
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

impl<D, C, H> Clone for HandshakeState<D, C, H>
    where D: DH, C: Cipher, H: Hash
{
    fn clone(&self) -> Self {
        Self {
            symmetric: self.symmetric.clone(),
            s: self.s.as_ref().map(U8Array::clone),
            e: self.e.as_ref().map(U8Array::clone),
            rs: self.rs.as_ref().map(U8Array::clone),
            re: self.re.as_ref().map(U8Array::clone),
            is_initiator: self.is_initiator,
            pattern: self.pattern.clone(),
            message_index: self.message_index,
        }
    }
}

impl<D, C, H> HandshakeState<D, C, H>
    where D: DH,
          C: Cipher,
          H: Hash
{
    /// Get protocol name, e.g. Noise_IK_25519_ChaChaPoly_BLAKE2s.
    fn get_name(has_psk: bool, pattern_name: &str) -> ArrayString<[u8; 256]> {
        let mut ret = ArrayString::new();
        write!(&mut ret, "Noise{}_{}_{}_{}_{}",
               if has_psk { "PSK" } else { "" },
               pattern_name,
               D::name(),
               C::name(),
               H::name()).unwrap();
        ret
    }

    /// Initialize a handshake state.
    ///
    /// If `e` is `None`, a new ephemeral key will be generated if necessary when `write_message`.
    ///
    /// An explicit `e` should only be specified for testing purposes, or in fallback patterns.
    /// If you do pass in an explicit `e`, `HandshakeState` will use it as is and will not
    /// generate new ephemeral keys in `write_message`.
    pub fn new<P, PSK>(pattern: HandshakePattern,
                       is_initiator: bool,
                       prologue: P,
                       psk: Option<PSK>,
                       s: Option<D::Key>,
                       e: Option<D::Key>,
                       rs: Option<D::Pubkey>,
                       re: Option<D::Pubkey>)
                       -> Self
        where P: AsRef<[u8]>,
              PSK: AsRef<[u8]>
    {
        let mut symmetric = SymmetricState::new(Self::get_name(psk.is_some(), pattern.get_name())
            .as_bytes());

        // Mix in prologue.
        symmetric.mix_hash(prologue.as_ref());

        // Mix in pre-shared key.
        if let Some(psk) = psk {
            let psk = psk.as_ref();
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

    /// Calculate the size overhead of the next message.
    ///
    /// # Panics
    ///
    /// If these is no more message to read/write, i.e.,
    /// if the handshake is already completed.
    pub fn get_next_message_overhead(&self) -> usize {
        let m = self.pattern.get_message_pattern(self.message_index);

        let mut overhead = 0;

        let mut has_key = self.symmetric.has_key();

        for &t in m {
            match t {
                Token::E => {
                    overhead += D::Pubkey::len();
                    if self.symmetric.has_preshared_key() {
                        has_key = true;
                    }
                }
                Token::S => {
                    overhead += D::Pubkey::len();
                    if has_key {
                        overhead += 16;
                    }
                }
                _ => {
                    has_key = true;
                }
            }
        }

        if has_key {
            overhead += 16
        }

        overhead
    }

    /// Like `write_message`, but returns a `Vec`.
    #[cfg(feature = "use_std")]
    pub fn write_message_vec(&mut self, payload: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = vec![0u8; payload.len() + self.get_next_message_overhead()];
        self.write_message(payload, &mut out)?;
        Ok(out)
    }

    /// Takes a payload and write the generated handshake message to
    /// `out`.
    ///
    /// This method will fail (returns `Err`) iff DH function fails,
    /// due to, e.g., invalid public keys.
    ///
    /// # Panics
    ///
    /// If `out.len() != payload.len() + self.get_next_message_overhead()`.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<(), ()> {
        debug_assert_eq!(out.len(), payload.len() + self.get_next_message_overhead());

        // Check that it is our turn to send.
        assert!(self.message_index % 2 == if self.is_initiator { 0 } else { 1 });

        // Get the message pattern.
        // Clone to make the borrow check happy.
        let m = self.pattern.get_message_pattern(self.message_index);
        self.message_index += 1;

        let mut cur: usize = 0;
        // Process tokens.
        for t in m {
            match *t {
                Token::E => {
                    if self.e.is_none() {
                        self.e = Some(D::genkey());
                    }
                    let e_pk = D::pubkey(self.e.as_ref().unwrap());
                    self.symmetric.mix_hash(e_pk.as_slice());
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(e_pk.as_slice());
                    }
                    out[cur..cur + D::Pubkey::len()].copy_from_slice(e_pk.as_slice());
                    cur += D::Pubkey::len();
                }
                Token::S => {
                    let len = if self.symmetric.has_key() {
                        D::Pubkey::len() + 16
                    } else {
                        D::Pubkey::len()
                    };

                    let encrypted_s_out = &mut out[cur..cur + len];
                    self.symmetric
                        .encrypt_and_hash(D::pubkey(self.s.as_ref().unwrap()).as_slice(),
                                          encrypted_s_out);
                    cur += len;
                }
                t => {
                    let dh_result = self.perform_dh(t)?;
                    self.symmetric.mix_key(dh_result.as_slice());
                }
            }
        }

        self.symmetric.encrypt_and_hash(payload, &mut out[cur..]);
        Ok(())
    }

    /// Takes a handshake message, process it and update our internal
    /// state, and write the encapsulated payload to `out`.
    ///
    /// If the message fails to decrypt, the whole `HandshakeState`
    /// may be in invalid state, and should not be used
    /// anymore. (Except to `get_re` before falling back to
    /// `XXfallback`). Consider cloning the `HandshakeState` if
    /// reusing is desirable.
    ///
    /// # Panics
    ///
    /// If `out.len() + self.get_next_message_overhead() != data.len()`.
    ///
    /// (Notes that this implies `data.len() >= overhead`.)
    pub fn read_message(&mut self, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
        debug_assert_eq!(out.len() + self.get_next_message_overhead(), data.len());

        assert!(self.message_index % 2 == if self.is_initiator { 1 } else { 0 });

        // Get the message pattern.
        let m = self.pattern.get_message_pattern(self.message_index);
        self.message_index += 1;

        let mut data = data;
        // Consume the next `n` bytes of data.
        let mut get = |n| {
            let ret = &data[..n];
            data = &data[n..];
            ret
        };

        // Process tokens.
        for t in m {
            match *t {
                Token::E => {
                    let re = D::Pubkey::from_slice(get(D::Pubkey::len()));
                    self.symmetric.mix_hash(re.as_slice());
                    if self.symmetric.has_preshared_key() {
                        self.symmetric.mix_key(re.as_slice());
                    }
                    self.re = Some(re);
                }
                Token::S => {
                    let temp = get(if self.symmetric.has_key() {
                        D::Pubkey::len() + 16
                    } else {
                        D::Pubkey::len()
                    });
                    let mut rs = D::Pubkey::new();
                    self.symmetric.decrypt_and_hash(temp, rs.as_mut())?;
                    self.rs = Some(rs);
                }
                t => {
                    let dh_result = self.perform_dh(t)?;
                    self.symmetric.mix_key(dh_result.as_slice());
                }
            }
        }

        Ok(self.symmetric.decrypt_and_hash(data, out)?)
    }

    /// Similar to `read_message`, but returns result as a `Vec`.
    ///
    /// Also does not require that `data.len() >= overhead`.
    #[cfg(feature = "use_std")]
    pub fn read_message_vec(&mut self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let overhead = self.get_next_message_overhead();
        if data.len() < overhead {
            Err(())
        } else {
            let mut out = vec![0u8; data.len() - overhead];
            self.read_message(data, &mut out)?;
            Ok(out)
        }
    }

    /// Whether handshake has completed.
    pub fn completed(&self) -> bool {
        self.message_index == self.pattern.get_message_patterns_len()
    }

    /// Get handshake hash. Useful for e.g., channel binding.
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
        self.rs.as_ref().map(U8Array::clone)
    }

    /// Get remote semi-ephemeral pubkey.
    ///
    /// Returns `None` if we do not know.
    ///
    /// Useful for noise-pipes.
    pub fn get_re(&self) -> Option<D::Pubkey> {
        self.re.as_ref().map(U8Array::clone)
    }

    /// Get whether this `HandshakeState` is created as initiator.
    pub fn get_is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get handshake pattern this `HandshakeState` uses.
    pub fn get_pattern(&self) -> &HandshakePattern {
        &self.pattern
    }

    fn perform_dh(&self, t: Token) -> Result<D::Output, ()> {
        let dh = |a: Option<&D::Key>, b: Option<&D::Pubkey>| D::dh(a.unwrap(), b.unwrap());

        match t {
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
        }
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
    /// Create a new `HandshakeStateBuilder`.
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

    /// Set handshake pattern.
    pub fn set_pattern(&mut self, p: HandshakePattern) -> &mut Self {
        self.pattern = Some(p);
        self
    }

    /// Set whether the `HandshakeState` is initiator.
    pub fn set_is_initiator(&mut self, is: bool) -> &mut Self {
        self.is_initiator = Some(is);
        self
    }

    /// Set prologue.
    pub fn set_prologue(&mut self, prologue: &'a [u8]) -> &mut Self {
        self.prologue = Some(prologue);
        self
    }

    /// Set pre-shared key.
    pub fn set_psk(&mut self, psk: &'a [u8]) -> &mut Self {
        self.psk = Some(psk);
        self
    }

    /// Set ephemeral key.
    ///
    /// This is usually not necessary. See doc of `HandshakeState::new()`.
    pub fn set_e(&mut self, e: D::Key) -> &mut Self {
        self.e = Some(e);
        self
    }

    /// Set static key.
    pub fn set_s(&mut self, s: D::Key) -> &mut Self {
        self.s = Some(s);
        self
    }

    /// Set peer semi-ephemeral public key.
    ///
    /// Usually used in fallback patterns.
    pub fn set_re(&mut self, re: D::Pubkey) -> &mut Self {
        self.re = Some(re);
        self
    }

    /// Set peer static public key.
    pub fn set_rs(&mut self, rs: D::Pubkey) -> &mut Self {
        self.rs = Some(rs);
        self
    }

    /// Build `HandshakeState`.
    ///
    /// # Panics
    ///
    /// `pattern`, `prologue` and `is_initiator` must be set.
    pub fn build_handshake_state<C, H>(self) -> HandshakeState<D, C, H>
        where C: Cipher,
              H: Hash
    {
        HandshakeState::new(self.pattern.unwrap(),
                            self.is_initiator.unwrap(),
                            self.prologue.unwrap(),
                            self.psk,
                            self.s,
                            self.e,
                            self.rs,
                            self.re)
    }
}
