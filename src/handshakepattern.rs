#[derive(Copy, Clone)]
pub enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
}

use self::Token::*;

/// Noise handshake pattern.
pub struct HandshakePattern {
    pre_i: Vec<Token>,
    pre_r: Vec<Token>,
    msg_patterns: Vec<Vec<Token>>,
    name: &'static str,
}

impl HandshakePattern {
    pub fn get_pre_i(&self) -> &[Token] {
        &self.pre_i
    }

    pub fn get_pre_r(&self) -> &[Token] {
        &self.pre_r
    }

    pub fn get_message_patterns(&self) -> &[Vec<Token>] {
        &self.msg_patterns
    }

    pub fn get_name(&self) -> &str {
        self.name
    }
}

// TODO more patterns.

/// The Noise_IK pattern.
pub fn noise_ik() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES, S, SS], vec![E, EE, SE]],
        name: "IK",
    }
}
