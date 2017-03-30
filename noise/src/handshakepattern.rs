extern crate arrayvec;

use self::arrayvec::ArrayVec;

/// A token in noise message patterns.
#[derive(Copy, Clone)]
pub enum Token {
    /// e.
    E,
    /// s.
    S,
    /// ee.
    EE,
    /// es.
    ES,
    /// se.
    SE,
    /// ss.
    SS,
}

use self::Token::*;

/// Noise handshake pattern.
#[derive(Clone)]
pub struct HandshakePattern {
    pre_i: ArrayVec<[Token; 4]>,
    pre_r: ArrayVec<[Token; 4]>,
    msg_patterns: ArrayVec<[ArrayVec<[Token; 8]>; 8]>,
    name: &'static str,
}

impl HandshakePattern {
    /// Get initiator pre-messages.
    pub fn get_pre_i(&self) -> &[Token] {
        &self.pre_i
    }

    /// Get responder pre-messages.
    pub fn get_pre_r(&self) -> &[Token] {
        &self.pre_r
    }

    /// Get message patterns.
    pub fn get_message_pattern(&self, i: usize) -> &[Token] {
        &self.msg_patterns[i]
    }

    /// Get number of message patterns.
    pub fn get_message_patterns_len(&self) -> usize {
        self.msg_patterns.len()
    }

    /// Get pattern name.
    pub fn get_name(&self) -> &str {
        self.name
    }
}

macro_rules! vec {
    () => {
        ArrayVec::new()
    };
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = ArrayVec::new();
            $(
                let push_result = temp_vec.push($x);
                assert!(push_result.is_none());
            )*
            temp_vec
        }
    };
}

/// The `Noise_N` pattern.
pub fn noise_n() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES]],
        name: "N",
    }
}

/// The `Noise_K` pattern.
pub fn noise_k() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![S],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES, SS]],
        name: "K",
    }
}

/// The `Noise_X` pattern.
pub fn noise_x() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES, S, SS]],
        name: "X",
    }
}

/// The `Noise_NN` pattern.
pub fn noise_nn() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE]],
        name: "NN",
    }
}

/// The `Noise_NK` pattern.
pub fn noise_nk() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES], vec![E, EE]],
        name: "NK",
    }
}

/// The `Noise_NX` pattern.
pub fn noise_nx() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE, S, ES]],
        name: "NX",
    }
}

/// The `Noise_XN` pattern.
pub fn noise_xn() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE], vec![S, SE]],
        name: "XN",
    }
}

/// The `Noise_XK` pattern.
pub fn noise_xk() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES], vec![E, EE], vec![S, SE]],
        name: "XK",
    }
}

/// The `Noise_XX` pattern.
pub fn noise_xx() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE, S, ES], vec![S, SE]],
        name: "XX",
    }
}

/// The `Noise_KN` pattern.
pub fn noise_kn() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![S],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE, SE]],
        name: "KN",
    }
}

/// The `Noise_KK` pattern.
pub fn noise_kk() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![S],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES, SS], vec![E, EE, SE]],
        name: "KK",
    }
}

/// The `Noise_KX` pattern.
pub fn noise_kx() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![S],
        pre_r: vec![],
        msg_patterns: vec![vec![E], vec![E, EE, SE, S, ES]],
        name: "KX",
    }
}

/// The `Noise_IN` pattern.
pub fn noise_in() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E, S], vec![E, EE, SE]],
        name: "IN",
    }
}

/// The `Noise_IK` pattern.
pub fn noise_ik() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![S],
        msg_patterns: vec![vec![E, ES, S, SS], vec![E, EE, SE]],
        name: "IK",
    }
}

/// The `Noise_IX` pattern.
pub fn noise_ix() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![],
        msg_patterns: vec![vec![E, S], vec![E, EE, SE, S, ES]],
        name: "IX",
    }
}

/// The `Noise_XXfallback` pattern.
///
/// Something that is used in noise pipes.
pub fn noise_xx_fallback() -> HandshakePattern {
    HandshakePattern {
        pre_i: vec![],
        pre_r: vec![E],
        msg_patterns: vec![vec![E, EE, S, SE], vec![S, ES]],
        name: "XXfallback",
    }
}
