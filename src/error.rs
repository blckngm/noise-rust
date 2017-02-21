use std::fmt::{self, Display, Formatter};

/// Noise error type.
#[derive(Debug)]
pub enum NoiseError {
    TooShort,
    DecryptionFailed,
}

impl From<()> for NoiseError {
    fn from(_: ()) -> Self {
        NoiseError::DecryptionFailed
    }
}

impl Display for NoiseError {
    fn fmt(&self, f: &mut Formatter) -> ::std::result::Result<(), fmt::Error> {
        match *self {
            NoiseError::TooShort => f.write_str("Message too short"),
            NoiseError::DecryptionFailed => f.write_str("Decryption failed"),
        }
    }
}

impl ::std::error::Error for NoiseError {
    fn description(&self) -> &str {
        match *self {
            NoiseError::TooShort => "Message too short",
            NoiseError::DecryptionFailed => "Decryption failed",
        }
    }
}
