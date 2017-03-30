extern crate core;

use self::core::fmt::{self, Display, Formatter};

/// Noise error type.
#[derive(Debug)]
pub enum NoiseError {
    /// The message is too short.
    TooShort,
    /// Decryption/authentication failure.
    DecryptionFailed,
}

impl From<()> for NoiseError {
    fn from(_: ()) -> Self {
        NoiseError::DecryptionFailed
    }
}

impl Display for NoiseError {
    fn fmt(&self, f: &mut Formatter) -> self::core::result::Result<(), fmt::Error> {
        match *self {
            NoiseError::TooShort => f.write_str("Message too short"),
            NoiseError::DecryptionFailed => f.write_str("Decryption failed"),
        }
    }
}

#[cfg(feature = "use_std")]
impl ::std::error::Error for NoiseError {
    fn description(&self) -> &str {
        match *self {
            NoiseError::TooShort => "Message too short",
            NoiseError::DecryptionFailed => "Decryption failed",
        }
    }
}
