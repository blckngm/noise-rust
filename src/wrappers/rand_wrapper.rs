extern crate rand;

use self::rand::{OsRng, Rng};
use crypto_types::RandomGen;

/// A random number generator that retrieves randomness straight from the operating system.
pub struct RandomOS {
    rng: OsRng,
}

impl Default for RandomOS {
    fn default() -> RandomOS {
        RandomOS { rng: OsRng::new().unwrap() }
    }
}

impl RandomGen for RandomOS {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out);
    }
}
