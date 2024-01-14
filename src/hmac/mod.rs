mod state;

use std::{error, fmt};

use crate::hash;
use crate::hmac::state::State;

/// An error returned from the encoding method.
///
/// The message could not be sent because the marshall binary is failed.
///
/// The error contains the message so it can be recovered.
#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct Error {
    pub(crate) message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for Error {}

/// [Marshalable] is contract of HMAC.
///
/// Any hash algorithm want to be compatible with HMAC has to
/// implemented it.
pub(crate) trait Marshalable {
    fn marshall_binary(&self) -> Vec<u8>;
    fn unmarshall_binary(&mut self, b: &[u8]) -> Option<Error>;
}

/// [new] returns a new HMAC hash using the given [crypto/hash] type and key.
/// New functions like shake.New from [crypto/sha3] can be used as h.
/// h must return a new Hash every time it is called.
/// Note that only hash functions that produce fixed-length unique values are supported.
pub fn new<F>(h: F, key: Option<&[u8]>) -> Box<dyn hash::Hash>
    where
        F: FnMut() -> Box<dyn hash::Hash>,
{
    Box::new(State::new(h, key))
}

