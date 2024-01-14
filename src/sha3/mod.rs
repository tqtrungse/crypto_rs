use crate::hash;
use crate::sha3::hashes::{Sha256, Sha512};
use crate::sha3::shakes::{Shake, CShake, RATE128, RATE256, DS_BYTE_SHAKE, DS_BYTE_CSHAKE};

mod keccakf;
mod state;
mod shakes;
pub(crate) mod hashes;

/// [new_256] creates a new SHA3-256 hash.
/// Its generic security strength is 256 bits against preimage attacks,
/// and 128 bits against collision attacks.
pub fn new_256() -> Box<dyn hash::Hash> {
    Box::new(Sha256::new())
}

/// [new_512] creates a new SHA3-512 hash.
/// Its generic security strength is 512 bits against preimage attacks,
/// and 256 bits against collision attacks.
pub fn new_512() -> Box<dyn hash::Hash> {
    Box::new(Sha512::new())
}

/// [new_shake128] creates a new SHAKE128 variable-output-length ShakeHash.
/// Its generic security strength is 128 bits against all attacks if at
/// least 32 bytes of its output are used.
pub fn new_shake128() -> Box<dyn hash::Hash> {
    Box::new(Shake::new(RATE128, 32, DS_BYTE_SHAKE))
}

/// [new_shake256] creates a new SHAKE256 variable-output-length ShakeHash.
/// Its generic security strength is 256 bits against all attacks if at
/// least 64 bytes of its output are used.
pub fn new_shake256() -> Box<dyn hash::Hash> {
    Box::new(Shake::new(RATE256, 64, DS_BYTE_SHAKE))
}

/// [new_cshake128] creates a new instance of cSHAKE128 variable-output-length ShakeHash,
/// a customizable variant of SHAKE128.
/// [n] is used to define functions based on cSHAKE, it can be empty when plain cSHAKE is
/// desired. [s] is a customization byte string used for domain separation - two cSHAKE
/// computations on same input with different s yield unrelated outputs.
/// When n and s are both empty, this is equivalent to [new_shake128].
pub fn new_cshake128(n: Option<&[u8]>, s: &[u8]) -> Box<dyn hash::Hash> {
    if n.is_none() && s.is_empty() {
        return new_shake128();
    }
    Box::new(CShake::new(n, s, RATE128, 32, DS_BYTE_CSHAKE))
}

/// [new_cshake256] creates a new instance of cSHAKE256 variable-output-length ShakeHash,
/// a customizable variant of SHAKE256.
/// [n] is used to define functions based on cSHAKE, it can be empty when plain cSHAKE is
/// desired. [s] is a customization byte string used for domain separation - two cSHAKE
/// computations on same input with different s yield unrelated outputs.
/// When n and s are both empty, this is equivalent to [new_shake256].
pub fn new_cshake256(n: Option<&[u8]>, s: &[u8]) -> Box<dyn hash::Hash> {
    if n.is_none() && s.is_empty() {
        return new_shake256();
    }
    Box::new(CShake::new(n, s, RATE256, 64, DS_BYTE_CSHAKE))
}