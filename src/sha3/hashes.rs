use std::any::Any;
use std::mem;

use crate::{hash, hmac};
use crate::sha3::state::{A_LEN, ST_LEN, SpongeDirection, State};

const PREFIX: &str = "sha3\x03";
const MARSHALED_SIZE: usize =
                                PREFIX.len() +
                                A_LEN * 8 +
                                ST_LEN +
                                mem::size_of::<usize>() * 2 + // seek + len
                                2; // ds_byte + state

pub(crate) struct Sha256 {
    state: State
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: State::new(136, 32, 0x06)
        }
    }
}

impl hash::Hash for Sha256 {
    fn write(&mut self, p: &[u8]) -> usize {
        self.state.write(p)
    }

    fn sum(&mut self, out: &mut [u8]) {
        self.state.sum(out);
    }

    fn reset(&mut self) {
        self.state.reset();
    }

    fn size(&self) -> usize {
        self.state.size()
    }

    fn block_size(&self) -> usize {
        self.state.block_size()
    }

    fn as_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_ref(&self) -> &dyn Any {
        self
    }

    fn hash_type(&self) -> hash::Type {
        hash::Type::SHA3_256
    }
}

impl hmac::Marshalable for Sha256 {
    fn marshall_binary(&self) -> Vec<u8> {
        marshall(&self.state)
    }

    fn unmarshall_binary(&mut self, _b: &[u8]) -> Option<hmac::Error> {
        unmarshall(&mut self.state, _b)
    }
}

pub(crate) struct Sha512 {
    state: State
}

impl Sha512 {
    pub(crate) fn new() -> Self {
        Self {
            state: State::new(72, 64, 0x06)
        }
    }
}

impl hash::Hash for Sha512 {
    fn write(&mut self, p: &[u8]) -> usize {
        self.state.write(p)
    }

    fn sum(&mut self, out: &mut [u8]) {
        self.state.sum(out);
    }

    fn reset(&mut self) {
        self.state.reset();
    }

    fn size(&self) -> usize {
        self.state.size()
    }

    fn block_size(&self) -> usize {
        self.state.block_size()
    }

    fn as_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_ref(&self) -> &dyn Any {
        self
    }

    fn hash_type(&self) -> hash::Type {
        hash::Type::SHA3_512
    }
}

impl hmac::Marshalable for Sha512 {
    fn marshall_binary(&self) -> Vec<u8> {
        marshall(&self.state)
    }

    fn unmarshall_binary(&mut self, _b: &[u8]) -> Option<hmac::Error> {
        unmarshall(&mut self.state, _b)
    }
}

fn marshall(state: &State) -> Vec<u8> {
    let mut out = Vec::<u8>::with_capacity(MARSHALED_SIZE);

    out.extend_from_slice(PREFIX.as_bytes());
    for i in (0..A_LEN).step_by(1) {
        out.extend_from_slice(&state.a[i].to_be_bytes());
    }
    out.push(state.ds_byte);
    out.extend_from_slice(&(state.seek as u64).to_be_bytes());
    out.extend_from_slice(&(state.len as u64).to_be_bytes());
    out.extend_from_slice(&state.storage);
    match state.state {
        SpongeDirection::SpongeAbsorbing => out.push(0u8),
        SpongeDirection::SpongeSqueezing => out.push(1u8),
    }
    out
}

fn unmarshall(state: &mut State, _b: &[u8]) -> Option<hmac::Error> {
    let err = hmac::Error {
        message: "crypto/sha3: invalid hash state identifier".to_string(),
    };

    if _b.len() < PREFIX.len() {
        return Some(err);
    }

    match std::str::from_utf8(&_b[..PREFIX.len()]) {
        Ok(str_ref) => if str_ref != PREFIX {
            return Some(err);
        }
        Err(_) => return Some(err)
    };

    if _b.len() != MARSHALED_SIZE {
        return Some(hmac::Error {
            message: "crypto/sha3: invalid hash state size".to_string(),
        });
    }

    // Parse state.
    if _b[MARSHALED_SIZE - 1] == 0 {
        state.state = SpongeDirection::SpongeAbsorbing;
    } else if _b[MARSHALED_SIZE - 1] == 1 {
        state.state = SpongeDirection::SpongeSqueezing;
    } else {
        return Some(err);
    }

    // Parse a.
    let mut seek = PREFIX.len();
    let mut slice = &_b[seek..seek + 8];
    for i in (0..A_LEN).step_by(1) {
        match slice.try_into() {
            Ok(buf) => state.a[i] = u64::from_be_bytes(buf),
            Err(_) => return Some(err)
        };

        seek += 8;
        slice = &_b[seek..seek + 8];
    }

    // Parse ds_byte.
    state.ds_byte = _b[seek];
    seek += 1;

    // Parse seek.
    slice = &_b[seek..seek + 8];
    seek += 8;
    let mut buf = match slice.try_into() {
            Ok(val) => val,
            Err(_) => return Some(err)
        };
    // Because seek is casted to u64 when marshall, so we can use "as".
    state.seek = u64::from_be_bytes(buf) as usize;

    // Parse len.
    slice = &_b[seek..seek + 8];
    seek += 8;
    buf = match slice.try_into() {
            Ok(val) => val,
            Err(_) => return Some(err)
        };
    // Because len is casted to u64 when marshall, so we can use "as".
    state.len = u64::from_be_bytes(buf) as usize;

    // Parse storage.
    state.storage.copy_from_slice(&_b[seek..seek + ST_LEN]);

    None
}

#[cfg(test)]
mod tests {
    use crate::hash::Hash;
    use crate::hmac::Marshalable;
    use crate::sha3::hashes::{Sha256, Sha512};
    use crate::util::to_hex;

    #[test]
    fn test_hash() {
        // https://emn178.github.io/online-tools/

        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        let mut out = [0u8; 64];
        let input = "sha3";

        sha256.write(input.as_bytes());
        sha256.sum(&mut out);
        assert_eq!(
            to_hex(&out[0..32]).as_str(),
            "6f8c90edbfe5c62f414208f03f62d3c4347774108ba5d6204733bc1fd5700015"
        );
        sha256.sum(&mut out);
        assert_eq!(
            to_hex(&out[0..32]).as_str(),
            "6f8c90edbfe5c62f414208f03f62d3c4347774108ba5d6204733bc1fd5700015"
        );

        sha512.write(input.as_bytes());
        sha512.sum(&mut out);
        assert_eq!(
            to_hex(&out).as_str(),
            "a83f8e8e7cb75aed0444637206743ce0361fd3609b558278afe0898d004aaac55286c4bb4c92da6f3197041eff6b8906addf7403ec9383bfd2f71ea3e4427f3d"
        );
    }

    #[test]
    fn test_same_input_same_output() {
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        let mut out = [0u8; 64];
        let input = "sha3";

        for _ in (0..8).step_by(1) {
            sha256.write(input.as_bytes());
            sha256.sum(&mut out);
            sha256.reset();
            assert_eq!(
                to_hex(&out[0..32]),
                "6f8c90edbfe5c62f414208f03f62d3c4347774108ba5d6204733bc1fd5700015"
            );

            sha512.write(input.as_ref());
            sha512.sum(&mut out);
            sha512.reset();
            assert_eq!(
                to_hex(&out),
                "a83f8e8e7cb75aed0444637206743ce0361fd3609b558278afe0898d004aaac55286c4bb4c92da6f3197041eff6b8906addf7403ec9383bfd2f71ea3e4427f3d"
            );
        }
    }

    #[test]
    fn test_unmarshall() {
        let mut sha256 = Sha256::new();
        let mut out1 = [0u8; 32];
        let input = "sha3";

        sha256.write(input.as_bytes());
        sha256.sum(&mut out1);

        let mut sha256_clone = Sha256::new();
        let buf = sha256.marshall_binary();

        match sha256_clone.unmarshall_binary(buf.as_slice()) {
            Some(err) => panic!("{}", err.message),
            None => {
                assert_eq!(sha256.state.state, sha256_clone.state.state);
                assert_eq!(sha256.state.a, sha256_clone.state.a);
                assert_eq!(sha256.state.ds_byte, sha256_clone.state.ds_byte);
                assert_eq!(sha256.state.seek, sha256_clone.state.seek);
                assert_eq!(sha256.state.len, sha256_clone.state.len);
                assert_eq!(sha256.state.storage, sha256_clone.state.storage);
            }
        };
    }
}