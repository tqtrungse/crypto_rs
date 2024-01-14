use std::any::Any;

use crate::hash;
use crate::sha3::state::State;

pub(crate) const DS_BYTE_SHAKE: u8 = 0x1f;
pub(crate) const DS_BYTE_CSHAKE: u8 = 0x04;
pub(crate) const RATE128: usize = 168;
pub(crate) const RATE256: usize = 136;

pub(crate) struct Shake {
    state: State,
}

impl Shake {
    pub(crate) fn new(rate: usize, output_len: usize, ds_byte: u8) -> Self {
        Self {
            state: State::new(rate, output_len, ds_byte)
        }
    }
}

impl hash::Hash for Shake {
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
        hash::Type::Shake
    }
}

pub(crate) struct CShake {
    // SHA-3 state context and Read/Write operations
    state: State,

    // init_block is the cSHAKE specific initialization set of bytes. It is initialized
    // by newCShake function and stores concatenation of N followed by S, encoded
    // by the method specified in 3.3 of [1].
    // It is stored here in order for Reset() to be able to put context into
    // initial state.
    init_block: Vec<u8>,
}

impl CShake {
    pub(crate) fn new(n: Option<&[u8]>, s: &[u8], rate: usize, output_len: usize, ds_byte: u8) -> Self {
        let mut c = Self {
            state: State::new(rate, output_len, ds_byte),
            init_block: Vec::<u8>::new(),
        };

        if let Some(n) = n {
            c.init_block.reserve(9 * 2 + n.len() + s.len());
            c.init_block.append(&mut left_encode(u64::try_from(8 * n.len()).unwrap()));
            c.init_block.extend_from_slice(n);
        } else {
            c.init_block.reserve(9 * 2 + s.len());
            c.init_block.append(&mut left_encode(0));
        }
        c.init_block.append(&mut left_encode(u64::try_from(8 * s.len()).unwrap()));
        c.init_block.extend_from_slice(s);
        c.state.write(byte_pad(c.init_block.as_slice(), c.state.rate).as_slice());
        c
    }
}

impl hash::Hash for CShake {
    fn write(&mut self, p: &[u8]) -> usize {
        self.state.write(p)
    }

    fn sum(&mut self, out: &mut [u8]) {
        self.state.sum(out)
    }

    fn reset(&mut self) {
        self.state.reset();
        self.state.write(byte_pad(self.init_block.as_slice(), self.state.rate).as_slice());
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
        hash::Type::CShake
    }
}

fn byte_pad(input: &[u8], w: usize) -> Vec<u8> {
    // leftEncode always returns max 9 bytes
    let mut buf = Vec::<u8>::with_capacity(9 + input.len() + w);
    buf.append(&mut left_encode(u64::try_from(w).unwrap()));
    buf.extend_from_slice(input);
    buf.append(&mut vec![0u8;w - (buf.len() % w)]);
    buf
}

fn left_encode(value: u64) -> Vec<u8> {
    let mut b = [0u8; 9];
    b[1..].copy_from_slice(&value.to_be_bytes());

    // Trim all but last leading zero bytes
    let mut i = 1;
    while i < 8 && b[i] == 0 {
        i += 1;
    }
    // Prepend number of encoded bytes
    b[i - 1] = 9 - u8::try_from(i).unwrap();
    b[i - 1..].to_vec()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::hash::Hash;
    use crate::sha3::shakes::{Shake, CShake, RATE128, RATE256, DS_BYTE_SHAKE, DS_BYTE_CSHAKE};
    use crate::util::to_hex;

    #[test]
    fn test_shake_hash() {
        // https://emn178.github.io/online-tools/
        let mut shake = Shake::new(RATE128, 32, DS_BYTE_SHAKE);
        let mut out1 = [0u8; 64];
        let input = "shake";

        shake.write(input.as_bytes());
        shake.sum(&mut out1);
        assert_eq!(
            to_hex(&out1[0..32]).as_str(),
            "f1aec7018ad4d465233eab4c7d1ef0cdb8730fe33bd116053ef3d1997e50ec5a"
        );
        shake.sum(&mut out1);
        assert_eq!(
            to_hex(&out1[0..32]).as_str(),
            "f1aec7018ad4d465233eab4c7d1ef0cdb8730fe33bd116053ef3d1997e50ec5a"
        );

        shake = Shake::new(RATE256, 64, DS_BYTE_SHAKE);
        shake.write(input.as_bytes());
        shake.sum(&mut out1);
        assert_eq!(
            to_hex(&out1),
            "972b427a643ed66c27d157b93cb99b63dff3dfd61d2dd698748b8b5bb1e5fec0\
             4114a23f086bd5fb148254b56f4bf75280b9ae0fd40834ea836a51b9f694ced2"
        );
    }

    #[test]
    fn test_cshake_hash() {
        // https://emn178.github.io/online-tools/
        let mut c_shake = CShake::new(None, "salt".as_bytes(), RATE128, 32, DS_BYTE_CSHAKE);
        let mut out1 = [0u8; 64];
        let input = "cshake";

        c_shake.write(input.as_bytes());
        c_shake.sum(&mut out1);
        assert_eq!(
            to_hex(&out1[0..32]).as_str(),
            "5a9b8d826e9485ebf90ccc2d53ac7838f6c1af1440ec614627fc03bb9c85d2be"
        );

        c_shake = CShake::new(None, "salt".as_bytes(), RATE256, 32, DS_BYTE_CSHAKE);
        c_shake.write(input.as_bytes());
        c_shake.sum(&mut out1);
        assert_eq!(
            to_hex(&out1).as_str(),
            "e7c112aecfc6624d543897ab4346f50548d0ead294e85cdf65fb8eefbad5ef6bac9d72e3a50e58ec3456ff1e15764ea6fb6e57a7adc80e24d2ac17cdd396ada1"
        );
    }

    #[test]
    fn test_shake_same_input_same_output() {
        let mut shake128 = Shake::new(RATE128, 32, DS_BYTE_SHAKE);
        let mut shake256 = Shake::new(RATE256, 64, DS_BYTE_SHAKE);
        let mut out = [0u8; 64];
        let input = "shake";

        for _ in (0..8).step_by(1) {
            shake128.write(input.as_bytes());
            shake128.sum(&mut out);
            shake128.reset();
            assert_eq!(
                to_hex(&out[0..32]),
                "f1aec7018ad4d465233eab4c7d1ef0cdb8730fe33bd116053ef3d1997e50ec5a"
            );

            shake256.write(input.as_ref());
            shake256.sum(&mut out);
            shake256.reset();
            assert_eq!(
                to_hex(&out),
                "972b427a643ed66c27d157b93cb99b63dff3dfd61d2dd698748b8b5bb1e5fec0\
                 4114a23f086bd5fb148254b56f4bf75280b9ae0fd40834ea836a51b9f694ced2"
            );
        }
    }

    #[test]
    fn test_cshake_same_input_different_output() {
        let input = "cshake";
        let mut salt =
            SystemTime::now().
                duration_since(UNIX_EPOCH).
                expect("Time went backwards").
                as_nanos().
                to_le_bytes();
        let mut cshake1 = CShake::new(None, &salt, RATE128, 32, DS_BYTE_CSHAKE);

        salt =
            SystemTime::now().
                duration_since(UNIX_EPOCH).
                expect("Time went backwards").
                as_nanos().
                to_le_bytes();
        let mut cshake2 = CShake::new(None, &salt, RATE128, 32, DS_BYTE_CSHAKE);

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];

        for _ in (0..8).step_by(1) {
            cshake1.write(input.as_bytes());
            cshake1.sum(&mut out1);
            cshake1.reset();

            cshake2.write(input.as_ref());
            cshake2.sum(&mut out2);
            cshake2.reset();

            assert_ne!(out1, out2);
        }
    }
}