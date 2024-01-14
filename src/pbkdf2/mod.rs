use std::num::NonZeroUsize;

use crate::{hash, hmac};

/// [key] derives a key from the password, salt and iteration count, returning a
/// []byte of length keylen that can be used as cryptographic key. The key is
/// derived based on the method described as PBKDF2 with the HMAC variant using
/// the supplied hash function.
///
/// For example, to use a HMAC-SHA-1 based PBKDF2 key derivation function, you
/// can get a derived key for e.g. AES-256 (which needs a 32-byte key) by
/// doing:
///
/// let mut out = [[0u8;32]];
///
///    pbkdf2.key(sha3::new_256, []byte("some password"), salt, 4096, &mut out);
///
/// Remember to get a good random salt. At least 8 bytes is recommended by the
/// RFC.
///
/// Using a higher iteration count will increase the cost of an exhaustive
/// search but will also make derivation proportionally slower.
pub fn key<F>(
    h: F,
    data: &[u8],
    salt: &[u8],
    iter: NonZeroUsize,
    out: &mut [u8],
) where
    F: FnMut() -> Box<dyn hash::Hash>
{
    let mut prf = hmac::new(h, Some(data));
    let h_len = prf.size();
    let n_blocks = (out.len() + h_len - 1) / h_len;

    // Fast path
    if n_blocks * h_len <= out.len() {
        exec(
            prf.as_mut(),
            salt,
            h_len,
            n_blocks,
            iter.get(),
            out,
        );
        return;
    }

    // Slow path
    let mut dk = vec![0u8; n_blocks * h_len];
    exec(
        prf.as_mut(),
        salt,
        h_len,
        n_blocks,
        iter.get(),
        dk.as_mut_slice(),
    );
    out.copy_from_slice(&dk.as_slice()[0..out.len()]);
}

fn exec(
    prf: &mut dyn hash::Hash,
    salt: &[u8],
    h_len: usize,
    n_blocks: usize,
    iter: usize,
    out: &mut [u8]
) {
    let mut seek = 0usize;
    let mut buf = [0u8; 4];
    let mut u = vec![0u8; h_len];

    for block in (0..n_blocks).step_by(1) {
        // N.B.: || means concatenation, ^ means XOR
        // for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
        // U_1 = PRF(password, salt || uint(i))

        prf.reset();
        prf.write(salt);

        buf[0] = (block >> 24) as u8;
        buf[1] = (block >> 16) as u8;
        buf[2] = (block >> 8) as u8;
        buf[3] = block as u8;
        prf.write(&buf);

        let t = &mut out[seek..seek + h_len];
        prf.sum(t);
        u.copy_from_slice(t);

        for _ in (2..=iter).step_by(1) {
            prf.reset();
            prf.write(u.as_slice());
            prf.sum(u.as_mut_slice());

            for x in 0..t.len() {
                t[x] ^= u[x];
            }
        }
        seek += h_len;
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZeroUsize;
    use lazy_static::lazy_static;
    use crate::{pbkdf2, sha3};
    use crate::util::to_hex;

    struct Test {
        data: Vec<u8>,
        salt: Vec<u8>,
        iter: NonZeroUsize,
        out: String
    }

    lazy_static! {
        static ref TESTS: [Test; 3] = [
            Test{
                data: Vec::from("password"),
                salt: Vec::from("salt"),
                iter: NonZeroUsize::new(1).unwrap(),
                out: String::from("615df6c507f95f1f795ad5dd19189d1736325f8e")
            },
            Test{
                data: Vec::from("password"),
                salt: Vec::from("salt"),
                iter: NonZeroUsize::new(2).unwrap(),
                out: String::from("8af33615f6bb91c69e756edac3a735eea45cb3bf")
            },
            Test{
                data: Vec::from("password"),
                salt: Vec::from("salt"),
                iter: NonZeroUsize::new(4096).unwrap(),
                out: String::from("f0416334d3f6982cfda802ecd6ff262dbcae1d4a")
            }
        ];
    }

    #[test]
    fn test() {
        let mut out = [0u8; 20];
        for i in (0..TESTS.len()).step_by(1) {
            pbkdf2::key(
                sha3::new_256,
                TESTS[i].data.as_slice(),
                TESTS[i].salt.as_slice(),
                TESTS[i].iter,
                &mut out
            );
            assert_eq!(to_hex(&out), TESTS[i].out)
        }
    }
}