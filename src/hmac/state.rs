use std::any::Any;

use crate::hash;
use crate::hmac::{Error, Marshalable};
use crate::sha3::hashes::{Sha256, Sha512};

/// FIPS 198-1:
/// https://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
///
/// key is zero padded to the block size of the hash function
/// ipad = 0x36 byte repeated for key length
/// opad = 0x5c byte repeated for key length
/// hmac = H([key ^ opad] H([key ^ ipad] text))
pub(crate) struct State {
    opad: Vec<u8>,
    ipad: Vec<u8>,

    outer: Box<dyn hash::Hash>,
    inner: Box<dyn hash::Hash>,

    // If marshaled is true, then opad and ipad do not contain a padded
    // copy of the key, but rather the marshaled state of outer/inner after
    // opad/ipad has been fed into it.
    marshaled: bool
}

impl State {
    pub(crate) fn new<F>(mut h: F, key: Option<&[u8]>) -> Self
        where
            F: FnMut() -> Box<dyn hash::Hash>,
    {
        let mut hm = Self {
            opad: Vec::new(),
            ipad: Vec::new(),
            outer: h(),
            inner: h(),
            marshaled: false
        };

        if hm.inner.hash_type() != hm.outer.hash_type() {
            panic!("crypto/hmac h function doesn't return the same hash");
        }
        match check_hash_type(hm.inner.hash_type()) {
            Some(err) => panic!("{}", err.message),
            None => ()
        }

        let block_size = hm.inner.block_size();
        hm.ipad.resize(block_size, 0);
        hm.opad.resize(block_size, 0);

        match key {
            Some(k) => {
                if k.len() > block_size {
                    let mut out = vec![0u8; hm.inner.size()];
                    let ipad = hm.ipad.as_mut_slice();
                    let opad = hm.opad.as_mut_slice();

                    // If key is too big, hash it.
                    hm.outer.write(k);
                    hm.outer.sum(out.as_mut_slice());

                    for i in (0..out.len()).step_by(1) {
                        ipad[i] = out[i];
                        opad[i] = out[i];
                    }
                } else {
                    let ipad = hm.ipad.as_mut_slice();
                    let opad = hm.opad.as_mut_slice();

                    for i in (0..k.len()).step_by(1) {
                        ipad[i] = k[i];
                        opad[i] = k[i];
                    }
                }
            },
            None => {}
        }

        hm.ipad.iter_mut().for_each(|elem| *elem ^= 0x36);
        hm.opad.iter_mut().for_each(|elem| *elem ^= 0x5c);

        hm.inner.write(hm.ipad.as_slice());
        hm
    }
}

impl hash::Hash for State {
    fn write(&mut self, p: &[u8]) -> usize {
        self.inner.write(p)
    }

    fn sum(&mut self, out: &mut [u8]) {
        self.inner.sum(out);

        if self.marshaled {
            match unmarshall(self.outer.as_mut(), self.opad.as_slice()) {
                Some(err) => panic!("{}", err.message),
                None => ()
            }
        } else {
            self.outer.reset();
            self.outer.write(self.opad.as_slice());
        }
        self.outer.write(out);
        self.outer.sum(out);
    }

    fn reset(&mut self) {
        if self.marshaled {
            match unmarshall(self.inner.as_mut(), self.ipad.as_slice()) {
                Some(err) => panic!("{}", err.message.as_str()),
                None => return
            }
        }

        self.inner.reset();
        self.inner.write(self.ipad.as_slice());

        // If the underlying hash is marshalable, we can save some time by
        // saving a copy of the hash state now, and restoring it on future
        // calls to Reset and Sum instead of writing ipad/opad every time.
        //
        // If either hash is unmarshal able for whatever reason,
        // it's safe to bail out here.

        let i_marshal = match marshal(self.inner.as_ref()) {
            Some(v) => v,
            None => return
        };

        self.outer.reset();
        self.outer.write(self.opad.as_slice());

        let o_marshal = match marshal(self.outer.as_ref()) {
            Some(v) => v,
            None => return
        };

        // Marshaling succeeded; save the marshaled state for later
        self.ipad = i_marshal;
        self.opad = o_marshal;
        self.marshaled = true;
    }

    fn size(&self) -> usize {
        self.outer.size()
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn as_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn as_ref(&self) -> &dyn Any {
        self
    }

    fn hash_type(&self) -> hash::Type {
        hash::Type::HMAC
    }
}

fn unmarshall(h: &mut dyn hash::Hash, b: &[u8]) -> Option<Error> {
    match h.hash_type() {
        hash::Type::SHA3_256 => h.as_mut().downcast_mut::<Sha256>().unwrap().unmarshall_binary(b),
        hash::Type::SHA3_512 => h.as_mut().downcast_mut::<Sha512>().unwrap().unmarshall_binary(b),
        hash::Type::Shake => Some(Error{
            message: String::from("HMAC doesn't support SHAKE")
        }),
        hash::Type::CShake => Some(Error{
            message: String::from("HMAC doesn't support cSHAKE")
        }),
        hash::Type::HMAC => Some(Error{
            message: String::from("HMAC doesn't support HMAC")
        }),
    };
    None
}

fn marshal(h: &dyn hash::Hash) -> Option<Vec<u8>> {
    match h.hash_type() {
        hash::Type::SHA3_256 =>
            return h.
                as_ref().
                downcast_ref::<Sha256>().
                map(|shake| shake.marshall_binary()),

        hash::Type::SHA3_512 =>
            return h.
                as_ref().
                downcast_ref::<Sha512>().
                map(|cshake| cshake.marshall_binary()),

        hash::Type::Shake => {},
        hash::Type::CShake => {},
        hash::Type::HMAC => {},
    };
    None
}

fn check_hash_type(t: hash::Type) -> Option<Error> {
    let accepted_types = [
        hash::Type::SHA3_256,
        hash::Type::SHA3_512,
    ];

    for i in (0..accepted_types.len()).step_by(1) {
        if accepted_types[i] == t {
            return None
        }
    }

    Some(Error{
        message: String::from("crypto/hmac: hash generation function does not produce unique values")
    })
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use crate::hash::Hash;
    use crate::sha3;
    use crate::hmac::state::State;
    use crate::util::to_hex;

    type H = fn() -> Box<dyn Hash>;

    struct Test<F>
        where
            F: FnMut() -> Box<dyn Hash>, {
        h: F,
        key: Vec<u8>,
        _in: Vec<u8>,
        out: String,
        size: usize,
        block_size: usize,
    }

    // https://www.liavaag.org/English/SHA-Generator/HMAC/
    lazy_static! {
        static ref TESTS: [Test<H>; 7] = [
            Test{
                h: sha3::new_256,
                key: Vec::new(),
                _in: Vec::from("Sample"),
                out: String::from("5ec05468d537fc17449aabf0616bc080ecf697868f605a0028a5f3c120d52412"),
                size: 32,
                block_size: 136
            },
            Test {
                h: sha3::new_256,
                key: Vec::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                _in: Vec::from("Sample message for keylen<blocklen"),
                out: String::from("21c6ee6aa84274420e17d2311b75046c8290f75527cb85ae5e0231b6c1f7dc69"),
                size: 32,
                block_size: 136
            },
            Test {
                h: sha3::new_256,
                key: Vec::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202\
                                122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142\
                                434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263"),
                _in: Vec::from("Sample message for keylen=blocklen"),
                out: String::from("278f97d72dce3f98760bc1711f9cf16bb35f6608d2b6f432cd345b94cc4905a3"),
                size: 32,
                block_size: 136
            },
            Test{
                h: sha3::new_512,
                key: Vec::new(),
                _in: Vec::from("Sample"),
                out: String::from("be833739c58d0e29b640f325647f10515250c3d89a858cc9b4481de261334d73\
                                   b0b76481ee687dba168ea03e6c9f0958a5670680d73a2a2531b111f5c52f004a"),
                size: 64,
                block_size: 72
            },
            Test {
                h: sha3::new_512,
                key: Vec::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202\
                                122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142\
                                434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636\
                                465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
                _in: Vec::from("Sample message for keylen=blocklen"),
                out: String::from("70a2b18c1749bd952917309e78dd406ce208714e6300d90648e9977594157fee\
                                   695b8f69a0f216b9d7601d1551df8d59bd1f06edcb846c899b1aef78f99ea46c"),
                size: 64,
                block_size: 72
            },
            Test {
                h: sha3::new_512,
                key: Vec::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202\
                                122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
                _in: Vec::from("Sample message for keylen<blocklen"),
                out: String::from("f19e1098fbf54a5abad67e61301389293cfb5918930de4895f6d160e2323ff416\
                                   59ff4619cd3bb670d0193145cba52cbcc4db48abda22fc6c10072e36314c71c"),
                size: 64,
                block_size: 72
            },
            Test {
                h: sha3::new_512,
                key: Vec::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202\
                                122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142\
                                434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636\
                                465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485\
                                868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a\
                                7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7"),
                _in: Vec::from("Sample message for keylen=blocklen"),
                out: String::from("d7498950d026f4ca37990193f778bb9745e9dc811d5afe20068aec742001eee1\
                                   3eba35092ccd2922aa55b29b1aee155831888f065443d5e02c78222f25cfa944"),
                size: 64,
                block_size: 72
            }
        ];
    }

    #[test]
    fn test_hmac() {
        for i in (0..TESTS.len()).step_by(1) {
            let mut h = State::new(TESTS[i].h, Some(TESTS[i].key.as_slice()));

            assert_eq!(h.size(), TESTS[i].size);
            assert_eq!(h.block_size(), TESTS[i].block_size);

            for _ in (0..4usize).step_by(1) {
                let n = h.write(TESTS[i]._in.as_slice());
                assert_eq!(n, TESTS[i]._in.len());

                // Repetitive sum() calls should return the same value
                for _ in (0..2usize).step_by(1) {
                    let mut out = [0u8; 64];
                    h.sum(&mut out[0..h.size()]);
                    assert_eq!(to_hex(&out[0..h.size()]), TESTS[i].out)
                }
                h.reset();
            }
        }
    }

    #[test]
    fn test_unsupported_hash() {
        let result = std::panic::catch_unwind(|| {
            State::new(sha3::new_shake128, None);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_write_after_sum() {
        let mut h = State::new(sha3::new_256, None);
        let mut out = [0u8;32];
        let mut out1 = [0u8;32];
        let mut out2 = [0u8;32];

        h.write("out1".as_bytes());
        h.sum(&mut out1);

        h = State::new(sha3::new_256, None);
        h.write("out12".as_bytes());
        h.sum(&mut out2);

        // Test that Sum has no effect on future Sum or Write operations.
        // This is a bit unusual as far as usage, but it's allowed
        // by the definition of Go hash.Hash, and some clients expect it to work.
        h = State::new(sha3::new_256, None);
        h.write("out1".as_bytes());

        h.sum(&mut out);
        assert_eq!(out, out1);

        h.sum(&mut out);
        assert_eq!(out, out1);

        h.write("2".as_bytes());

        h.sum(&mut out);
        assert_eq!(out, out2);

        h.sum(&mut out);
        assert_eq!(out, out2);

        h.reset();
        h.write("out1".as_bytes());
        h.sum(&mut out);
        assert_eq!(out, out1);
    }
}