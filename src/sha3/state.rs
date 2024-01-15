use crate::sha3::keccakf;

#[derive(PartialEq, Clone, Debug)]
pub(crate) enum SpongeDirection {
    SpongeAbsorbing,
    SpongeSqueezing,
}

pub(crate) const A_LEN: usize = 25;

pub(crate) const ST_LEN: usize = 168;

pub(crate) struct State {
    //===========================
    // Generic sponge components.
    //===========================

    // main state of the hash
    pub(crate) a: [u64; A_LEN],

    // the number of bytes of state to use
    pub(crate) rate: usize,

    // ds_byte contains the "domain separation" bits and the first bit of
    // the padding. Sections 6.1 and 6.2 of [1] separate the outputs of the
    // SHA-3 and SHAKE functions by appending bit strings to the message.
    // Using a little-endian bit-ordering convention, these are "01" for SHA-3
    // and "1111" for SHAKE, or 00000010b and 00001111b, respectively. Then the
    // padding rule from section 5.1 is applied to pad the message to a multiple
    // of the rate, which involves adding a "1" bit, zero or more "0" bits, and
    // a final "1" bit. We merge the first "1" bit from the padding into ds_byte,
    // giving 00000110b (0x06) and 00011111b (0x1f).
    // [1] http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf
    //     "Draft FIPS 202: SHA-3 Standard: Permutation-Based Hash and
    //      Extendable-Output Functions (May 2014)"
    pub(crate) ds_byte: u8,

    // windows slice storage
    pub(crate) seek: usize,
    pub(crate) len: usize,
    pub(crate) storage: [u8; ST_LEN],

    //=============================
    // Specific to SHA-3 and SHAKE.
    //=============================
    pub(crate) output_len: usize,
    pub(crate) state: SpongeDirection,
}

impl State {
    pub(crate) fn new(rate: usize, output_len: usize, ds_byte: u8) -> Self {
        Self {
            a: [0; A_LEN],
            seek: 0,
            len: 0,
            rate,
            output_len,
            ds_byte,
            storage: [0; ST_LEN],
            state: SpongeDirection::SpongeAbsorbing,
        }
    }

    /// [write] absorbs more data into the hash's state. It panics if any
    /// output has already been read.
    pub(crate) fn write(&mut self, p: &[u8]) -> usize {
        if self.state != SpongeDirection::SpongeAbsorbing {
            panic!("sha3: write after read");
        }

        let mut p_from = 0;
        let mut p_len = p.len();

        while p_len > 0 {
            if self.len == 0 && p_len >= self.rate {
                // The fast path; absorb a full "rate" bytes of input and apply the permutation.
                xor_in(&mut self.a, p, p_from, self.rate);
                keccakf::keccakf_1600(&mut self.a);

                p_from += self.rate;
                p_len -= self.rate;
            } else {
                // The slow path; buffer the input until we can fill the sponge, and then xor it in.
                let todo = std::cmp::min(self.rate - self.len, p_len);
                let seek = self.seek + self.len;
                self.storage[seek..(seek + todo)].copy_from_slice(&p[p_from..(p_from + todo)]);
                self.len += todo;

                if self.len == self.rate {
                    self.permute();
                }

                p_from += todo;
                p_len -= todo;
            }
        }
        p.len()
    }

    /// [sum] applies padding to the hash state and then squeezes out the desired
    /// number of output bytes. It panics if any output has already been read.
    pub(crate) fn sum(&mut self, out: &mut [u8]) {
        if self.state != SpongeDirection::SpongeAbsorbing {
            panic!("sha3: sum after read");
        }

        // Make a copy of the original hash so that caller can keep writing
        // and summing.
        self.clone().read(out);
    }

    /// [reset] clears the internal state by zeroing the sponge state and
    /// the byte buffer, and setting Sponge.state to absorbing.
    pub(crate) fn reset(&mut self) {
        // Zero the permutation's state.
        for elem in self.a.iter_mut() {
            *elem = 0;
        }

        self.state = SpongeDirection::SpongeAbsorbing;
        self.seek = 0;
        self.len = 0;
    }

    /// [size] returns the output size of the hash function in bytes.
    pub(crate) fn size(&self) -> usize {
        self.output_len
    }

    /// [block_size] returns the rate of sponge underlying this hash function.
    pub(crate) fn block_size(&self) -> usize {
        self.rate
    }

    /// [read] squeezes an arbitrary number of bytes from the sponge.
    fn read(&mut self, out: &mut [u8]) -> usize {
        // If we're still absorbing, pad and apply the permutation.
        if self.state == SpongeDirection::SpongeAbsorbing {
            self.pad_and_permute(self.ds_byte);
        }

        let mut out_from = 0;
        let mut out_len = out.len();

        while out_len > 0 {
            let len_copy = std::cmp::min(out_len, self.len);
            let slice_storage = &self.storage[self.seek..(self.seek + len_copy)];
            out[out_from..(out_from + len_copy)].copy_from_slice(slice_storage);

            out_from += len_copy;
            out_len -= len_copy;

            self.seek += len_copy;
            self.len -= len_copy;

            // Apply the permutation if we've squeezed the sponge dry.
            if self.len == 0 {
                self.permute();
            }
        }

        out.len()
    }

    /// [permute] applies the KeccakF-1600 permutation. It handles
    /// any input-output buffering.
    fn permute(&mut self) {
        match self.state {
            SpongeDirection::SpongeAbsorbing => {
                // If we're absorbing, we need to xor the input into the state
                // before applying the permutation.
                xor_in(&mut self.a, &self.storage, self.seek, self.len);
                self.seek = 0;
                self.len = 0;
                keccakf::keccakf_1600(&mut self.a);
            }
            SpongeDirection::SpongeSqueezing => {
                // If we're squeezing, we need to apply the permutation before
                // copying more output.
                keccakf::keccakf_1600(&mut self.a);
                self.seek = 0;
                self.len = self.rate;
                u64s_to_bytes(&self.a, &mut self.storage, self.seek, self.len);
            }
        }
    }

    /// pads appends the domain separation bits in ds_byte, applies
    /// the multi-bitrate 10..1 padding rule, and permutes the state.
    fn pad_and_permute(&mut self, ds_byte: u8) {
        // Pad with this instance's domain-separator bits. We know that there's
        // at least one byte of space in d.buf because, if it were full,
        // permute would have been called to empty it. ds_byte also contains the
        // first one bit for the padding. See the comment in the state struct.
        self.storage[self.seek + self.len] = ds_byte;
        self.len += 1;
        let zeros_start = self.seek + self.len;
        for i in zeros_start..self.rate {
            self.storage[i] = 0
        }
        // This adds the final one bit for the padding. Because of the way that
        // bits are numbered from the LSB upwards, the final bit is the MSB of
        // the last byte.
        self.storage[self.rate - 1] ^= 0x80;
        // Apply the permutation
        self.seek = 0;
        self.len = self.rate;
        self.permute();

        self.state = SpongeDirection::SpongeSqueezing;
        self.seek = 0;
        self.len = self.rate;
        u64s_to_bytes(&self.a, &mut self.storage, self.seek, self.len);
    }

    fn clone(&self) -> Self {
        let mut out = Self {
            a:          self.a,
            rate:       self.rate,
            ds_byte:    self.ds_byte,
            seek:       self.seek,
            len:        self.len,
            storage:    self.storage,
            output_len: self.output_len,
            state:      self.state.clone(),
        };
        if self.state == SpongeDirection::SpongeSqueezing {
            out.seek = self.rate - (ST_LEN - self.seek);
            out.len = self.rate;
        }
        out
    }
}

/// [xor_in] xor the bytes in buf into the state; it
/// makes no non-portable assumptions about memory layout
/// or alignment.
fn xor_in(a: &mut [u64; A_LEN], storage: &[u8], seek: usize, len: usize) {
    let n = len / 8;
    for i in (0..n).step_by(1) {
        let from = seek + (i * 8);
        let bytes = &storage[from..from + 8];
        let value = u64::from_le_bytes(bytes.try_into().unwrap());
        a[i] ^= value;
    }
}

/// [u64s_to_bytes] copies uint64s to a byte buffer.
fn u64s_to_bytes(a: &[u64; A_LEN], storage: &mut [u8], seek: usize, len: usize) {
    let n = len / 8;
    for i in (0..n).step_by(1) {
        let from = seek + (i * 8);
        storage[from..from + 8].copy_from_slice(&a[i].to_le_bytes());
    }
}