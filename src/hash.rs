use std::any::Any;

#[derive(PartialEq)]
pub enum Type {
    SHA3_256,
    SHA3_512,
    Shake,
    CShake,
    HMAC,
}

pub trait Hash {
    /// [write] adds more data to the running hash.
    /// It never returns an error.
    fn write(&mut self, p: &[u8]) -> usize;

    /// [sum] returns the resulting slice.
    /// It does not change the underlying hash state.
    fn sum(&mut self, out: &mut [u8]);

    /// [reset] resets the Hash to its initial state.
    fn reset(&mut self);

    /// [size] returns the number of bytes [sum] will return.
    fn size(&self) -> usize;

    /// [block_size] returns the hash's underlying block size.
    /// The [write] method must be able to accept any amount
    /// of data, but it may operate more efficiently if all writes
    /// are a multiple of the block size.
    fn block_size(&self) -> usize;

    /// [as_mut] returns mutable [Any] of raw type.
    fn as_mut(&mut self) -> &mut dyn Any;

    /// [as_ref] returns reference [Any] of raw type.
    fn as_ref(&self) -> &dyn Any;

    /// [hash_type] returns hash type.
    fn hash_type(&self) -> Type;
}