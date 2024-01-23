/// Signature entity.
pub trait Signature: Sized {
    /// An entity that produced this signature.
    type Signer: Clone;
    /// Key used to create this signature.
    type Key;

    /// An entity that produced this signature.
    fn signer(&self) -> Option<Self::Signer>;

    /// Returns `Ok(true)` if the underlying signature was produced on supplied bytes using the given key.
    fn verify_bytes<M>(&self, message: M, key: &Self::Key) -> Result<bool, VerificationError>
    where
        M: AsRef<[u8]>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    IncompatibleKey,
}
