use codec::{Decode, Encode, MaxEncodedLen};

/// Defines version of the storage being used.
#[derive(
    Encode, Decode, scale_info_derive::TypeInfo, Copy, Clone, Debug, Eq, PartialEq, MaxEncodedLen,
)]
pub enum StorageVersion {
    /// The old version which supports only a single key for DID.
    SingleKey,
    /// Multi-key DID.
    MultiKey,
}

impl Default for StorageVersion {
    fn default() -> Self {
        Self::SingleKey
    }
}
