use super::*;

pub mod offchain;
pub mod onchain;
pub mod signature;

pub use offchain::*;
pub use onchain::*;
pub use signature::DidSignature;

/// Size of the Dock DID in bytes
pub const DID_BYTE_SIZE: usize = 32;
/// The type of the Dock DID.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Did(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; DID_BYTE_SIZE]);

impl From<[u8; DID_BYTE_SIZE]> for Did {
    fn from(slice: [u8; DID_BYTE_SIZE]) -> Did {
        Did(slice)
    }
}

impl From<Did> for [u8; DID_BYTE_SIZE] {
    fn from(Did(slice): Did) -> [u8; DID_BYTE_SIZE] {
        slice
    }
}

impl sp_std::ops::Index<sp_std::ops::RangeFull> for Did {
    type Output = [u8; DID_BYTE_SIZE];

    fn index(&self, _: sp_std::ops::RangeFull) -> &Self::Output {
        &self.0
    }
}

/// Enum describing the storage of the DID
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
pub enum DidDetailStorage<T: Trait> {
    /// Off-chain DID has no need of nonce as the signature is made on the whole transaction by
    /// the caller account and Substrate takes care of replay protection. Thus it stores the data
    /// about off-chain DID Doc (hash, URI or any other reference) and the account that owns it.
    OffChain(OffChainDidDetails<T>),
    /// For on-chain DID, all data is stored on the chain.
    OnChain(OnChainDidDetails<T>),
}

impl<T: Trait> DidDetailStorage<T> {
    pub fn is_onchain(&self) -> bool {
        match self {
            DidDetailStorage::OnChain(_) => true,
            _ => false,
        }
    }

    pub fn is_offchain(&self) -> bool {
        !self.is_onchain()
    }

    pub fn into_offchain(self) -> Option<OffChainDidDetails<T>> {
        match self {
            DidDetailStorage::OffChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn into_onchain(self) -> Option<OnChainDidDetails<T>> {
        match self {
            DidDetailStorage::OnChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn to_onchain_mut(&mut self) -> Option<&mut OnChainDidDetails<T>> {
        match self {
            DidDetailStorage::OnChain(details) => Some(details),
            _ => None,
        }
    }
}
