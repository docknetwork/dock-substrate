use sp_std::ops::{Index, RangeFull};

use super::*;

pub mod offchain;
pub mod onchain;
pub mod signature;

pub use offchain::*;
pub use onchain::*;
pub use signature::DidSignature;

/// Raw DID representation.
pub type RawDid = [u8; Did::BYTE_SIZE];

/// The type of the Dock DID.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Did(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub RawDid);

impl Did {
    /// Size of the Dock DID in bytes
    pub const BYTE_SIZE: usize = 32;
}

impl From<RawDid> for Did {
    fn from(raw: RawDid) -> Did {
        Did(raw)
    }
}

impl From<Did> for RawDid {
    fn from(Did(raw): Did) -> RawDid {
        raw
    }
}

impl Index<RangeFull> for Did {
    type Output = RawDid;

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

/// Contains underlying DID describing its storage type.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
pub enum StoredDidDetails<T: Trait> {
    /// Off-chain DID has no need of nonce as the signature is made on the whole transaction by
    /// the caller account and Substrate takes care of replay protection. Thus it stores the data
    /// about off-chain DID Doc (hash, URI or any other reference) and the account that owns it.
    OffChain(OffChainDidDetails<T>),
    /// For on-chain DID, all data is stored on the chain.
    OnChain(OnChainDidDetails<T>),
}

impl<T: Trait> StoredDidDetails<T> {
    pub fn is_onchain(&self) -> bool {
        matches!(self, StoredDidDetails::OnChain(_))
    }

    pub fn is_offchain(&self) -> bool {
        matches!(self, StoredDidDetails::OffChain(_))
    }

    pub fn into_offchain(self) -> Option<OffChainDidDetails<T>> {
        match self {
            StoredDidDetails::OffChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn into_onchain(self) -> Option<OnChainDidDetails<T>> {
        match self {
            StoredDidDetails::OnChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn to_offchain_mut(&mut self) -> Option<&mut OffChainDidDetails<T>> {
        match self {
            StoredDidDetails::OffChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn to_onchain_mut(&mut self) -> Option<&mut OnChainDidDetails<T>> {
        match self {
            StoredDidDetails::OnChain(details) => Some(details),
            _ => None,
        }
    }
}
