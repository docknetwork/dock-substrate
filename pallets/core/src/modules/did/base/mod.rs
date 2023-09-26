use crate::{common::TypesAndLimits, impl_wrapper};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_std::{
    fmt::Debug,
    ops::{Index, RangeFull},
};

use super::*;

pub mod offchain;
pub mod onchain;
pub mod signature;

pub use offchain::*;
pub use onchain::*;
pub use signature::DidSignature;

/// The type of the Dock `DID`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Did(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub RawDid);

impl Did {
    /// Size of the Dock DID in bytes
    pub const BYTE_SIZE: usize = 32;
}

impl_wrapper! { Did(RawDid), with tests as did_tests }

/// Raw DID representation.
pub type RawDid = [u8; Did::BYTE_SIZE];

impl Index<RangeFull> for Did {
    type Output = RawDid;

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

/// Contains underlying DID describing its storage type.
#[derive(Encode, Decode, DebugNoBound, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum StoredDidDetails<T: TypesAndLimits> {
    /// For off-chain DID, most data is stored off-chain.
    OffChain(OffChainDidDetails<T>),
    /// For on-chain DID, all data is stored on the chain.
    OnChain(StoredOnChainDidDetails<T>),
}

impl<T: TypesAndLimits> StoredDidDetails<T> {
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

    pub fn into_onchain(self) -> Option<StoredOnChainDidDetails<T>> {
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

    pub fn to_onchain_mut(&mut self) -> Option<&mut StoredOnChainDidDetails<T>> {
        match self {
            StoredDidDetails::OnChain(details) => Some(details),
            _ => None,
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Inserts details for the given `DID`.
    pub(crate) fn insert_did_details<D: Into<StoredDidDetails<T>>>(did: Did, did_details: D) {
        Dids::<T>::insert(did, did_details.into())
    }
}
