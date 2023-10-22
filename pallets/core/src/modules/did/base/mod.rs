use crate::{
    common::{AuthorizeTarget, TypesAndLimits},
    impl_wrapper,
};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_std::{
    fmt::Debug,
    ops::{Index, RangeFull},
};

use super::*;

pub mod did_method_key;
pub mod offchain;
pub mod onchain;
pub mod signature;

pub use did_method_key::*;
pub use offchain::*;
pub use onchain::*;
pub use signature::*;

/// Either Dock DID or `did:key`,
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum DidOrDidMethodKey {
    Did(Did),
    DidMethodKey(DidMethodKey),
}

impl<T: Config> StorageRef<T> for DidOrDidMethodKey {
    type Value = WithNonce<T, ()>;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<WithNonce<T, ()>>) -> Result<R, E>,
    {
        match self {
            Self::Did(did) => did.try_mutate_associated(|details| {
                details.update_with(|onchain_details: &mut Option<StoredOnChainDidDetails<T>>| {
                    let mut with_nonce = onchain_details
                        .as_ref()
                        .map(|details| WithNonce::new_with_nonce((), details.nonce));

                    let res = f(&mut with_nonce);

                    *onchain_details =
                        with_nonce
                            .zip(onchain_details.take())
                            .map(|(with_nonce, details)| {
                                WithNonce::new_with_nonce(details.into_data(), with_nonce.nonce)
                            });

                    res
                })
            }),
            Self::DidMethodKey(did_method_key) => did_method_key.try_mutate_associated(f),
        }
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<Self::Value>) -> R,
    {
        match self {
            Self::Did(did) => did.view_associated(|details_opt| {
                f(details_opt.and_then(|v| v.try_into().ok()).map(
                    |details: StoredOnChainDidDetails<T>| {
                        WithNonce::<T, _>::new_with_nonce((), details.nonce)
                    },
                ))
            }),
            Self::DidMethodKey(did_method_key) => did_method_key.view_associated(f),
        }
    }
}

impl From<Did> for DidOrDidMethodKey {
    fn from(did: Did) -> Self {
        Self::Did(did)
    }
}

impl From<DidMethodKey> for DidOrDidMethodKey {
    fn from(did: DidMethodKey) -> Self {
        Self::DidMethodKey(did)
    }
}

impl TryFrom<DidKeyOrDidMethodKey> for DidKey {
    type Error = DidMethodKey;

    fn try_from(did_key_or_did_method_key: DidKeyOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_key_or_did_method_key {
            DidKeyOrDidMethodKey::DidKey(did_key) => Ok(did_key),
            DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => Err(did_method_key),
        }
    }
}

impl TryFrom<DidKeyOrDidMethodKey> for DidMethodKey {
    type Error = DidKey;

    fn try_from(did_key_or_did_method_key: DidKeyOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_key_or_did_method_key {
            DidKeyOrDidMethodKey::DidKey(did_key) => Err(did_key),
            DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => Ok(did_method_key),
        }
    }
}

impl TryFrom<DidOrDidMethodKey> for Did {
    type Error = DidMethodKey;

    fn try_from(did_or_did_method_key: DidOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_or_did_method_key {
            DidOrDidMethodKey::Did(did) => Ok(did),
            DidOrDidMethodKey::DidMethodKey(did_key) => Err(did_key),
        }
    }
}

impl TryFrom<DidOrDidMethodKey> for DidMethodKey {
    type Error = Did;

    fn try_from(did_or_did_key: DidOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_or_did_key {
            DidOrDidMethodKey::Did(did) => Err(did),
            DidOrDidMethodKey::DidMethodKey(did_key) => Ok(did_key),
        }
    }
}

/// The type of the Dock `DID`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Did(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub RawDid);

impl<Target> AuthorizeTarget<Target, DidKey> for Did {
    fn ensure_authorizes_target<T, A>(&self, key: &DidKey, _: &A) -> Result<(), Error<T>>
    where
        T: crate::did::Config,
        A: Action<Target = Target>,
    {
        ensure!(
            key.can_authenticate_or_control(),
            Error::<T>::InsufficientVerificationRelationship
        );

        Ok(())
    }
}

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
