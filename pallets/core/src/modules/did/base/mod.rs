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

/// Either `did:dock:*` or `did:key:*`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(omit_prefix)]
pub enum DidOrDidMethodKey {
    Did(Did),
    DidMethodKey(DidMethodKey),
}

impl<Target> AuthorizeTarget<Target, DidKey> for DidOrDidMethodKey
where
    Did: AuthorizeTarget<Target, DidKey>,
{
    fn ensure_authorizes_target<T, A>(&self, key: &DidKey, action: &A) -> Result<(), Error<T>>
    where
        T: crate::did::Config,
        A: Action<Target = Target>,
    {
        match self {
            DidOrDidMethodKey::Did(did) => did.ensure_authorizes_target(key, action),
            _ => Err(Error::<T>::ExpectedDid),
        }
    }
}

impl<Target> AuthorizeTarget<Target, DidMethodKey> for DidOrDidMethodKey
where
    DidMethodKey: AuthorizeTarget<Target, DidMethodKey>,
{
    fn ensure_authorizes_target<T, A>(&self, key: &DidMethodKey, action: &A) -> Result<(), Error<T>>
    where
        T: crate::did::Config,
        A: Action<Target = Target>,
    {
        match self {
            DidOrDidMethodKey::DidMethodKey(did_method_key) => {
                did_method_key.ensure_authorizes_target(key, action)
            }
            _ => Err(Error::<T>::ExpectedDidMethodKey),
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
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Did(#[cfg_attr(feature = "serde", serde(with = "crate::util::serde_hex"))] pub RawDid);

impl Debug for Did {
    fn fmt(
        &self,
        f: &mut scale_info::prelude::fmt::Formatter<'_>,
    ) -> scale_info::prelude::fmt::Result {
        write!(f, "0x{}", ::hex::encode(&self.0[..]))
    }
}

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

    pub fn to_offchain(&self) -> Option<&OffChainDidDetails<T>> {
        match self {
            StoredDidDetails::OffChain(details) => Some(details),
            _ => None,
        }
    }

    pub fn to_onchain(&self) -> Option<&StoredOnChainDidDetails<T>> {
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

    pub fn nonce(&self) -> Option<T::BlockNumber> {
        self.to_onchain().map(|with_nonce| with_nonce.nonce)
    }

    pub fn try_update_onchain(
        &mut self,
        nonce: <T as Types>::BlockNumber,
    ) -> Result<&mut OnChainDidDetails, Error<T>>
    where
        T: Config,
    {
        self.to_onchain_mut()
            .ok_or(Error::<T>::ExpectedOnChainDid)?
            .try_update(nonce)
            .map_err(Into::into)
    }
}

impl<T: Config> From<StoredDidDetails<T>> for WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>> {
    fn from(details: StoredDidDetails<T>) -> Self {
        let nonce = details.nonce().unwrap_or_default();

        WithNonce::new_with_nonce(DidDetailsOrDidMethodKeyDetails::DidDetails(details), nonce)
    }
}

impl<T: Config> TryFrom<StoredOnChainDidDetails<T>>
    for WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>
{
    type Error = Error<T>;

    fn try_from(details: StoredOnChainDidDetails<T>) -> Result<Self, Self::Error> {
        let nonce = details.nonce;

        Ok(WithNonce::new_with_nonce(
            DidDetailsOrDidMethodKeyDetails::DidDetails(details.into()),
            nonce,
        ))
    }
}

impl<T: Config> From<WithNonce<T, ()>> for WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>> {
    fn from(this: WithNonce<T, ()>) -> Self {
        WithNonce::new_with_nonce(
            DidDetailsOrDidMethodKeyDetails::DidMethodKeyDetails,
            this.nonce,
        )
    }
}

impl<T: Config> TryFrom<WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>> for WithNonce<T, ()> {
    type Error = Error<T>;

    fn try_from(
        details: WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>,
    ) -> Result<Self, Self::Error> {
        let nonce = details.nonce;

        match details.into_data() {
            DidDetailsOrDidMethodKeyDetails::DidMethodKeyDetails => {
                Ok(WithNonce::new_with_nonce((), nonce))
            }
            _ => Err(Error::<T>::ExpectedDidMethodKey),
        }
    }
}

impl<T: Config> TryFrom<WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>> for StoredDidDetails<T> {
    type Error = Error<T>;

    fn try_from(
        details: WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>,
    ) -> Result<Self, Self::Error> {
        let nonce = details.nonce;

        match details.into_data() {
            DidDetailsOrDidMethodKeyDetails::DidDetails(mut details) => {
                details.try_update_onchain(nonce)?;

                Ok(details)
            }
            _ => Err(Error::<T>::ExpectedDid),
        }
    }
}

impl<T: Config> TryFrom<WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>>
    for StoredOnChainDidDetails<T>
{
    type Error = Error<T>;

    fn try_from(
        details: WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>,
    ) -> Result<Self, Self::Error> {
        let nonce = details.nonce;

        match details.into_data() {
            DidDetailsOrDidMethodKeyDetails::DidDetails(details) => {
                let onchain_details: StoredOnChainDidDetails<T> = details.try_into()?;
                if onchain_details.nonce != nonce {
                    Err(NonceError::IncorrectNonce)?
                }

                Ok(onchain_details)
            }
            _ => Err(Error::<T>::ExpectedDid),
        }
    }
}

pub enum DidDetailsOrDidMethodKeyDetails<T: TypesAndLimits> {
    DidDetails(StoredDidDetails<T>),
    DidMethodKeyDetails,
}

impl<T: Config> StorageRef<T> for DidOrDidMethodKey {
    type Value = WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<Self::Value>) -> Result<R, E>,
    {
        match self {
            Self::Did(did) => did.try_mutate_associated(|details| details.update_with(f)),
            Self::DidMethodKey(did_method_key) => {
                did_method_key.try_mutate_associated(|details| details.update_with(f))
            }
        }
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<Self::Value>) -> R,
    {
        match self {
            Self::Did(did) => did.view_associated(|details_opt| {
                f(details_opt.map(TryInto::try_into).and_then(Result::ok))
            }),
            Self::DidMethodKey(did_method_key) => {
                did_method_key.view_associated(|details| f(details.map(Into::into)))
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Inserts details for the given `DID`.
    pub(crate) fn insert_did_details<D: Into<StoredDidDetails<T>>>(did: Did, did_details: D) {
        Dids::<T>::insert(did, did_details.into())
    }
}
