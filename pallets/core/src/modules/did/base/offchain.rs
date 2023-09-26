use super::super::*;
use crate::{common::TypesAndLimits, deposit_indexed_event};

/// Stores details of an off-chain DID.
/// Off-chain DID has no need of nonce as the signature is made on the whole transaction by
/// the caller account and Substrate takes care of replay protection. Thus it stores the data
/// about off-chain DID Doc (hash, URI or any other reference) and the account that owns it.
#[derive(Encode, Decode, DebugNoBound, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct OffChainDidDetails<T: TypesAndLimits> {
    pub account_id: T::AccountId,
    pub doc_ref: OffChainDidDocRef<T>,
}

impl<T: TypesAndLimits> From<OffChainDidDetails<T>> for StoredDidDetails<T> {
    fn from(details: OffChainDidDetails<T>) -> Self {
        Self::OffChain(details)
    }
}

impl<T: TypesAndLimits> TryFrom<StoredDidDetails<T>> for OffChainDidDetails<T> {
    type Error = Error<T>;

    fn try_from(details: StoredDidDetails<T>) -> Result<Self, Self::Error> {
        details
            .into_offchain()
            .ok_or(Error::<T>::CannotGetDetailForOffChainDid)
    }
}

impl<T: TypesAndLimits> OffChainDidDetails<T> {
    /// Constructs new off-chain DID details using supplied params.
    pub fn new(account_id: T::AccountId, doc_ref: OffChainDidDocRef<T>) -> Self {
        Self {
            account_id,
            doc_ref,
        }
    }

    /// Ensures that caller is able to update given off-chain DID.
    pub fn ensure_can_update(&self, caller: &T::AccountId) -> Result<(), Error<T>> {
        ensure!(&self.account_id == caller, Error::<T>::DidNotOwnedByAccount);

        Ok(())
    }
}

/// To describe the off chain DID Doc's reference. This is just to inform the client, this module
/// does not check if the bytes are indeed valid as per the enum variant
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum OffChainDidDocRef<T: Limits> {
    /// Content IDentifier as per https://github.com/multiformats/cid.
    CID(BoundedBytes<T::MaxDidDocRefSize>),
    /// A URL
    URL(BoundedBytes<T::MaxDidDocRefSize>),
    /// A custom encoding of the reference
    Custom(BoundedBytes<T::MaxDidDocRefSize>),
}

impl<T: Limits> OffChainDidDocRef<T> {
    pub fn len(&self) -> u32 {
        match self {
            OffChainDidDocRef::CID(v) => v.len() as u32,
            OffChainDidDocRef::URL(v) => v.len() as u32,
            OffChainDidDocRef::Custom(v) => v.len() as u32,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn new_offchain_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef<T>,
    ) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        let details = OffChainDidDetails::new(caller, did_doc_ref.clone());
        Self::insert_did_details(did, details);

        deposit_indexed_event!(OffChainDidAdded(did, did_doc_ref) over did);
        Ok(())
    }

    pub(crate) fn set_offchain_did_doc_ref_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef<T>,
    ) -> DispatchResult {
        Self::offchain_did_details(&did)?.ensure_can_update(&caller)?;

        let details: StoredDidDetails<T> =
            OffChainDidDetails::new(caller, did_doc_ref.clone()).into();
        Dids::<T>::insert(did, details);

        deposit_indexed_event!(OffChainDidUpdated(did, did_doc_ref) over did);
        Ok(())
    }

    pub(crate) fn remove_offchain_did_(caller: T::AccountId, did: Did) -> DispatchResult {
        Self::offchain_did_details(&did)?.ensure_can_update(&caller)?;

        Dids::<T>::remove(did);

        deposit_indexed_event!(OffChainDidRemoved(did));
        Ok(())
    }

    pub fn is_offchain_did(did: &Did) -> Result<bool, Error<T>> {
        Self::did(did)
            .as_ref()
            .map(StoredDidDetails::is_offchain)
            .ok_or(Error::<T>::DidDoesNotExist)
    }

    /// Get DID detail of an off-chain DID. Throws error if DID does not exist or is on-chain.
    pub fn offchain_did_details(did: &Did) -> Result<OffChainDidDetails<T>, Error<T>> {
        Self::did(did)
            .ok_or(Error::<T>::DidDoesNotExist)?
            .try_into()
    }
}
