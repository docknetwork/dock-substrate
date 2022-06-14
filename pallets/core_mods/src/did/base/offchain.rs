use super::super::*;

/// Stores details of an off-chain DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
pub struct OffChainDidDetails<T: Trait> {
    pub account_id: T::AccountId,
    pub doc_ref: OffChainDidDocRef,
}

impl<T: Trait> From<OffChainDidDetails<T>> for DidDetailStorage<T> {
    fn from(details: OffChainDidDetails<T>) -> Self {
        Self::OffChain(details)
    }
}

impl<T: Trait> OffChainDidDetails<T> {
    /// Constructs new off-chain DID details using supplied params.
    pub fn new(account_id: T::AccountId, doc_ref: OffChainDidDocRef) -> Self {
        Self {
            account_id,
            doc_ref,
        }
    }
}

/// To describe the off chain DID Doc's reference. This is just to inform the client, this module
/// does not check if the bytes are indeed valid as per the enum variant
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OffChainDidDocRef {
    /// Content IDentifier as per https://github.com/multiformats/cid.
    CID(WrappedBytes),
    /// A URL
    URL(WrappedBytes),
    /// A custom encoding of the reference
    Custom(WrappedBytes),
}

impl OffChainDidDocRef {
    pub fn len(&self) -> usize {
        match self {
            OffChainDidDocRef::CID(v) => v.len(),
            OffChainDidDocRef::URL(v) => v.len(),
            OffChainDidDocRef::Custom(v) => v.len(),
        }
    }
}

impl<T: Trait + Debug> Module<T> {
    pub(crate) fn new_offchain_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef,
    ) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        Dids::<T>::insert::<_, DidDetailStorage<T>>(
            did,
            OffChainDidDetails::new(caller, did_doc_ref.clone()).into(),
        );
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did[..])],
            <T as Trait>::Event::from(Event::OffChainDidAdded(did, did_doc_ref)).into(),
        );
        Ok(())
    }

    pub(crate) fn set_offchain_did_uri_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef,
    ) -> DispatchResult {
        Self::ensure_offchain_did_be_updated(&caller, &did)?;

        Dids::<T>::insert::<_, DidDetailStorage<T>>(
            did,
            OffChainDidDetails::new(caller, did_doc_ref.clone()).into(),
        );
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did[..])],
            <T as Trait>::Event::from(Event::OffChainDidUpdated(did, did_doc_ref)).into(),
        );
        Ok(())
    }

    pub(crate) fn remove_offchain_did_(caller: T::AccountId, did: Did) -> DispatchResult {
        Self::ensure_offchain_did_be_updated(&caller, &did)?;

        Dids::<T>::remove(did);
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did[..])],
            <T as Trait>::Event::from(Event::OffChainDidRemoved(did)).into(),
        );
        Ok(())
    }

    pub fn is_offchain_did(did: &Did) -> Result<bool, Error<T>> {
        Self::did(did)
            .as_ref()
            .map(DidDetailStorage::is_offchain)
            .ok_or(Error::<T>::DidDoesNotExist)
    }

    /// Check that given DID is off-chain and owned by the caller
    pub fn ensure_offchain_did_be_updated(
        caller: &T::AccountId,
        did: &Did,
    ) -> Result<(), DispatchError> {
        let account_id = Self::did(did)
            .ok_or(Error::<T>::DidDoesNotExist)?
            .into_offchain()
            .ok_or(Error::<T>::NotAnOffChainDid)?
            .account_id;

        ensure!(account_id == *caller, Error::<T>::DidNotOwnedByAccount);

        Ok(())
    }
}
