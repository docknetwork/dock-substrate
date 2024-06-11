use super::super::*;
use crate::{
    common::TypesAndLimits,
    deposit_indexed_event,
    util::{StorageRef, WithNonce},
};

/// Each on-chain DID is associated with a nonce that is incremented each time the DID does a
/// write (through an extrinsic). The nonce starts from the block number when the DID was created to avoid
/// replay attacks where an action of a DID that is removed and recreated by the same owner and same key
/// is replayed by someone else.
pub type StoredOnChainDidDetails<T> = WithNonce<T, OnChainDidDetails>;

/// Stores details of an on-chain DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Default, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct OnChainDidDetails {
    /// Number of keys added for this DID so far.
    pub last_key_id: IncId,
    /// Number of currently active controller keys.
    pub active_controller_keys: u32,
    /// Number of currently active controllers.
    pub active_controllers: u32,
}

impl<T: TypesAndLimits> From<StoredOnChainDidDetails<T>> for StoredDidDetails<T> {
    fn from(details: StoredOnChainDidDetails<T>) -> Self {
        Self::OnChain(details)
    }
}

impl<T: Config> TryFrom<StoredDidDetails<T>> for StoredOnChainDidDetails<T> {
    type Error = Error<T>;

    fn try_from(details: StoredDidDetails<T>) -> Result<Self, Self::Error> {
        details.into_onchain().ok_or(Error::<T>::ExpectedOnChainDid)
    }
}

impl<T: TypesAndLimits> Associated<T> for Did {
    type Value = StoredDidDetails<T>;
}

impl<T: Config> StorageRef<T> for Did {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<StoredDidDetails<T>>) -> Result<R, E>,
    {
        Dids::<T>::try_mutate_exists(self, |details| details.update_with(f))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<StoredDidDetails<T>>) -> R,
    {
        f(Dids::<T>::get(self))
    }
}

impl OnChainDidDetails {
    /// Constructs new on-chain DID details using supplied params.
    ///
    /// - `last_key_id` - last incremental identifier of the key being used for the given DID.
    /// - `active_controller_keys` - amount of currently active controller keys for the given DID.
    /// - `active_controllers` - amount of currently active controllers for the given DID.
    pub fn new(last_key_id: IncId, active_controller_keys: u32, active_controllers: u32) -> Self {
        Self {
            last_key_id,
            active_controller_keys,
            active_controllers,
        }
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn new_onchain_(
        did: Did,
        keys: Vec<UncheckedDidKey>,
        mut controllers: BTreeSet<Controller>,
    ) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        let keys: Vec<_> = keys
            .into_iter()
            .map(DidKey::try_from)
            .collect::<Result<_, _>>()
            .map_err(Error::<T>::from)?;

        let controller_keys_count = keys.iter().filter(|key| key.can_control()).count() as u32;
        // Make self controlled if needed
        if controller_keys_count > 0 {
            controllers.insert(Controller(did.into()));
        }
        ensure!(!controllers.is_empty(), Error::<T>::NoControllerProvided);

        let mut last_key_id = IncId::new();
        for (key, key_id) in keys.into_iter().zip(&mut last_key_id) {
            DidKeys::<T>::insert(did, key_id, key);
        }

        for ctrl in &controllers {
            DidControllers::<T>::insert(did, ctrl, ());
        }

        let did_details = WithNonce::new(OnChainDidDetails::new(
            last_key_id,
            controller_keys_count,
            controllers.len() as u32,
        ));

        Self::insert_did_details(did, did_details);

        deposit_indexed_event!(OnChainDidAdded(did));
        Ok(())
    }

    pub(crate) fn remove_onchain_did_(
        DidRemoval { did, .. }: DidRemoval<T>,
        details: &mut Option<OnChainDidDetails>,
    ) -> DispatchResult {
        // This will result in the removal of DID from storage map `Dids`
        details.take().ok_or(Error::<T>::OnchainDidDoesntExist)?;

        // TODO: limit and cursor
        let _ = DidKeys::<T>::clear_prefix(did, u32::MAX, None);
        // TODO: limit and cursor
        let _ = DidControllers::<T>::clear_prefix(did, u32::MAX, None);
        // TODO: limit and cursor
        let _ = DidServiceEndpoints::<T>::clear_prefix(did, u32::MAX, None);
        // TODO: dynamic weight
        let _ = T::OnDidRemoval::on_did_removal(did);

        deposit_indexed_event!(OnChainDidRemoved(did));
        Ok(())
    }

    pub fn is_onchain_did(did: &Did) -> Result<bool, Error<T>> {
        Self::did(did)
            .as_ref()
            .map(StoredDidDetails::is_onchain)
            .ok_or(Error::<T>::DidDoesNotExist)
    }

    /// Get DID detail of an on-chain DID. Throws error if DID does not exist or is off-chain.
    pub fn onchain_did_details(did: &Did) -> Result<StoredOnChainDidDetails<T>, Error<T>> {
        Self::did(did)
            .ok_or(Error::<T>::DidDoesNotExist)?
            .try_into()
    }
}
