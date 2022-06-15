use super::super::*;

/// Stores details of an on-chain DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
pub struct OnChainDidDetails<T: Trait> {
    /// The nonce is set to the current block number when a DID is registered. Subsequent updates/removal
    /// should supply a nonce 1 more than the current nonce of the DID and on successful update, the
    /// new nonce is stored with the DID. The reason for starting the nonce with current block number
    /// and not 0 is to prevent replay attack where a signed payload of removed DID is used to perform
    /// replay on the same DID created again as nonce would be reset to 0 for new DIDs.
    pub nonce: T::BlockNumber,
    /// Number of keys added for this DID so far.
    pub last_key_id: IncId,
    /// Number of currently active controller keys.
    pub active_controller_keys: u32,
    /// Number of currently active controllers.
    pub active_controllers: u32,
}

impl<T: Trait> From<OnChainDidDetails<T>> for StoredDidDetails<T> {
    fn from(details: OnChainDidDetails<T>) -> Self {
        Self::OnChain(details)
    }
}

impl<T: Trait + Debug> OnChainDidDetails<T> {
    /// Constructs new on-chain DID details using supplied params.
    ///
    /// - `nonce` - to be used as base for next actions for the given DID.
    /// - `last_key_id` - last incremental identifier of the key being used for the given DID.
    /// - `active_controller_keys` - amount of currenlty active controller keys for the given DID.
    /// - `active_controllers` - amount of currently active controllers for the given DID.
    pub fn new(
        nonce: T::BlockNumber,
        last_key_id: IncId,
        active_controller_keys: impl Into<u32>,
        active_controllers: impl Into<u32>,
    ) -> Self {
        Self {
            nonce,
            last_key_id,
            active_controller_keys: active_controller_keys.into(),
            active_controllers: active_controllers.into(),
        }
    }

    /// Increases current nonce if provided nonce is equal to current nonce plus 1, otherwise
    /// returns an error.
    pub fn inc_nonce(&mut self, nonce: T::BlockNumber) -> Result<(), Error<T>> {
        if nonce == self.nonce + 1u8.into() {
            self.nonce += 1u8.into();

            Ok(())
        } else {
            Err(Error::<T>::IncorrectNonce)
        }
    }
}

impl<T: Trait + Debug> Module<T> {
    pub(crate) fn new_onchain_(
        did: Did,
        keys: Vec<DidKey>,
        mut controllers: BTreeSet<Controller>,
    ) -> Result<(), Error<T>> {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        let (keys_to_insert, controller_keys_count) = Self::prepare_keys_to_insert(keys)?;
        // Make self controlled if needed
        if controller_keys_count > 0 {
            controllers.insert(Controller(did));
        }
        ensure!(!controllers.is_empty(), Error::<T>::NoControllerProvided);

        let mut last_key_id = IncId::new();
        for (key, key_id) in keys_to_insert.into_iter().zip(&mut last_key_id) {
            DidKeys::insert(&did, key_id, key);
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, &ctrl, ());
        }

        // Nonce will start from current block number
        let nonce = <system::Module<T>>::block_number();
        let did_details: StoredDidDetails<T> = OnChainDidDetails::new(
            nonce,
            last_key_id,
            controller_keys_count,
            controllers.len() as u32,
        )
        .into();

        Dids::<T>::insert(did, did_details);

        deposit_indexed_event!(OnChainDidAdded(did));
        Ok(())
    }

    pub(crate) fn remove_onchain_did_(
        DidRemoval { did, nonce }: DidRemoval<T>,
    ) -> Result<(), Error<T>> {
        Self::onchain_did_details(&did)?.inc_nonce(nonce)?;

        DidKeys::remove_prefix(did);
        DidControllers::remove_prefix(did);
        DidServiceEndpoints::remove_prefix(did);
        Dids::<T>::remove(did);

        deposit_indexed_event!(OnChainDidRemoved(did));
        Ok(())
    }

    /// Executes action over target on-chain DID providing a mutable reference if the given nonce is correct,
    /// i.e. 1 more than the current nonce.
    pub(crate) fn exec_onchain_did_action<A, F, R>(action: A, f: F) -> Result<R, Error<T>>
    where
        F: FnOnce(A, &mut OnChainDidDetails<T>) -> Result<R, Error<T>>,
        A: Action<T, Target = Did>,
    {
        Dids::<T>::try_mutate(action.target(), |details_opt| {
            let onchain_details = details_opt
                .as_mut()
                .ok_or(Error::<T>::DidDoesNotExist)?
                .to_onchain_mut()
                .ok_or(Error::<T>::CannotGetDetailForOffChainDid)?;

            onchain_details.inc_nonce(action.nonce())?;

            f(action, onchain_details)
        })
    }

    pub fn is_onchain_did(did: &Did) -> Result<bool, Error<T>> {
        Self::did(did)
            .as_ref()
            .map(StoredDidDetails::is_onchain)
            .ok_or(Error::<T>::DidDoesNotExist)
    }

    /// Get DID detail of an on-chain DID. Throws error if DID does not exist or is off-chain.
    pub fn onchain_did_details(did: &Did) -> Result<OnChainDidDetails<T>, Error<T>> {
        Self::did(did)
            .ok_or(Error::<T>::DidDoesNotExist)?
            .into_onchain()
            .ok_or(Error::<T>::CannotGetDetailForOffChainDid)
    }
}
