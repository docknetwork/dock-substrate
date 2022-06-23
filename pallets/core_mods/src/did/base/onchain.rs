use sp_runtime::DispatchError;

use super::super::*;

/// Each on-chain DID is associated with a nonce that is incremented each time the DID does a write (through an extrinsic)
pub type StoredOnChainDidDetails<T> = WithNonce<T, OnChainDidDetails>;

/// Stores details of an on-chain DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OnChainDidDetails {
    /// Number of keys added for this DID so far.
    pub last_key_id: IncId,
    /// Number of currently active controller keys.
    pub active_controller_keys: u32,
    /// Number of currently active controllers.
    pub active_controllers: u32,
}

impl<T: Config> From<StoredOnChainDidDetails<T>> for StoredDidDetails<T> {
    fn from(details: StoredOnChainDidDetails<T>) -> Self {
        Self::OnChain(details)
    }
}

impl<T: Config + Debug> TryFrom<StoredDidDetails<T>> for StoredOnChainDidDetails<T> {
    type Error = Error<T>;

    fn try_from(details: StoredDidDetails<T>) -> Result<Self, Self::Error> {
        details
            .into_onchain()
            .ok_or(Error::<T>::CannotGetDetailForOffChainDid)
    }
}

struct DidActionWrapper<T: Config, A> {
    action: A,
    did: Did,
    nonce: T::BlockNumber,
}

impl<T: Config, A: Action<T>> Action<T> for DidActionWrapper<T, A> {
    type Target = Did;

    fn target(&self) -> Self::Target {
        self.did
    }

    fn len(&self) -> u32 {
        self.action.len()
    }

    fn to_state_change(&self) -> crate::StateChange<'_, T> {
        self.action.to_state_change()
    }

    fn into_state_change(self) -> crate::StateChange<'static, T> {
        self.action.into_state_change()
    }
}

impl<T: Config, A: Action<T>> ActionWithNonce<T> for DidActionWrapper<T, A> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}

impl OnChainDidDetails {
    /// Constructs new on-chain DID details using supplied params.
    ///
    /// - `last_key_id` - last incremental identifier of the key being used for the given DID.
    /// - `active_controller_keys` - amount of currently active controller keys for the given DID.
    /// - `active_controllers` - amount of currently active controllers for the given DID.
    pub fn new(
        last_key_id: IncId,
        active_controller_keys: impl Into<u32>,
        active_controllers: impl Into<u32>,
    ) -> Self {
        Self {
            last_key_id,
            active_controller_keys: active_controller_keys.into(),
            active_controllers: active_controllers.into(),
        }
    }
}

impl<T: Config + Debug> Module<T> {
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

        let did_details: StoredDidDetails<T> = StoredOnChainDidDetails::new(
            OnChainDidDetails::new(last_key_id, controller_keys_count, controllers.len() as u32),
        )
        .into();

        Dids::<T>::insert(did, did_details);

        deposit_indexed_event!(OnChainDidAdded(did));
        Ok(())
    }

    pub(crate) fn remove_onchain_did_(
        DidRemoval { did, .. }: DidRemoval<T>,
        details: &mut Option<OnChainDidDetails>,
    ) -> Result<Option<()>, DispatchError> {
        // This will result in the removal of DID from storage map `Dids`
        details.take();
        DidKeys::remove_prefix(did);
        DidControllers::remove_prefix(did);
        DidServiceEndpoints::remove_prefix(did);

        deposit_indexed_event!(OnChainDidRemoved(did));
        Ok(None)
    }

    /// Executes action over target on-chain DID providing a mutable reference if the given nonce is correct,
    /// i.e. 1 more than the current nonce.
    /// Unlike `try_exec_onchain_did_action`, this action may result in a removal of a DID, if the value under option
    /// will be taken.
    pub(crate) fn try_exec_removable_onchain_did_action<A, F, R, E>(
        action: A,
        f: F,
    ) -> Result<R, DispatchError>
    where
        F: FnOnce(A, &mut Option<OnChainDidDetails>) -> Result<R, E>,
        A: ActionWithNonce<T>,
        A::Target: Into<Did>,
        DispatchError: From<Error<T>> + From<E>,
    {
        Dids::<T>::try_mutate_exists(action.target().into(), |details_opt| {
            WithNonce::try_inc_opt_nonce_with(details_opt, action.nonce(), |data_opt| {
                f(action, data_opt).map_err(DispatchError::from)
            })
            .ok_or(Error::<T>::DidDoesNotExist)?
        })
    }

    /// Executes action over target on-chain DID providing a mutable reference if the given nonce is correct,
    /// i.e. 1 more than the current nonce.
    pub(crate) fn try_exec_onchain_did_action<A, F, R, E>(
        action: A,
        f: F,
    ) -> Result<R, DispatchError>
    where
        F: FnOnce(A, &mut OnChainDidDetails) -> Result<R, E>,
        A: ActionWithNonce<T>,
        A::Target: Into<Did>,
        DispatchError: From<Error<T>> + From<E>,
    {
        Self::try_exec_removable_onchain_did_action(action, |action, details_opt| {
            f(action, details_opt.as_mut().unwrap())
        })
    }

    /// Try executing an action by a DID. Each action of a DID is supposed to have a nonce which should
    /// be one more than the current one. This function will check that payload has correct nonce and
    /// will then execute the given function `f` on te action and if `f` executes successfully, it will increment
    /// the DID's nonce by 1.
    pub(crate) fn try_exec_by_onchain_did<A, F, S, R, E>(
        action: A,
        did: S,
        f: F,
    ) -> Result<R, DispatchError>
    where
        F: FnOnce(A, S) -> Result<R, E>,
        A: ActionWithNonce<T>,
        S: Into<Did> + Copy,
        DispatchError: From<Error<T>> + From<E>,
    {
        let wrapped = DidActionWrapper {
            did: did.into(),
            nonce: action.nonce(),
            action,
        };

        Self::try_exec_onchain_did_action(wrapped, |wrapper, _| f(wrapper.action, did))
    }

    pub(crate) fn insert_onchain_did(did: &Did, onchain_did_detail: StoredOnChainDidDetails<T>) {
        let did_details: StoredDidDetails<T> = onchain_did_detail.into();
        Dids::<T>::insert(did, did_details)
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
            .into_onchain()
            .ok_or(Error::<T>::CannotGetDetailForOnChainDid)
    }
}
