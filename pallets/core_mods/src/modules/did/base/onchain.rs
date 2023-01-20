use super::super::*;
use crate::{
    bbs_plus::BbsPlusKeys, deposit_indexed_event, util::WrappedActionWithNonce, ToStateChange,
};

/// Each on-chain DID is associated with a nonce that is incremented each time the DID does a
/// write (through an extrinsic). The nonce starts from the block number when the DID was created to avoid
/// replay attacks where an action of a DID that is removed and recreated by the same owner and same key
/// is replayed by someone else.
pub type StoredOnChainDidDetails<T> = WithNonce<T, OnChainDidDetails>;

/// Stores details of an on-chain DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Default)]
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
            .ok_or(Error::<T>::CannotGetDetailForOnChainDid)
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

impl<T: Config + Debug> Module<T> {
    pub(crate) fn new_onchain_(
        did: Did,
        keys: Vec<UncheckedDidKey>,
        mut controllers: BTreeSet<Controller>,
    ) -> Result<(), Error<T>> {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        let keys: Vec<_> = keys
            .into_iter()
            .map(DidKey::try_from)
            .collect::<Result<_, _>>()?;

        let controller_keys_count = keys.iter().filter(|key| key.can_control()).count() as u32;
        // Make self controlled if needed
        if controller_keys_count > 0 {
            controllers.insert(Controller(did));
        }
        ensure!(!controllers.is_empty(), Error::<T>::NoControllerProvided);

        let mut last_key_id = IncId::new();
        for (key, key_id) in keys.into_iter().zip(&mut last_key_id) {
            DidKeys::insert(&did, key_id, key);
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, &ctrl, ());
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
    ) -> Result<(), Error<T>> {
        // This will result in the removal of DID from storage map `Dids`
        details.take();

        // TODO: limit and cursor
        let _ = DidKeys::clear_prefix(did, u32::MAX, None);
        // TODO: limit and cursor
        let _ = DidControllers::clear_prefix(did, u32::MAX, None);
        // TODO: limit and cursor
        let _ = DidServiceEndpoints::clear_prefix(did, u32::MAX, None);
        // TODO: limit and cursor
        let _ = BbsPlusKeys::clear_prefix(did, u32::MAX, None);

        deposit_indexed_event!(OnChainDidRemoved(did));
        Ok(())
    }

    /// Try executing an action by a DID. Each action of a DID is supposed to have a nonce which should
    /// be one more than the current one. This function will check that payload has correct nonce and
    /// will then execute the given function `f` on the action and if `f` executes successfully, it will increment
    /// the DID's nonce by 1.
    pub(crate) fn try_exec_signed_action_from_onchain_did<A, F, S, R, E>(
        f: F,
        action: A,
        signature: DidSignature<S>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, S) -> Result<R, E>,
        A: ActionWithNonce<T> + ToStateChange<T>,
        S: Into<Did> + Copy,
        E: From<Error<T>> + From<NonceError>,
    {
        ensure!(
            Self::verify_sig_from_auth_or_control_key(&action, &signature)?,
            Error::<T>::InvalidSignature
        );

        Self::try_exec_action_over_onchain_did(
            |WrappedActionWithNonce { action, target, .. }, _| f(action, target),
            WrappedActionWithNonce::new(action.nonce(), signature.did, action),
        )
    }

    /// Try to execute an action signed by a DID that controls (possibly) another DID. This means nonce of signing DID
    /// must be checked and increased if the action is successful. Also the DID Doc of the controlled
    /// DID will change
    pub(crate) fn try_exec_signed_action_from_controller<A, F, R, E>(
        f: F,
        action: A,
        signature: DidSignature<Controller>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut OnChainDidDetails) -> Result<R, E>,
        A: ActionWithNonce<T, Target = Did> + ToStateChange<T>,
        A::Target: Into<Did>,
        E: From<Error<T>> + From<NonceError>,
    {
        Self::try_exec_signed_removable_action_from_controller(
            |action, details_opt| f(action, details_opt.as_mut().unwrap()),
            action,
            signature,
        )
    }

    /// Same as `Self::try_exec_signed_action_from_controller` except that the DID
    /// Doc of controlled DID might be removed on completion.
    pub(crate) fn try_exec_signed_removable_action_from_controller<A, F, R, E>(
        f: F,
        action: A,
        signature: DidSignature<Controller>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<OnChainDidDetails>) -> Result<R, E>,
        A: ActionWithNonce<T, Target = Did> + ToStateChange<T>,
        E: From<Error<T>> + From<NonceError>,
    {
        ensure!(
            Self::verify_sig_from_controller(&action, &signature)?,
            Error::<T>::InvalidSignature
        );

        if action.target() != *signature.did {
            let wrapped_action = WrappedActionWithNonce::new(action.nonce(), signature.did, action);

            // Target DID and acting (signer) DID are different and thus both DID's details must be modified
            Self::try_exec_removable_action_over_onchain_did(
                |WrappedActionWithNonce { action, .. }, _| {
                    Dids::<T>::try_mutate_exists(action.target(), |details_opt| {
                        WithNonce::try_update_opt_without_increasing_nonce_with(
                            details_opt,
                            |data_opt| f(action, data_opt),
                        )
                        .ok_or(Error::<T>::DidDoesNotExist)?
                    })
                },
                wrapped_action,
            )
        } else {
            // Target DID and acting (signer) DID are the same
            Self::try_exec_removable_action_over_onchain_did(f, action)
        }
    }

    crate::pub_for_test! {
        /// Executes action over target on-chain DID providing a mutable reference if the given
        /// nonce is correct, i.e. 1 more than the current nonce.
        fn try_exec_action_over_onchain_did<A, F, R, E>(f: F, action: A) -> Result<R, E>
        where
            F: FnOnce(A, &mut OnChainDidDetails) -> Result<R, E>,
            A: ActionWithNonce<T>,
            A::Target: Into<Did>,
            E: From<Error<T>> + From<NonceError>,
        {
            Self::try_exec_removable_action_over_onchain_did(|action, details_opt| {
                f(action, details_opt.as_mut().unwrap())
            }, action)
        }
    }

    crate::pub_for_test! {
        /// Executes action over target on-chain DID providing a mutable reference if the given
        /// nonce is correct, i.e. 1 more than the current nonce.
        /// Unlike `try_exec_action_over_onchain_did`, this action may result in a removal of a DID,
        /// if the value under option will be taken.
        fn try_exec_removable_action_over_onchain_did<A, F, R, E>(
            f: F,
            action: A,
        ) -> Result<R, E>
        where
            F: FnOnce(A, &mut Option<OnChainDidDetails>) -> Result<R, E>,
            A: ActionWithNonce<T>,
            A::Target: Into<Did>,
            E: From<Error<T>> + From<NonceError>,
        {
            ensure!(!action.is_empty(), Error::<T>::EmptyPayload);

            Dids::<T>::try_mutate_exists(action.target().into(), |cnt_details_opt| {
                WithNonce::try_update_opt_with(cnt_details_opt, action.nonce(), |data_opt| {
                    f(action, data_opt)
                })
                .ok_or(Error::<T>::DidDoesNotExist)?
            })
        }
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
