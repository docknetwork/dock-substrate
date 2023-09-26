use super::*;

impl<T: Config> Pallet<T> {
    pub(super) fn create_(
        id: StatusListCredentialId,
        credential: StatusListCredentialWithPolicy<T>,
    ) -> DispatchResult {
        ensure!(
            !StatusListCredentials::<T>::contains_key(id),
            Error::<T>::StatusListCredentialAlreadyExists
        );
        credential.ensure_valid()?;

        StatusListCredentials::insert(id, credential);

        deposit_indexed_event!(StatusListCredentialCreated(id));
        Ok(())
    }

    pub(super) fn update_(
        UpdateStatusListCredentialRaw { id, credential, .. }: UpdateStatusListCredentialRaw<T>,
        status_list_credential: &mut StatusListCredentialWithPolicy<T>,
    ) -> DispatchResult {
        credential.ensure_valid()?;

        status_list_credential.status_list_credential = credential;

        deposit_indexed_event!(StatusListCredentialUpdated(id));
        Ok(())
    }

    pub(super) fn remove_(
        RemoveStatusListCredentialRaw { id, .. }: RemoveStatusListCredentialRaw<T>,
        status_list_credential: &mut Option<StatusListCredentialWithPolicy<T>>,
    ) -> DispatchResult {
        status_list_credential.take();

        deposit_indexed_event!(StatusListCredentialRemoved(id));
        Ok(())
    }

    /// Executes action over target `StatusListCredential` providing a mutable reference if all checks succeed.
    ///
    /// Checks:
    /// 1. Ensure that the `StatusListCredential` exists.
    /// 2. Verify that `proof` authorizes `action` according to `policy`.
    /// 3. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying StatusListCredential if the command is authorized, otherwise returns Err.
    pub(crate) fn try_exec_action_over_status_list_credential<A, F, R, E>(
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut StatusListCredentialWithPolicy<T>) -> Result<R, E>,
        A: Action<Target = StatusListCredentialId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<Error<T>> + From<PolicyExecutionError> + From<did::Error<T>> + From<NonceError>,
    {
        Self::try_exec_removable_action_over_status_list_credential(
            |action, reg| f(action, reg.as_mut().unwrap()),
            action,
            proof,
        )
    }

    /// Executes action over target `StatusListCredential` providing a mutable reference if all checks succeed.
    ///
    /// Unlike `try_exec_action_over_status_list_credential`, this action may result in a removal of a `StatusListCredential`, if the value under option
    /// will be taken.
    ///
    /// Checks:
    /// 1. Ensure that the `StatusListCredential` exists.
    /// 2. Verify that `proof` authorizes `action` according to `policy`.
    /// 3. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying `StatusListCredential` wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    pub(crate) fn try_exec_removable_action_over_status_list_credential<A, F, R, E>(
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<StatusListCredentialWithPolicy<T>>) -> Result<R, E>,
        A: Action<Target = StatusListCredentialId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<Error<T>> + From<PolicyExecutionError> + From<did::Error<T>> + From<NonceError>,
    {
        ensure!(!action.is_empty(), Error::EmptyPayload);

        StatusListCredentials::try_mutate_exists(action.target(), |credential| {
            Policy::try_exec_removable_action(credential, f, action, proof)
        })
    }
}
