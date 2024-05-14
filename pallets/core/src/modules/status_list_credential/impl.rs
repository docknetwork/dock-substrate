use alloc::collections::BTreeSet;

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
        _: BTreeSet<PolicyExecutor>,
    ) -> DispatchResult {
        credential.ensure_valid()?;

        status_list_credential.status_list_credential = credential;

        deposit_indexed_event!(StatusListCredentialUpdated(id));
        Ok(())
    }

    pub(super) fn remove_(
        RemoveStatusListCredentialRaw { id, .. }: RemoveStatusListCredentialRaw<T>,
        status_list_credential: &mut Option<StatusListCredentialWithPolicy<T>>,
        _: BTreeSet<PolicyExecutor>,
    ) -> DispatchResult {
        status_list_credential
            .take()
            .ok_or(Error::<T>::StatusListCredentialDoesntExist)?;

        deposit_indexed_event!(StatusListCredentialRemoved(id));
        Ok(())
    }
}
