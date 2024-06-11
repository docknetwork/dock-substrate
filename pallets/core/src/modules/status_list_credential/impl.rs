use alloc::collections::BTreeSet;

use crate::common::IntermediateError;

use super::*;

impl<T: Config> Pallet<T> {
    pub(super) fn create_(
        AddStatusListCredential { id, credential }: AddStatusListCredential<T>,
        cred_opt: &mut Option<StatusListCredentialWithPolicy<T>>,
    ) -> Result<(), IntermediateError<T>> {
        credential.ensure_valid()?;

        ensure!(
            cred_opt.replace(credential).is_none(),
            IntermediateError::<T>::dispatch(Error::<T>::StatusListCredentialAlreadyExists)
        );

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
