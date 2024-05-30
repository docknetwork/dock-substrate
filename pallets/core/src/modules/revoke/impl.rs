use super::*;
use crate::{common::IntermediateError, deposit_indexed_event};

impl<T: Config> Pallet<T> {
    pub(super) fn new_registry_(
        AddRegistry { new_registry, id }: AddRegistry<T>,
        registry_opt: &mut Option<RevocationRegistry<T>>,
    ) -> Result<(), IntermediateError<T>> {
        // check
        new_registry.policy.ensure_valid()?;

        ensure!(
            registry_opt.replace(new_registry).is_none(),
            IntermediateError::<T>::dispatch(Error::<T>::RegExists)
        );

        deposit_indexed_event!(RegistryAdded(id));
        Ok(())
    }

    pub(super) fn revoke_(
        RevokeRaw {
            registry_id,
            revoke_ids,
            ..
        }: RevokeRaw<T>,
        _: RevocationRegistry<T>,
        _: BTreeSet<PolicyExecutor>,
    ) -> DispatchResult {
        // execute
        for cred_id in &revoke_ids {
            Revocations::<T>::insert(registry_id, cred_id, ());
        }

        deposit_indexed_event!(RevokedInRegistry(registry_id));
        Ok(())
    }

    pub(super) fn unrevoke_(
        UnRevokeRaw {
            revoke_ids,
            registry_id,
            ..
        }: UnRevokeRaw<T>,
        registry: RevocationRegistry<T>,
        _: BTreeSet<PolicyExecutor>,
    ) -> DispatchResult {
        ensure!(!registry.add_only, Error::<T>::AddOnly);

        // execute
        for cred_id in &revoke_ids {
            Revocations::<T>::remove(registry_id, cred_id);
        }

        deposit_indexed_event!(UnrevokedInRegistry(registry_id));
        Ok(())
    }

    pub(super) fn remove_registry_(
        RemoveRegistryRaw { registry_id, .. }: RemoveRegistryRaw<T>,
        registry: &mut Option<RevocationRegistry<T>>,
        _: BTreeSet<PolicyExecutor>,
    ) -> DispatchResult {
        let registry = registry.take().ok_or(Error::<T>::RegistryDoesntExist)?;
        ensure!(!registry.add_only, Error::<T>::AddOnly);

        // execute
        // TODO: limit and cursor
        let _ = Revocations::<T>::clear_prefix(registry_id, u32::MAX, None);

        deposit_indexed_event!(RegistryRemoved(registry_id));
        Ok(())
    }
}
