use super::*;
use crate::deposit_indexed_event;

impl<T: Config> Pallet<T> {
    pub(super) fn new_registry_(
        AddRegistry { new_registry, id }: AddRegistry<T>,
    ) -> DispatchResult {
        // check
        new_registry.policy.ensure_valid()?;
        ensure!(!Registries::<T>::contains_key(id), Error::<T>::RegExists);

        // execute
        Registries::<T>::insert(id, new_registry);

        deposit_indexed_event!(RegistryAdded(id));
        Ok(())
    }

    pub(super) fn revoke_(
        RevokeRaw {
            registry_id,
            revoke_ids,
            ..
        }: RevokeRaw<T>,
        _: &mut RevocationRegistry<T>,
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
        registry: &mut RevocationRegistry<T>,
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
    ) -> DispatchResult {
        let registry = registry.take().unwrap();
        ensure!(!registry.add_only, Error::<T>::AddOnly);

        // execute
        // TODO: limit and cursor
        let _ = Revocations::<T>::clear_prefix(registry_id, u32::MAX, None);

        deposit_indexed_event!(RegistryRemoved(registry_id));
        Ok(())
    }
}
