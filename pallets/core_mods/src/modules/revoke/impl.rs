use super::*;
use crate::{
    common::{DidSignatureWithNonce, PolicyExecutionError},
    deposit_indexed_event,
};

impl<T: Config + Debug> Module<T> {
    pub(super) fn new_registry_(AddRegistry { new_registry, id }: AddRegistry) -> DispatchResult {
        // check
        new_registry.policy.ensure_valid::<T>()?;
        ensure!(!Registries::contains_key(id), RevErr::<T>::RegExists);

        // execute
        Registries::insert(id, new_registry);

        deposit_indexed_event!(RegistryAdded(id));
        Ok(())
    }

    pub(super) fn revoke_(
        RevokeRaw {
            registry_id,
            revoke_ids,
            ..
        }: RevokeRaw<T>,
        _: &mut Registry,
    ) -> DispatchResult {
        // execute
        for cred_id in &revoke_ids {
            Revocations::insert(registry_id, cred_id, ());
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
        registry: &mut Registry,
    ) -> DispatchResult {
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);

        // execute
        for cred_id in &revoke_ids {
            Revocations::remove(registry_id, cred_id);
        }

        deposit_indexed_event!(UnrevokedInRegistry(registry_id));
        Ok(())
    }

    pub(super) fn remove_registry_(
        RemoveRegistryRaw { registry_id, .. }: RemoveRegistryRaw<T>,
        registry: &mut Option<Registry>,
    ) -> DispatchResult {
        let registry = registry.take().unwrap();
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);

        // execute
        // TODO: limit and cursor
        let _ = Revocations::clear_prefix(registry_id, u32::MAX, None);

        deposit_indexed_event!(RegistryRemoved(registry_id));
        Ok(())
    }

    /// Executes action over target registry providing a mutable reference if all checks succeed.
    ///
    /// Checks:
    /// 1. Ensure that the registry exists and this is not a replayed payload by checking the equality
    /// with stored block number when the registry was last modified.
    /// 2. Verify that `proof` authorizes `action` according to `policy`.
    ///
    /// Returns a mutable reference to the underlying registry if the command is authorized, otherwise returns Err.
    pub(crate) fn try_exec_action_over_registry<A, F, R, E>(
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Registry) -> Result<R, E>,
        A: Action<T, Target = RegistryId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<PolicyExecutionError> + From<did::Error<T>> + From<NonceError>,
    {
        Self::try_exec_removable_action_over_registry(
            |action, reg| f(action, reg.as_mut().unwrap()),
            action,
            proof,
        )
    }

    /// Executes action over target registry providing a mutable reference if all checks succeed.
    ///
    /// Unlike `try_exec_action_over_registry`, this action may result in a removal of a Registry, if the value under option
    /// will be taken.
    ///
    /// Checks:
    /// 1. Ensure that the registry exists and this is not a replayed payload by checking the equality
    /// with stored block number when the registry was last modified.
    /// 2. Verify that `proof` authorizes `action` according to `policy`.
    ///
    /// Returns a mutable reference to the underlying registry wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    pub(crate) fn try_exec_removable_action_over_registry<A, F, R, E>(
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<Registry>) -> Result<R, E>,
        A: Action<T, Target = RegistryId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<PolicyExecutionError> + From<did::Error<T>> + From<NonceError>,
    {
        ensure!(!action.is_empty(), RevErr::EmptyPayload);

        Registries::try_mutate_exists(action.target(), |registry| {
            Policy::try_exec_removable_action(registry, f, action, proof)
        })
    }
}
