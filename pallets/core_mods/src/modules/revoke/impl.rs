use super::*;
use crate::deposit_indexed_event;

impl<T: Config + Debug> Module<T> {
    pub(super) fn new_registry_(AddRegistry { new_registry, id }: AddRegistry) -> DispatchResult {
        // check
        ensure!(new_registry.policy.valid(), RevErr::<T>::InvalidPolicy);
        ensure!(!Registries::contains_key(&id), RevErr::<T>::RegExists);
        ensure!(
            T::MaxControllers::get() >= new_registry.policy.len(),
            RevErr::<T>::TooManyControllers
        );

        // execute
        Registries::insert(&id, new_registry);

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
            Revocations::insert(&registry_id, cred_id, ());
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
            Revocations::remove(&registry_id, cred_id);
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
        let _ = Revocations::clear_prefix(&registry_id, u32::MAX, None);

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
        action: A,
        proof: Vec<DidSigs<T>>,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Registry) -> Result<R, E>,
        A: Action<T, Target = RegistryId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<did::Error<T>> + From<NonceError>,
    {
        Self::try_exec_removable_action_over_registry(action, proof, |action, reg| {
            f(action, reg.as_mut().unwrap())
        })
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
        mut action: A,
        proof: Vec<DidSigs<T>>,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<Registry>) -> Result<R, E>,
        A: Action<T, Target = RegistryId>,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<did::Error<T>> + From<NonceError>,
    {
        ensure!(!action.is_empty(), RevErr::<T>::EmptyPayload);

        Registries::try_mutate_exists(action.target(), |registry_opt| {
            let registry = registry_opt.take().ok_or(RevErr::<T>::NoReg)?;
            // check the signer set satisfies policy
            match &registry.policy {
                Policy::OneOf(controllers) => {
                    ensure!(
                        proof.len() == 1 && proof.iter().all(|a| controllers.contains(&a.sig.did)),
                        RevErr::<T>::NotAuthorized
                    );
                }
            }

            let mut new_did_details = Vec::with_capacity(proof.len());
            // check each signature is valid over payload and signed by the claimed signer
            for DidSigs { sig, nonce } in proof {
                let signer = sig.did;

                // Check if nonce is valid and increase it
                let mut did_detail = did::Pallet::<T>::onchain_did_details(&signer)?;
                did_detail
                    .try_update(nonce)
                    .map_err(|_| RevErr::<T>::IncorrectNonce)?;

                let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
                // Verify signature
                let valid = did::Pallet::<T>::verify_sig_from_auth_or_control_key(
                    &action_with_nonce,
                    &sig,
                )?;
                action = action_with_nonce.into_data();

                ensure!(valid, RevErr::<T>::NotAuthorized);
                new_did_details.push((signer, did_detail));
            }

            let mut data_opt = Some(registry);
            let res = f(action, &mut data_opt)?;
            *registry_opt = data_opt;

            // The nonce of each DID must be updated
            for (signer, did_details) in new_did_details {
                did::Pallet::<T>::insert_did_details(signer, did_details);
            }

            Ok(res)
        })
    }
}
