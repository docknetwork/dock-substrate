use crate::did::{self, Did};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use frame_support::{decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::ensure_signed;

type RegistryId = [u8; 32];
type CredentialId = [u8; 32]; // XXX: Call this something more general. It will be useful to revoke
                              // things that are not credentials.

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub enum Policy {
    OneOf {
        /// Set of dids allowed to modify a registry.
        controllers: BTreeSet<Did>,
    },
}

impl Policy {
    /// Check for user error in the construction of self.
    /// if self is invalid, return `Err(reason)`, else return `Ok(())`.
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::OneOf { controllers } if controllers.len() != 0 => Ok(()),
            Self::OneOf { .. } => Err("that policy requires at least one controller"),
        }
    }

    /// Return whether a signature by each member of verifier_set would satisfy the conditions of
    /// this policy.
    fn satisfied_by(&self, verifier_set: &[&Did]) -> bool {
        match self {
            Self::OneOf { controllers } => {
                verifier_set.len() == 1
                    && verifier_set
                        .iter()
                        .all(|verifier| controllers.contains(*verifier))
            }
        }
    }
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct Registry {
    /// Who is allowed to update this registry.
    policy: Policy,
    /// true: credentials can be revoked, but not un-revoked
    /// false: credentials can be revoked and un-revoked
    add_only: bool,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct Revoke {
    /// The registry on which to operate
    registry_id: RegistryId,
    /// Credential ids which will be revoked
    credential_ids: BTreeSet<CredentialId>,
    /// For replay protection
    last_modified: crate::BlockNumber,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct UnRevoke {
    /// The registry on which to operate
    registry_id: RegistryId,
    /// Credential ids which will be revoked
    credential_ids: BTreeSet<CredentialId>,
    /// For replay protection
    last_modified: crate::BlockNumber,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct RemoveRegistry {
    /// The registry on which to operate
    registry_id: RegistryId,
    /// For replay protection
    last_modified: crate::BlockNumber,
}

pub trait Trait: system::Trait + did::Trait {}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
        Registries get(get_revocation_registry):
            map RegistryId => Option<(Registry, T::BlockNumber)>;
        // **the following should be removed before merging the pr**
        // Lovesh, I made an optimization/simplification here. This differs from the impl spec in
        // that revocations no longer store a block number as nonce. Instead the registry nonce is
        // used for replay protection.
        //
        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        Revocations get(get_revocation_status):
            double_map RegistryId, blake2_256(CredentialId) => Option<()>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        pub fn new_registry(origin, id: RegistryId, registry: Registry) -> DispatchResult {
            Module::<T>::new_registry_(origin, id, registry)
        }

        pub fn revoke(
            origin,
            to_revoke: Revoke,
            sigs: BTreeMap<Did, did::Signature>,
        ) -> DispatchResult {
            Module::<T>::revoke_(origin, to_revoke, sigs)
        }

        pub fn unrevoke(
            origin,
            to_unrevoke: UnRevoke,
            sigs: BTreeMap<Did, did::Signature>,
        ) -> DispatchResult {
            Module::<T>::unrevoke_(origin, to_unrevoke, sigs)
        }

        pub fn remove_registry(
            origin,
            removal: RemoveRegistry,
            sigs: BTreeMap<Did, did::Signature>,
        ) -> DispatchResult {
            Module::<T>::remove_registry_(origin, removal, sigs)
        }
    }
}

impl<T: Trait> Module<T> {
    pub fn new_registry_(
        origin: <T as system::Trait>::Origin,
        id: RegistryId,
        registry: Registry,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        registry.policy.validate()?;
        ensure!(
            !Registries::<T>::exists(&id),
            "registry already exists with that id"
        );
        Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));
        Ok(())
    }

    pub fn revoke_(
        origin: <T as system::Trait>::Origin,
        to_revoke: Revoke,
        sigs: BTreeMap<Did, did::Signature>,
    ) -> DispatchResult {
        // setup
        let signers: Vec<_> = sigs.keys().collect();
        let payload = super::StateChange::Revoke(to_revoke.clone()).encode();
        let current_block = system::Module::<T>::block_number();
        let (registry, last_modified_actual) =
            Registries::<T>::get(&to_revoke.registry_id).ok_or("registry does not exists")?;

        // check
        ensure_signed(origin)?;
        ensure!(
            T::BlockNumber::from(to_revoke.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        ensure!(
            registry.policy.satisfied_by(&signers),
            "policy requirements not met"
        );
        for (signer, sig) in sigs {
            let valid = did::Module::<T>::verify_sig_from_did(&sig, &payload, &signer)?;
            ensure!(valid, "invalid signature");
        }

        // execute
        for cred_id in &to_revoke.credential_ids {
            Revocations::insert(&to_revoke.registry_id, cred_id, ());
        }
        Registries::<T>::insert(&to_revoke.registry_id, (registry, current_block));

        Ok(())
    }

    pub fn unrevoke_(
        origin: <T as system::Trait>::Origin,
        to_unrevoke: UnRevoke,
        sigs: BTreeMap<Did, did::Signature>,
    ) -> DispatchResult {
        // setup
        let signers: Vec<_> = sigs.keys().collect();
        let payload = super::StateChange::UnRevoke(to_unrevoke.clone()).encode();
        let current_block = system::Module::<T>::block_number();
        let (registry, last_modified_actual) =
            Registries::<T>::get(&to_unrevoke.registry_id).ok_or("registry does not exists")?;

        // check
        ensure_signed(origin)?;
        ensure!(
            T::BlockNumber::from(to_unrevoke.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        ensure!(
            registry.policy.satisfied_by(&signers),
            "policy requirements not met"
        );
        ensure!(
            !registry.add_only,
            "revocations in this registry are permanent"
        );
        for (signer, sig) in sigs {
            let valid = did::Module::<T>::verify_sig_from_did(&sig, &payload, &signer)?;
            ensure!(valid, "invalid signature");
        }

        // execute
        for cred_id in &to_unrevoke.credential_ids {
            Revocations::remove(&to_unrevoke.registry_id, cred_id);
        }
        Registries::<T>::insert(&to_unrevoke.registry_id, (registry, current_block));

        Ok(())
    }

    pub fn remove_registry_(
        origin: <T as system::Trait>::Origin,
        removal: RemoveRegistry,
        sigs: BTreeMap<Did, did::Signature>,
    ) -> DispatchResult {
        // setup
        let signers: Vec<_> = sigs.keys().collect();
        let payload = super::StateChange::RemoveRegisty(removal.clone()).encode();
        let (registry, last_modified_actual) =
            Registries::<T>::get(&removal.registry_id).ok_or("registry does not exists")?;

        // check
        ensure_signed(origin)?;
        ensure!(
            T::BlockNumber::from(removal.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        ensure!(
            registry.policy.satisfied_by(&signers),
            "policy requirements not met"
        );
        ensure!(!registry.add_only, "this registry is permanent");
        for (signer, sig) in sigs {
            let valid = did::Module::<T>::verify_sig_from_did(&sig, &payload, &signer)?;
            ensure!(valid, "invalid signature");
        }

        // execute
        Revocations::remove_prefix(&removal.registry_id);
        Registries::<T>::remove(&removal.registry_id);

        Ok(())
    }
}
