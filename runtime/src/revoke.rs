use crate::did::{self, Did};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use frame_support::{decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::ensure_signed;

type RegistryId = [u8; 32];
/// Proof of authorization to modify a registry.
pub type PAuth = BTreeMap<Did, did::Signature>;
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

        pub fn revoke(origin, revoke: Revoke, proof: PAuth) -> DispatchResult {
            Module::<T>::revoke_(origin, revoke, proof)
        }

        pub fn unrevoke(origin, unrevoke: UnRevoke, proof: PAuth) -> DispatchResult {
            Module::<T>::unrevoke_(origin, unrevoke, proof)
        }

        pub fn remove_registry( origin, removal: RemoveRegistry, proof: PAuth) -> DispatchResult {
            Module::<T>::remove_registry_(origin, removal, proof)
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

        // check
        registry.policy.validate()?;
        ensure!(
            !Registries::<T>::exists(&id),
            "registry already exists with that id"
        );

        // execute
        Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));

        Ok(())
    }

    pub fn revoke_(
        origin: <T as system::Trait>::Origin,
        revoke: Revoke,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&revoke.registry_id).ok_or("registry does not exists")?;

        // check
        ensure!(
            T::BlockNumber::from(revoke.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        Self::ensure_auth(
            &super::StateChange::Revoke(revoke.clone()),
            &proof,
            &registry.policy,
        )?;

        // execute
        for cred_id in &revoke.credential_ids {
            Revocations::insert(&revoke.registry_id, cred_id, ());
        }
        Registries::<T>::insert(
            &revoke.registry_id,
            (registry, system::Module::<T>::block_number()),
        );

        Ok(())
    }

    pub fn unrevoke_(
        origin: <T as system::Trait>::Origin,
        unrevoke: UnRevoke,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&unrevoke.registry_id).ok_or("registry does not exists")?;

        // check
        ensure!(
            !registry.add_only,
            "revocations in this registry are permanent"
        );
        ensure!(
            T::BlockNumber::from(unrevoke.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        Self::ensure_auth(
            &super::StateChange::UnRevoke(unrevoke.clone()),
            &proof,
            &registry.policy,
        )?;

        // execute
        for cred_id in &unrevoke.credential_ids {
            Revocations::remove(&unrevoke.registry_id, cred_id);
        }
        Registries::<T>::insert(
            &unrevoke.registry_id,
            (registry, system::Module::<T>::block_number()),
        );

        Ok(())
    }

    pub fn remove_registry_(
        origin: <T as system::Trait>::Origin,
        removal: RemoveRegistry,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&removal.registry_id).ok_or("registry does not exists")?;

        // check
        ensure!(!registry.add_only, "this registry is permanent");
        ensure!(
            T::BlockNumber::from(removal.last_modified) == last_modified_actual,
            "last_modified is incorrect"
        );
        Self::ensure_auth(
            &super::StateChange::RemoveRegisty(removal.clone()),
            &proof,
            &registry.policy,
        )?;

        // execute
        Revocations::remove_prefix(&removal.registry_id);
        Registries::<T>::remove(&removal.registry_id);

        Ok(())
    }

    fn ensure_auth(command: &super::StateChange, proof: &PAuth, policy: &Policy) -> DispatchResult {
        let signers: Vec<_> = proof.keys().collect();
        ensure!(policy.satisfied_by(&signers), "policy requirements not met");
        let payload = command.encode();
        for (signer, sig) in proof {
            let valid = did::Module::<T>::verify_sig_from_did(&sig, &payload, &signer)?;
            ensure!(valid, "invalid signature");
        }
        todo!("recheck me")
    }
}
