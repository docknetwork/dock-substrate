use crate::did::{self, Did, DidSignature};
use crate::keys_and_sigs::{SigValue, ED25519_WEIGHT, SECP256K1_WEIGHT, SR25519_WEIGHT};
use crate::util::{NonceError, WithNonce};
use crate::{self as dock, StorageVersion};
use crate::{Action, ToStateChange};
use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode};
use core::fmt::Debug;
use core::marker::PhantomData;
use sp_std::vec::Vec;

use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    ensure,
    traits::Get,
    weights::{RuntimeDbWeight, Weight},
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;

/// Points to an on-chain revocation registry.
pub type RegistryId = [u8; 32];

/// Points to a revocation which may or may not exist in a registry.
pub type RevokeId = [u8; 32];

/// Proof of authorization to modify a registry. It can be made a set instead of a map but that causes serialization errors
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PAuth<T: frame_system::Config> {
    /// Mapping from DID -> (signature from DID, nonce used by the signer)
    pub auths: BTreeMap<Did, (DidSignature<Did>, T::BlockNumber)>,
}

/// Authorization logic for a registry.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Policy {
    /// Set of dids allowed to modify a registry.
    OneOf(BTreeSet<Did>),
}

impl Policy {
    /// Check for user error in the construction of self.
    /// if self is invalid, return `false`, else return `true`.
    fn valid(&self) -> bool {
        match self {
            Self::OneOf(controllers) => !controllers.is_empty(),
        }
    }
}

/// Metadata about a revocation scope.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Registry {
    /// Who is allowed to update this registry.
    pub policy: Policy,
    /// true: credentials can be revoked, but not un-revoked and the registry can't be removed either
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddRegistry {
    pub id: RegistryId,
    pub registry: Registry,
}

/// Command to create a set of revocations withing a registry.
/// Creation of revocations is idempotent; creating a revocation that already exists is allowed,
/// but has no effect.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevokeRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _marker: PhantomData<T>,
}

/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnRevokeRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _marker: PhantomData<T>,
}

/// Command to remove an entire registry. Removes all revocations in the registry as well as
/// registry metadata.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveRegistryRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
}

crate::impl_action! {
    for RegistryId:
        RevokeRaw with revoke_ids as len, registry_id as target no_state_change,
        UnRevokeRaw with revoke_ids as len, registry_id as target no_state_change,
        RemoveRegistryRaw with 1 as len, registry_id as target no_state_change
}

/// Command to create a set of revocations withing a registry.
/// Creation of revocations is idempotent; creating a revocation that already exists is allowed,
/// but has no effect.
pub type Revoke<T> = WithNonce<T, RevokeRaw<T>>;
/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
pub type UnRevoke<T> = WithNonce<T, UnRevokeRaw<T>>;
/// Command to remove an entire registry. Removes all revocations in the registry as well as
/// registry metadata.
pub type RemoveRegistry<T> = WithNonce<T, RemoveRegistryRaw<T>>;

crate::impl_action_with_nonce! {
    for RegistryId:
        UnRevoke with { |a: &UnRevoke<T>| a.data().len() } as len, { |a: &UnRevoke<T>| a.data().registry_id } as target,
        Revoke with { |a: &Revoke<T>| a.data().len() } as len, { |a: &Revoke<T>| a.data().registry_id } as target,
        RemoveRegistry with { |a: &RemoveRegistry<T>| a.data().len() } as len, { |a: &RemoveRegistry<T>| a.data().registry_id } as target
}

/// Return counts of different signature types in given PAuth as 3-Tuple as (no. of Sr22519 sigs,
/// no. of Ed25519 Sigs, no. of Secp256k1 sigs). Useful for weight calculation and thus the return
/// type is in `Weight` but realistically, it should fit in a u8
fn count_sig_types<T: frame_system::Config>(auth: &PAuth<T>) -> (Weight, Weight, Weight) {
    let mut sr = 0;
    let mut ed = 0;
    let mut secp = 0;
    for (a, _) in auth.auths.values() {
        match a.sig {
            SigValue::Sr25519(_) => sr += 1,
            SigValue::Ed25519(_) => ed += 1,
            SigValue::Secp256k1(_) => secp += 1,
        }
    }
    (sr, ed, secp)
}

/// Computes weight of the given `PAuth`. Considers the no. and types of signatures and no. of reads. Disregards
/// message size as messages are hashed giving the same output size and hashing itself is very cheap.
/// The extrinsic using it might decide to consider adding some weight proportional to the message size.
pub fn get_weight_for_pauth<T: frame_system::Config>(
    auth: &PAuth<T>,
    db_weights: RuntimeDbWeight,
) -> Weight {
    let (sr, ed, secp) = count_sig_types(auth);
    (db_weights.reads(auth.auths.len() as u64)
        + (sr * SR25519_WEIGHT)
        + (ed * ED25519_WEIGHT)
        + (secp * SECP256K1_WEIGHT)) as Weight
}

pub trait Config: system::Config + did::Config {
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_event!(
    pub enum Event {
        /// Registry with given id created
        RegistryAdded(RegistryId),
        /// Some items were revoked from given registry id
        RevokedInRegistry(RegistryId),
        /// Some items were un-revoked from given registry id
        UnrevokedInRegistry(RegistryId),
        /// Registry with given id removed
        RegistryRemoved(RegistryId),
    }
);

decl_error! {
    /// Revocation Error
    pub enum RevErr for Module<T: Config> where T: Debug {
        /// The authorization policy provided was illegal.
        InvalidPolicy,
        /// Proof of authorization does not meet policy requirements.
        NotAuthorized,
        /// A revocation registry with that name already exists.
        RegExists,
        /// A revocation registry with that name does not exist.
        NoReg,
        /// nonce is incorrect. This is related to replay protection.
        IncorrectNonce,
        /// This registry is marked as add_only. Deletion of revocations is not allowed. Deletion of
        /// the registry is not allowed.
        AddOnly,
    }
}

impl<T: Config + Debug> From<NonceError> for RevErr<T> {
    fn from(NonceError::IncorrectNonce: NonceError) -> Self {
        Self::IncorrectNonce
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Revoke where T: Debug {
        /// Registry metadata
        pub(crate) Registries get(fn get_revocation_registry):
            map hasher(blake2_128_concat) dock::revoke::RegistryId => Option<Registry>;

        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        /// The single global revocation set
        Revocations get(fn get_revocation_status):
            double_map hasher(blake2_128_concat) dock::revoke::RegistryId, hasher(opaque_blake2_256) dock::revoke::RevokeId => Option<()>;

        pub Version get(fn version): StorageVersion;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        fn deposit_event() = default;

        type Error = RevErr<T>;

        /// Create a new revocation registry named `id` with `registry` metadata.
        ///
        /// # Errors
        ///
        /// Returns an error if `id` is already in use as a registry id.
        ///
        /// Returns an error if `registry.policy` is invalid.
        #[weight = T::DbWeight::get().reads_writes(1, 1) + 41_000_000]
        pub fn new_registry(
            origin,
            add_registry: AddRegistry
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::new_registry_(add_registry)?;
            Ok(())
        }

        /// Create some revocations according to the `revoke`` command.
        ///
        /// # Errors
        ///
        /// Returns an error if `revoke.last_modified` does not match the block number when the
        /// registry referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `revoke.registry_id`.
        #[weight = T::DbWeight::get().reads_writes(1, revoke.revoke_ids.len() as u64) + 75_000_000 + get_weight_for_pauth(&proof, T::DbWeight::get())]
        pub fn revoke(
            origin,
            revoke: dock::revoke::RevokeRaw<T>,
            proof: dock::revoke::PAuth<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(revoke, proof, Self::revoke_)?;
            Ok(())
        }

        /// Delete some revocations according to the `unrevoke` command.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `unrevoke.last_modified` does not match the block number when the
        /// registry referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `unrevoke.registry_id`.
        #[weight = T::DbWeight::get().reads_writes(1, unrevoke.revoke_ids.len() as u64) + 75_000_000 + get_weight_for_pauth(&proof, T::DbWeight::get())]
        pub fn unrevoke(
            origin,
            unrevoke: dock::revoke::UnRevokeRaw<T>,
            proof: dock::revoke::PAuth<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(unrevoke, proof, Self::unrevoke_)?;
            Ok(())
        }

        /// Delete an entire registry. Deletes all revocations within the registry, as well as
        /// registry metadata. Once the registry is deleted, it can be reclaimed by any party using
        /// a call to `new_registry`.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `removal.last_modified` does not match the block number when the
        /// registry referenced by `removal.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `removal.registry_id`.
        #[weight = T::DbWeight::get().reads_writes(1, 2) + 100_000_000 + get_weight_for_pauth(&proof, T::DbWeight::get())]
        pub fn remove_registry(
            origin,
            removal: dock::revoke::RemoveRegistryRaw<T>,
            proof: dock::revoke::PAuth<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_registry(removal, proof, Self::remove_registry_)?;
            Ok(())
        }

        fn on_runtime_upgrade() -> Weight {
            T::DbWeight::get().reads(1) + if Self::version() == StorageVersion::SingleKey {
                let weight = crate::migrations::revoke::single_key::migrate_to_multi_key::<T>();
                Version::put(StorageVersion::MultiKey);

                T::DbWeight::get().writes(1) + weight
            } else {
                0
            }
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn new_registry_(AddRegistry { registry, id }: AddRegistry) -> DispatchResult {
        // check
        ensure!(registry.policy.valid(), RevErr::<T>::InvalidPolicy);
        ensure!(!Registries::contains_key(&id), RevErr::<T>::RegExists);

        // execute
        Registries::insert(&id, registry);

        crate::deposit_indexed_event!(RegistryAdded(id));
        Ok(())
    }

    fn revoke_(
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

        crate::deposit_indexed_event!(RevokedInRegistry(registry_id));
        Ok(())
    }

    fn unrevoke_(
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

        crate::deposit_indexed_event!(UnrevokedInRegistry(registry_id));
        Ok(())
    }

    fn remove_registry_(
        RemoveRegistryRaw { registry_id, .. }: RemoveRegistryRaw<T>,
        registry: &mut Option<Registry>,
    ) -> DispatchResult {
        let registry = registry.take().unwrap();
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);

        // execute
        Revocations::remove_prefix(&registry_id);

        crate::deposit_indexed_event!(RegistryRemoved(registry_id));
        Ok(())
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
        proof: PAuth<T>,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<Registry>) -> Result<R, E>,
        A: Action<T, Target = RegistryId> + Clone,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<did::Error<T>> + From<NonceError>,
    {
        ensure!(!action.is_empty(), RevErr::<T>::NoReg);

        Registries::try_mutate_exists(action.target(), |registry_opt| {
            let registry = registry_opt.take().ok_or(RevErr::<T>::NoReg)?;
            // check the signer set satisfies policy
            match &registry.policy {
                Policy::OneOf(controllers) => {
                    ensure!(
                        proof.auths.len() == 1
                            && proof
                                .auths
                                .values()
                                .all(|(sig, _)| controllers.contains(&sig.did)),
                        RevErr::<T>::NotAuthorized
                    );
                }
            }

            let mut new_did_details = Vec::with_capacity(proof.auths.len());
            // check each signature is valid over payload and signed by the claimed signer
            for (signer, (sig, nonce)) in proof.auths {
                // Check if nonce is valid and increase it
                let mut did_detail = did::Module::<T>::onchain_did_details(&signer)?;
                did_detail
                    .try_update(nonce)
                    .map_err(|_| RevErr::<T>::IncorrectNonce)?;

                let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
                // Verify signature
                let valid = did::Module::<T>::verify_sig_from_auth_or_control_key(
                    &action_with_nonce,
                    &sig,
                )?;
                action = action_with_nonce.into_data();

                ensure!(valid && signer == sig.did, RevErr::<T>::NotAuthorized);

                new_did_details.push((signer, did_detail));
            }

            let mut data_opt = Some(registry);
            let res = f(action, &mut data_opt)?;
            *registry_opt = data_opt;

            // The nonce of each DID must be updated
            for (signer, did_details) in new_did_details {
                did::Module::<T>::insert_did_details(signer, did_details);
            }

            Ok(res)
        })
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
        proof: PAuth<T>,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(A, &mut Registry) -> Result<R, E>,
        A: Action<T, Target = RegistryId> + Clone,
        WithNonce<T, A>: ToStateChange<T>,
        E: From<RevErr<T>> + From<did::Error<T>> + From<NonceError>,
    {
        Self::try_exec_removable_action_over_registry(action, proof, |action, reg| {
            f(action, reg.as_mut().unwrap())
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::test_common::*;
    use crate::util::WithNonce;
    use crate::Action;
    use crate::ToStateChange;
    use core::iter::once;
    use sp_core::sr25519;

    pub fn get_pauth<A: Action<Test> + Clone>(
        action: &A,
        signers: &[(Did, &sr25519::Pair)],
    ) -> PAuth<Test>
    where
        WithNonce<Test, A>: ToStateChange<Test>,
    {
        let auths: BTreeMap<Did, (DidSignature<Did>, u64)> = signers
            .iter()
            .map(|(did, kp)| {
                let did_detail = DIDModule::onchain_did_details(&did).unwrap();
                let next_nonce = did_detail.next_nonce();
                let sp = WithNonce::<Test, _>::new_with_nonce(action.clone(), next_nonce);
                let sig = did_sig_on_bytes::<Test, _>(
                    &sp.to_state_change().encode(),
                    &kp,
                    did.clone(),
                    1,
                );
                (did.clone(), (sig, next_nonce))
            })
            .collect();
        PAuth { auths }
    }

    pub fn inc_nonce(d: &Did) {
        let mut did_detail = DIDModule::onchain_did_details(&d).unwrap();
        did_detail.nonce = did_detail.next_nonce();
        DIDModule::insert_did_details(*d, did_detail);
    }

    pub fn get_nonces(signers: &[(Did, &sr25519::Pair)]) -> BTreeMap<Did, u64> {
        let mut nonces = BTreeMap::new();
        for (d, _) in signers {
            let did_detail = DIDModule::onchain_did_details(&d).unwrap();
            nonces.insert(*d, did_detail.nonce);
        }
        nonces
    }

    pub fn check_nonce_increase(old_nonces: BTreeMap<Did, u64>, signers: &[(Did, &sr25519::Pair)]) {
        let new_nonces = get_nonces(&signers);
        assert_eq!(new_nonces.len(), old_nonces.len());
        for (d, new_nonce) in new_nonces {
            assert_eq!(old_nonces.get(&d).unwrap() + 1, new_nonce);
        }
    }

    /// Tests every failure case in the module.
    /// If a failure case is not covered, thats a bug.
    /// If an error variant from RevErr is not covered, thats a bug.
    ///
    /// Tests in this module are named after the errors they check.
    /// For example, `#[test] fn invalidpolicy` exercises the RevErr::InvalidPolicy.
    mod errors {
        // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
        use super::*;
        use alloc::collections::{BTreeMap, BTreeSet};
        use frame_support::dispatch::DispatchError;

        #[test]
        fn invalidpolicy() {
            if !in_ext() {
                return ext().execute_with(invalidpolicy);
            }

            let ar = AddRegistry {
                id: RGA,
                registry: Registry {
                    policy: oneof(&[]),
                    add_only: false,
                },
            };

            let err = RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap_err();
            assert_eq!(err, RevErr::<Test>::InvalidPolicy.into());
        }

        // this test has caught at least one bug
        #[test]
        fn notauthorized() {
            if !in_ext() {
                return ext().execute_with(notauthorized);
            }

            fn assert_revoke_err(
                policy: Policy,
                signers: &[(Did, &sr25519::Pair)],
            ) -> DispatchError {
                let regid: RegistryId = random();
                let ar = AddRegistry {
                    id: regid,
                    registry: Registry {
                        policy,
                        add_only: false,
                    },
                };
                RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

                let rev = RevokeRaw {
                    _marker: PhantomData,
                    registry_id: regid,
                    revoke_ids: random::<[RevokeId; 32]>().iter().cloned().collect(),
                };
                let pauth = get_pauth(&rev, signers);
                dbg!(&rev);
                dbg!(&pauth);
                RevoMod::revoke(Origin::signed(ABBA), rev, pauth).unwrap_err()
            }

            run_to_block(10);

            let (a, b, c) = (DIDA, DIDB, DIDC);
            let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));

            let cases: &[(Policy, &[(Did, &sr25519::Pair)], &str)] = &[
                (oneof(&[a]), &[], "provide no signatures"),
                (oneof(&[a]), &[(b, &kpb)], "wrong account; wrong key"),
                (oneof(&[a]), &[(a, &kpb)], "correct account; wrong key"),
                (oneof(&[a]), &[(a, &kpb)], "wrong account; correct key"),
                (oneof(&[a, b]), &[(c, &kpc)], "account not a controller"),
                (oneof(&[a, b]), &[(a, &kpa), (b, &kpb)], "two signers"),
                (oneof(&[a]), &[], "one controller; no sigs"),
                (oneof(&[a, b]), &[], "two controllers; no sigs"),
            ];

            for (pol, set, description) in cases {
                dbg!(description);
                assert_eq!(
                    assert_revoke_err(pol.clone(), set),
                    RevErr::<Test>::NotAuthorized.into(),
                    "{}",
                    description
                );
            }
        }

        #[test]
        /// sign unrelated commands and ensure they fail
        fn notauthorized_wrong_command() {
            if !in_ext() {
                return ext().execute_with(notauthorized_wrong_command);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = false;

            run_to_block(10);

            let kpa = create_did(DIDA);
            let reg = Registry { policy, add_only };

            let ar = AddRegistry {
                id: registry_id,
                registry: reg,
            };
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let unrevoke = UnRevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: once(Default::default()).collect(),
            };
            let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof).unwrap();

            let rev = RevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: once(Default::default()).collect(),
            };
            let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
            assert_eq!(
                RevoMod::revoke(Origin::signed(ABBA), rev, ur_proof).unwrap_err(),
                RevErr::<Test>::NotAuthorized.into()
            );

            let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof).unwrap();
        }

        #[test]
        fn regexists() {
            if !in_ext() {
                return ext().execute_with(regexists);
            }

            let reg = Registry {
                policy: oneof(&[DIDA]),
                add_only: false,
            };
            let ar = AddRegistry {
                id: RGA,
                registry: reg,
            };
            RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap();
            let err = RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap_err();
            assert_eq!(err, RevErr::<Test>::RegExists.into());
        }

        #[test]
        fn noreg() {
            if !in_ext() {
                return ext().execute_with(noreg);
            }

            let registry_id = RGA;

            let noreg: Result<(), DispatchError> = Err(RevErr::<Test>::NoReg.into());

            assert_eq!(
                RevoMod::revoke(
                    Origin::signed(ABBA),
                    RevokeRaw {
                        _marker: PhantomData,
                        registry_id,
                        revoke_ids: once(Default::default()).collect(),
                    },
                    PAuth {
                        auths: BTreeMap::new()
                    }
                ),
                noreg
            );
            assert_eq!(
                RevoMod::unrevoke(
                    Origin::signed(ABBA),
                    UnRevokeRaw {
                        _marker: PhantomData,
                        registry_id,
                        revoke_ids: once(Default::default()).collect(),
                    },
                    PAuth {
                        auths: BTreeMap::new()
                    },
                ),
                noreg
            );
            assert_eq!(
                RevoMod::remove_registry(
                    Origin::signed(ABBA),
                    RemoveRegistryRaw {
                        _marker: PhantomData,
                        registry_id
                    },
                    PAuth {
                        auths: BTreeMap::new()
                    },
                ),
                noreg
            );
        }

        #[test]
        fn incorrect_nonce() {
            if !in_ext() {
                return ext().execute_with(incorrect_nonce);
            }

            run_to_block(1);

            let kpa = create_did(DIDA);

            let registry_id = RGA;
            let err: Result<(), DispatchError> = Err(RevErr::<Test>::IncorrectNonce.into());

            let ar = AddRegistry {
                id: registry_id,
                registry: Registry {
                    policy: oneof(&[DIDA]),
                    add_only: false,
                },
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let rev = RevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: once(Default::default()).collect(),
            };
            let proof = get_pauth(&rev, &[(DIDA, &kpa)]);

            // Increase nonce to make the auth chekc fail
            inc_nonce(&DIDA);
            assert_eq!(RevoMod::revoke(Origin::signed(ABBA), rev, proof), err);

            let unrevoke = UnRevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: once(Default::default()).collect(),
            };
            let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);

            // Increase nonce to make the auth chekc fail
            inc_nonce(&DIDA);
            assert_eq!(
                RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof,),
                err
            );

            let remove = RemoveRegistryRaw {
                _marker: PhantomData,
                registry_id,
            };
            let proof = get_pauth(&remove, &[(DIDA, &kpa)]);

            // Increase nonce to make the auth chekc fail
            inc_nonce(&DIDA);
            assert_eq!(
                RevoMod::remove_registry(Origin::signed(ABBA), remove, proof,),
                err
            );
        }

        #[test]
        fn addonly() {
            if !in_ext() {
                return ext().execute_with(addonly);
            }

            let registry_id = RGA;
            let err: Result<(), DispatchError> = Err(RevErr::<Test>::AddOnly.into());
            let revoke_ids: BTreeSet<_> = [RA, RB, RC].iter().cloned().collect();

            run_to_block(1);

            let kpa = create_did(DIDA);

            let ar = AddRegistry {
                id: registry_id,
                registry: Registry {
                    policy: oneof(&[DIDA]),
                    add_only: true,
                },
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let unrevoke = UnRevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids,
            };
            let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
            assert_eq!(
                RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof),
                err
            );

            let remove = RemoveRegistryRaw {
                _marker: PhantomData,
                registry_id,
            };
            let proof = get_pauth(&remove, &[(DIDA, &kpa)]);
            assert_eq!(
                RevoMod::remove_registry(Origin::signed(ABBA), remove, proof),
                err
            );
        }

        // Untested variants will be a match error.
        // To fix the match error, write a test for the variant then update the test.
        fn _all_included(dummy: RevErr<Test>) {
            match dummy {
                RevErr::__Ignore(_, _)
                | RevErr::InvalidPolicy
                | RevErr::NotAuthorized
                | RevErr::RegExists
                | RevErr::NoReg
                | RevErr::IncorrectNonce
                | RevErr::AddOnly
                | RevErr::NoReg => {}
            }
        }
    }

    /// Tests every happy path for every public extrinsic call in the module.
    /// If a happy path is not covered, thats a bug.
    /// If a call is not covered, thats a bug.
    ///
    /// Tests in this module are named after the calls they check.
    /// For example, `#[test] fn new_registry` tests the happy path for Module::new_registry.
    mod calls {
        use super::*;
        // Cannot do `use super::super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
        use super::super::{Call as RevCall, Registries, Revocations};
        use alloc::collections::BTreeSet;
        use frame_support::{StorageDoubleMap, StorageMap};

        #[test]
        fn new_registry() {
            if !in_ext() {
                return ext().execute_with(new_registry);
            }

            let cases: &[(Policy, bool)] = &[
                (oneof(&[DIDA]), false),
                (oneof(&[DIDA, DIDB]), false),
                (oneof(&[DIDA]), true),
                (oneof(&[DIDA, DIDB]), true),
            ];
            for (policy, add_only) in cases.iter().cloned() {
                let reg_id = random();
                let reg = Registry { policy, add_only };
                let ar = AddRegistry {
                    id: reg_id,
                    registry: reg.clone(),
                };
                assert!(!Registries::contains_key(&reg_id));
                RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
                assert!(Registries::contains_key(reg_id));
                assert_eq!(Registries::get(reg_id).unwrap(), reg);
            }
        }

        #[test]
        fn revoke() {
            if !in_ext() {
                return ext().execute_with(revoke);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = true;

            run_to_block(1);

            let kpa = create_did(DIDA);

            let ar = AddRegistry {
                id: registry_id,
                registry: Registry { policy, add_only },
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let cases: &[&[RevokeId]] = &[
                // &[],
                &[random()],
                &[random(), random()],
                &[random(), random(), random()],
                &[RA], // Test idempotence, step 1
                &[RA], // Test idempotence, step 2
            ];
            for (i, ids) in cases.into_iter().enumerate() {
                println!("Revoke ids: {:?}", ids);
                let revoke = RevokeRaw {
                    _marker: PhantomData,
                    registry_id,
                    revoke_ids: ids.iter().cloned().collect(),
                };
                let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);
                RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
                assert!(ids
                    .iter()
                    .all(|id| Revocations::contains_key(registry_id, id)));
                run_to_block(1 + 1 + i as u64);
            }
        }

        #[test]
        fn unrevoke() {
            if !in_ext() {
                return ext().execute_with(unrevoke);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = false;

            run_to_block(10);

            let kpa = create_did(DIDA);

            enum Action {
                Revoke,
                UnRevo,
                AsrtRv, // assert revoked
                AsrtNR, // assert not revoked
            }

            let ar = AddRegistry {
                id: registry_id,
                registry: Registry { policy, add_only },
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let cases: &[(Action, &[RevokeId], u32)] = &[
                //(Action::UnRevo, &[], line!()),
                (Action::UnRevo, &[random()], line!()),
                (Action::UnRevo, &[random(), random()], line!()),
                (Action::UnRevo, &[random(), random(), random()], line!()),
                (Action::Revoke, &[RA, RB], line!()),
                (Action::AsrtRv, &[RA, RB], line!()),
                (Action::UnRevo, &[RA], line!()),
                (Action::AsrtNR, &[RA], line!()),
                (Action::AsrtRv, &[RB], line!()),
                (Action::UnRevo, &[RA, RB], line!()),
                (Action::AsrtNR, &[RA, RB], line!()),
                (Action::Revoke, &[RA, RB], line!()),
                (Action::AsrtRv, &[RA, RB], line!()),
                (Action::UnRevo, &[RA, RB], line!()),
                (Action::AsrtNR, &[RA, RB], line!()),
            ];
            for (i, (action, ids, line_no)) in cases.into_iter().enumerate() {
                eprintln!("running action from line {}", line_no);
                let revoke_ids: BTreeSet<RevokeId> = ids.iter().cloned().collect();
                match action {
                    Action::Revoke => {
                        let revoke = RevokeRaw {
                            _marker: PhantomData,
                            registry_id,
                            revoke_ids,
                        };
                        let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);
                        RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
                    }
                    Action::UnRevo => {
                        let unrevoke = UnRevokeRaw {
                            _marker: PhantomData,
                            registry_id,
                            revoke_ids: revoke_ids.clone(),
                        };
                        let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
                        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof).unwrap();
                    }
                    Action::AsrtRv => {
                        assert!(revoke_ids
                            .iter()
                            .all(|id| Revocations::contains_key(registry_id, id)));
                    }
                    Action::AsrtNR => {
                        assert!(!revoke_ids
                            .iter()
                            .any(|id| Revocations::contains_key(registry_id, id)));
                    }
                }
                run_to_block(10 + 1 + i as u64)
            }
        }

        #[test]
        fn remove_registry() {
            if !in_ext() {
                return ext().execute_with(remove_registry);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = false;
            let kpa = create_did(DIDA);

            let reg = Registry { policy, add_only };
            let ar = AddRegistry {
                id: registry_id,
                registry: reg.clone(),
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
            assert!(Registries::contains_key(registry_id));

            // destroy reg
            let rem = RemoveRegistryRaw {
                _marker: PhantomData,
                registry_id,
            };
            let proof = get_pauth(&rem, &[(DIDA, &kpa)]);
            RevoMod::remove_registry(Origin::signed(ABBA), rem, proof).unwrap();

            // assert not exists
            assert!(!Registries::contains_key(registry_id));
        }

        // Untested variants will be a match error.
        // To fix the match error, write a test for the variant then update the test.
        fn _all_included(dummy: RevCall<Test>) {
            match dummy {
                RevCall::new_registry(_)
                | RevCall::revoke(_, _)
                | RevCall::unrevoke(_, _)
                | RevCall::remove_registry(_, _)
                | RevCall::__PhantomItem(_, _) => {}
            }
        }
    }

    mod test {
        use frame_support::StorageMap;
        use sp_runtime::DispatchError;
        // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
        use super::*;
        use crate::revoke::Registries;
        use alloc::collections::BTreeSet;

        #[test]
        /// Exercises Module::ensure_auth, both success and failure cases.
        fn ensure_auth() {
            if !in_ext() {
                return ext().execute_with(ensure_auth);
            }

            run_to_block(10);

            let (a, b, c): (Did, Did, Did) = (Did(random()), Did(random()), Did(random()));
            let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));
            let rev = RevokeRaw {
                _marker: PhantomData,
                registry_id: RGA,
                revoke_ids: once(Default::default()).collect(),
            };

            let cases: &[(u32, Policy, &[(Did, &sr25519::Pair)], bool)] = &[
                (line!(), oneof(&[a]), &[(a, &kpa)], true),
                (line!(), oneof(&[a, b]), &[(a, &kpa)], true),
                (line!(), oneof(&[a, b]), &[(b, &kpb)], true),
                (line!(), oneof(&[a]), &[], false), // provide no signatures
                (line!(), oneof(&[a]), &[(b, &kpb)], false), // wrong account; wrong key
                (line!(), oneof(&[a]), &[(a, &kpb)], false), // correct account; wrong key
                (line!(), oneof(&[a]), &[(a, &kpb)], false), // wrong account; correct key
                (line!(), oneof(&[a, b]), &[(c, &kpc)], false), // account not a controller
                (line!(), oneof(&[a, b]), &[(a, &kpa), (b, &kpb)], false), // two signers
                (line!(), oneof(&[a]), &[], false), // one controller; no sigs
                (line!(), oneof(&[a, b]), &[], false), // two controllers; no sigs
            ];
            for (i, (line_no, policy, signers, expect_success)) in cases.into_iter().enumerate() {
                eprintln!("running case from line {}", line_no);
                Registries::insert(
                    RGA,
                    Registry {
                        policy: policy.clone(),
                        add_only: false,
                    },
                );

                let old_nonces = get_nonces(signers);
                let command = &rev;
                let proof = get_pauth(command, &signers);
                let res = RevoMod::try_exec_action_over_registry(command.clone(), proof, |_, _| {
                    Ok::<_, DispatchError>(())
                });
                assert_eq!(res.is_ok(), *expect_success);

                if *expect_success {
                    check_nonce_increase(old_nonces, signers);
                }
                run_to_block(10 + 1 + i as u64);
            }
        }

        #[test]
        /// Exercises the revocation registry convenience getter, get_revocation_registry.
        fn get_revocation_registry() {
            if !in_ext() {
                return ext().execute_with(get_revocation_registry);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = false;
            let reg = Registry { policy, add_only };

            let ar = AddRegistry {
                id: registry_id,
                registry: reg.clone(),
            };

            assert_eq!(RevoMod::get_revocation_registry(registry_id), None);
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
            assert_eq!(RevoMod::get_revocation_registry(registry_id), Some(reg));
        }

        #[test]
        /// Exercises the revocation status convenience getter, get_revocation_status.
        fn get_revocation_status() {
            if !in_ext() {
                return ext().execute_with(get_revocation_status);
            }

            let policy = oneof(&[DIDA]);
            let registry_id = RGA;
            let add_only = false;
            let reg = Registry { policy, add_only };
            let kpa = create_did(DIDA);
            let revid: RevokeId = random();

            let ar = AddRegistry {
                id: registry_id,
                registry: reg.clone(),
            };

            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
            let revoke = RevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: once(revid).collect(),
            };
            let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);

            assert_eq!(RevoMod::get_revocation_status(registry_id, revid), None);
            RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
            assert_eq!(RevoMod::get_revocation_status(registry_id, revid), Some(()));
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use crate::did::{Did, Dids};
    use frame_benchmarking::{account, benchmarks};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const SEED: u32 = 0;
    const MAX_USER_INDEX: u32 = 1000;

    /// create a OneOf policy. Redefining from test as cannot import
    pub fn oneof(dids: &[Did]) -> Policy {
        Policy::OneOf(dids.iter().cloned().collect())
    }

    /*crate::bench_with_all_pairs! {
        new_registry {
            let u in 1 .. MAX_USER_INDEX => ();
            let d in 0 .. 255 => ();
            let r in 0 .. 255 => ();

            let caller = whitelisted_caller();
            let did = Did([d as u8; Did::BYTE_SIZE]);
            let reg_id = [r as u8; 32];
            let reg = Registry {
                policy: oneof(&[did]),
                add_only: false,
            };
            let add_reg = AddRegistry {
                registry: reg.clone(),
                id: Default::default()
            };

        }: new_registry(RawOrigin::Signed(caller), add_reg)
        verify {
            assert_eq!(Registries::get(reg_id), reg);
        }
        /*
        revoke {
            let u in 1 .. MAX_USER_INDEX => ();
            let i in 0 .. (REV_DATA_SIZE - 1) as u32 => ();

            let caller = whitelisted_caller();

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let ids =
            // let (n, pk, revoke_ids, signature) = get_data_for_revocation(i as usize);

            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));

            let rev_cmd = RevokeRaw {_marker: PhantomData,registry_id: reg_id, revoke_ids: revoke_ids.clone().into_iter().collect(), nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rev_cmd, p_auth)
        verify {
            assert!(revoke_ids
                .iter()
                .all(|id| Revocations::contains_key(reg_id, id)));
        }

        unrevoke {
            let u in 1 .. MAX_USER_INDEX => ();
            let i in 0 .. (REV_DATA_SIZE - 1) as u32 => ();

            let caller = whitelisted_caller();

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let (n, pk, revoke_ids, signature) = get_data_for_unrevocation(i as usize);
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));
            for r_id in &revoke_ids {
                Revocations::insert(reg_id, r_id, ());
            }
            let rev_cmd = UnRevokeRaw {_marker: PhantomData,registry_id: reg_id, revoke_ids: revoke_ids.clone().into_iter().collect(), nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rev_cmd, p_auth)
        verify {
            assert!(revoke_ids
                .iter()
                .all(|id| !Revocations::contains_key(reg_id, id)));
        }

        remove_registry {
            let u in 1 .. MAX_USER_INDEX => ();
            let i in 0 .. (REV_DATA_SIZE - 1) as u32 => ();

            let caller = whitelisted_caller();

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let (n, pk, signature) = get_data_for_remove();
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));
            for k in 0..i {
                Revocations::insert(reg_id, [k as u8; 32], ());
            }
            let rem_cmd = RemoveRegistryRaw { _marker: PhantomData,registry_id: reg_id, nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rem_cmd, p_auth)*/
    }*/
}
