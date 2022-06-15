use crate as dock;
use crate::did::{self, Did, DidSignature};
use crate::keys_and_sigs::{SigValue, ED25519_WEIGHT, SECP256K1_WEIGHT, SR25519_WEIGHT};
use crate::{Action, StateChange};
use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchError, DispatchResult},
    ensure,
    traits::Get,
    weights::{RuntimeDbWeight, Weight},
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{Hash, One};
use sp_std::borrow::Cow;

/// Points to an on-chain revocation registry.
pub type RegistryId = [u8; 32];

/// Points to a revocation which may or may not exist in a registry.
pub type RevokeId = [u8; 32];

/// Proof of authorization to modify a registry. It can be made a set instead of a map but that causes serialization errors
pub type PAuth = BTreeMap<Did, DidSignature>;

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
    /// true: credentials can be revoked, but not un-revoked
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

/// Command to create a set of revocations withing a registry.
/// Creation of revocations is idempotent; creating a revocation that already exists is allowed,
/// but has no effect.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Revoke<T: frame_system::Config> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    /// For replay protection
    pub nonce: T::BlockNumber,
}

/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnRevoke<T: frame_system::Config> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    /// For replay protection
    pub nonce: T::BlockNumber,
}

/// Command to remove an entire registry. Removes all revocations in the registry as well as
/// registry metadata.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveRegistry<T: frame_system::Config> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// For replay protection
    pub nonce: T::BlockNumber,
}

impl_action!(RegistryId, registry_id, Revoke, UnRevoke, RemoveRegistry);

/// Return counts of different signature types in given PAuth as 3-Tuple as (no. of Sr22519 sigs,
/// no. of Ed25519 Sigs, no. of Secp256k1 sigs). Useful for weight calculation and thus the return
/// type is in `Weight` but realistically, it should fit in a u8
fn count_sig_types(auth: &PAuth) -> (Weight, Weight, Weight) {
    let mut sr = 0;
    let mut ed = 0;
    let mut secp = 0;
    for (_, a) in auth {
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
pub fn get_weight_for_pauth(auth: &PAuth, db_weights: RuntimeDbWeight) -> Weight {
    let (sr, ed, secp) = count_sig_types(auth);
    (db_weights.reads(auth.len() as u64)
        + (sr * SR25519_WEIGHT)
        + (ed * ED25519_WEIGHT)
        + (secp * SECP256K1_WEIGHT)) as Weight
}

pub trait Trait: system::Config + did::Trait {
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
    pub enum RevErr for Module<T: Trait> where T: Debug {
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

decl_storage! {
    trait Store for Module<T: Trait> as Revoke where T: Debug {
        /// Registry metadata
        Registries get(fn get_revocation_registry):
            map hasher(blake2_128_concat) dock::revoke::RegistryId => Option<(dock::revoke::Registry, T::BlockNumber)>;

        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        /// The single global revocation set
        Revocations get(fn get_revocation_status):
            double_map hasher(blake2_128_concat) dock::revoke::RegistryId, hasher(opaque_blake2_256) dock::revoke::RevokeId => Option<()>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin, T: Debug {
        fn deposit_event() = default;

        type Error = RevErr<T>;

        /// Create a new revocation registry named `id` with `registry` metadata.
        ///
        /// # Errors
        ///
        /// Returns an error if `id` is already in use as a registry id.
        ///
        /// Returns an error if `registry.policy` is invalid.
        #[weight = T::DbWeight::get().reads_writes(1, 1)  + 41_000_000]
        pub fn new_registry(
            origin,
            id: dock::revoke::RegistryId,
            registry: dock::revoke::Registry,
        ) -> DispatchResult {
            Module::<T>::new_registry_(origin, id, registry)
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
            revoke: dock::revoke::Revoke<T>,
            proof: dock::revoke::PAuth,
        ) -> DispatchResult {
            Module::<T>::revoke_(origin, revoke, proof)
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
            unrevoke: dock::revoke::UnRevoke<T>,
            proof: dock::revoke::PAuth,
        ) -> DispatchResult {
            Module::<T>::unrevoke_(origin, unrevoke, proof)
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
            removal: dock::revoke::RemoveRegistry<T>,
            proof: dock::revoke::PAuth,
        ) -> DispatchResult {
            Module::<T>::remove_registry_(origin, removal, proof)
        }
    }
}

impl<T: Trait + Debug> Module<T> {
    fn new_registry_(
        origin: <T as system::Config>::Origin,
        id: RegistryId,
        registry: Registry,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        ensure!(registry.policy.valid(), RevErr::<T>::InvalidPolicy);
        ensure!(!Registries::<T>::contains_key(&id), RevErr::<T>::RegExists);

        // execute
        Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&id)],
            <T as Trait>::Event::from(Event::RegistryAdded(id)).into(),
        );

        Ok(())
    }

    fn revoke_(
        origin: <T as system::Config>::Origin,
        revoke: Revoke<T>,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        let registry = Self::ensure_registry_exists_and_payload_valid(&revoke, proof)?;

        // execute
        for cred_id in &revoke.revoke_ids {
            Revocations::insert(&revoke.registry_id, cred_id, ());
        }
        Registries::<T>::insert(&revoke.registry_id, (registry, revoke.nonce));

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&revoke.registry_id)],
            <T as Trait>::Event::from(Event::RevokedInRegistry(revoke.registry_id)).into(),
        );

        Ok(())
    }

    fn unrevoke_(
        origin: <T as system::Config>::Origin,
        unrevoke: UnRevoke<T>,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        let registry = Self::ensure_registry_exists_and_payload_valid(&unrevoke, proof)?;
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);

        // execute
        for cred_id in &unrevoke.revoke_ids {
            Revocations::remove(&unrevoke.registry_id, cred_id);
        }
        Registries::<T>::insert(&unrevoke.registry_id, (registry, unrevoke.nonce));

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&unrevoke.registry_id)],
            <T as Trait>::Event::from(Event::UnrevokedInRegistry(unrevoke.registry_id)).into(),
        );

        Ok(())
    }

    fn remove_registry_(
        origin: <T as system::Config>::Origin,
        removal: RemoveRegistry<T>,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        let registry = Self::ensure_registry_exists_and_payload_valid(&removal, proof)?;

        ensure!(!registry.add_only, RevErr::<T>::AddOnly);

        // execute
        Revocations::remove_prefix(&removal.registry_id);
        Registries::<T>::remove(&removal.registry_id);

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&removal.registry_id)],
            <T as Trait>::Event::from(Event::RegistryRemoved(removal.registry_id)).into(),
        );

        Ok(())
    }

    /// Check whether `proof` authorizes `payload` according to `policy`.
    ///
    /// Returns Ok if command is authorized, otherwise returns Err.
    fn ensure_auth(payload: &[u8], proof: &PAuth, policy: &Policy) -> DispatchResult {
        // check the signer set satisfies policy
        match policy {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1 && proof.values().all(|sig| controllers.contains(&sig.did)),
                    RevErr::<T>::NotAuthorized
                );
            }
        }

        // check each signature is valid over payload and signed by the claimed signer
        for (signer, sig) in proof {
            let valid = did::Module::<T>::verify_sig_from_auth_or_control_key(payload, sig)?;
            ensure!(valid && (*signer == sig.did), RevErr::<T>::NotAuthorized);
        }

        Ok(())
    }

    /// Ensure that the registry exists and this is not a replayed payload by checking the equality
    /// with stored block number when the registry was last modified.
    fn ensure_registry_exists_and_payload_fresh(
        registry_id: &RegistryId,
        new_nonce: T::BlockNumber,
    ) -> Result<Registry, DispatchError> {
        // setup
        let (registry, nonce) =
            Registries::<T>::get(registry_id).ok_or_else(|| RevErr::<T>::NoReg)?;

        // check
        ensure!(
            new_nonce == (nonce + T::BlockNumber::one()),
            RevErr::<T>::IncorrectNonce
        );
        Ok(registry)
    }

    /// Ensure that the registry exists and this is not a replayed payload and the sender of the payload
    /// is authorized
    fn ensure_registry_exists_and_payload_valid<A>(
        action: &A,
        proof: PAuth,
    ) -> Result<Registry, DispatchError>
    where
        A: Action<T, Target = RegistryId>,
    {
        let registry =
            Self::ensure_registry_exists_and_payload_fresh(&action.target(), action.nonce())?;

        Self::ensure_auth(&action.to_state_change().encode(), &proof, &registry.policy)?;
        Ok(registry)
    }
}

#[cfg(test)]
/// Tests every failure case in the module.
/// If a failure case is not covered, thats a bug.
/// If an error variant from RevErr is not covered, thats a bug.
///
/// Tests in this module are named after the errors they check.
/// For example, `#[test] fn invalidpolicy` exercises the RevErr::InvalidPolicy.
mod errors {
    use sp_std::borrow::Cow;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
    use super::{
        Did, DidSignature, Policy, Registry, RegistryId, RemoveRegistry, RevErr, Revoke, RevokeId,
        UnRevoke,
    };
    use crate::test_common::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use frame_support::dispatch::DispatchError;
    use sp_core::sr25519;

    #[test]
    fn invalidpolicy() {
        if !in_ext() {
            return ext().execute_with(invalidpolicy);
        }

        let err = RevoMod::new_registry(
            Origin::signed(ABBA),
            RGA,
            Registry {
                policy: oneof(&[]),
                add_only: false,
            },
        )
        .unwrap_err();
        assert_eq!(err, RevErr::<Test>::InvalidPolicy.into());
    }

    // this test has caught at least one bug
    #[test]
    fn notauthorized() {
        if !in_ext() {
            return ext().execute_with(notauthorized);
        }

        fn assert_revoke_err(policy: Policy, signers: &[(Did, &sr25519::Pair)]) -> DispatchError {
            let regid: RegistryId = random();
            let start = block_no();
            RevoMod::new_registry(
                Origin::signed(ABBA),
                regid,
                Registry {
                    policy,
                    add_only: false,
                },
            )
            .unwrap();

            let revoke = Revoke {
                registry_id: regid,
                revoke_ids: random::<[RevokeId; 32]>().iter().cloned().collect(),
                nonce: start + 1,
            };
            let proof: BTreeMap<Did, DidSignature> = signers
                .iter()
                .map(|(did, kp)| {
                    (
                        did.clone(),
                        did_sig::<Test>(
                            &crate::StateChange::Revoke(Cow::Borrowed(&revoke)),
                            &kp,
                            did.clone(),
                            1,
                        ),
                    )
                })
                .collect();
            dbg!(&revoke);
            dbg!(&proof);
            RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap_err()
        }

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
        let kpa = create_did(DIDA);
        let reg = Registry { policy, add_only };

        let start = block_no();
        RevoMod::new_registry(Origin::signed(ABBA), registry_id, reg).unwrap();

        let unrevoke = UnRevoke {
            registry_id,
            revoke_ids: BTreeSet::new(),
            nonce: start + 1,
        };
        let ur_proof: BTreeMap<Did, DidSignature> = once((
            DIDA,
            did_sig(
                &crate::StateChange::UnRevoke(Cow::Borrowed(&unrevoke)),
                &kpa,
                DIDA,
                1,
            ),
        ))
        .collect();
        let revoke = Revoke::<Test> {
            registry_id,
            revoke_ids: BTreeSet::new(),
            nonce: start + 2,
        };

        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof.clone()).unwrap();
        assert_eq!(
            RevoMod::revoke(Origin::signed(ABBA), revoke, ur_proof.clone()).unwrap_err(),
            RevErr::<Test>::NotAuthorized.into()
        );
        assert_eq!(
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, ur_proof).unwrap_err(),
            RevErr::<Test>::IncorrectNonce.into()
        );
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
        RevoMod::new_registry(Origin::signed(ABBA), RGA, reg.clone()).unwrap();
        let err = RevoMod::new_registry(Origin::signed(ABBA), RGA, reg).unwrap_err();
        assert_eq!(err, RevErr::<Test>::RegExists.into());
    }

    #[test]
    fn noreg() {
        if !in_ext() {
            return ext().execute_with(noreg);
        }

        let registry_id = RGA;
        let nonce = block_no();
        let noreg: Result<(), DispatchError> = Err(RevErr::<Test>::NoReg.into());

        assert_eq!(
            RevoMod::revoke(
                Origin::signed(ABBA),
                Revoke {
                    registry_id,
                    revoke_ids: BTreeSet::new(),
                    nonce,
                },
                BTreeMap::new()
            ),
            noreg
        );
        assert_eq!(
            RevoMod::unrevoke(
                Origin::signed(ABBA),
                UnRevoke {
                    registry_id,
                    revoke_ids: BTreeSet::new(),
                    nonce,
                },
                BTreeMap::new(),
            ),
            noreg
        );
        assert_eq!(
            RevoMod::remove_registry(
                Origin::signed(ABBA),
                RemoveRegistry { registry_id, nonce },
                BTreeMap::new(),
            ),
            noreg
        );
    }

    #[test]
    fn incorrect_nonce() {
        if !in_ext() {
            return ext().execute_with(incorrect_nonce);
        }

        let registry_id = RGA;
        let nonce = 200;
        let err: Result<(), DispatchError> = Err(RevErr::<Test>::IncorrectNonce.into());

        RevoMod::new_registry(
            Origin::signed(ABBA),
            registry_id,
            Registry {
                policy: oneof(&[DIDA]),
                add_only: false,
            },
        )
        .unwrap();

        assert_eq!(
            RevoMod::revoke(
                Origin::signed(ABBA),
                Revoke {
                    registry_id,
                    revoke_ids: BTreeSet::new(),
                    nonce,
                },
                BTreeMap::new()
            ),
            err
        );
        assert_eq!(
            RevoMod::unrevoke(
                Origin::signed(ABBA),
                UnRevoke {
                    registry_id,
                    revoke_ids: BTreeSet::new(),
                    nonce,
                },
                BTreeMap::new(),
            ),
            err
        );
        assert_eq!(
            RevoMod::remove_registry(
                Origin::signed(ABBA),
                RemoveRegistry { registry_id, nonce },
                BTreeMap::new(),
            ),
            err
        );
    }

    #[test]
    fn addonly() {
        if !in_ext() {
            return ext().execute_with(addonly);
        }

        let registry_id = RGA;
        let start = 1;
        let err: Result<(), DispatchError> = Err(RevErr::<Test>::AddOnly.into());
        let revoke_ids: BTreeSet<_> = [RA, RB, RC].iter().cloned().collect();
        let kpa = create_did(DIDA);

        RevoMod::new_registry(
            Origin::signed(ABBA),
            registry_id,
            Registry {
                policy: oneof(&[DIDA]),
                add_only: true,
            },
        )
        .unwrap();

        let unrevoke = UnRevoke {
            registry_id,
            revoke_ids,
            nonce: start + 1,
        };
        let ur_proof = once((
            DIDA,
            did_sig::<Test>(
                &crate::StateChange::UnRevoke(Cow::Borrowed(&unrevoke)),
                &kpa,
                DIDA,
                1,
            ),
        ))
        .collect();
        assert_eq!(
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, ur_proof),
            err
        );

        let removeregistry = RemoveRegistry {
            registry_id,
            nonce: start + 1,
        };
        let rr_proof = once((
            DIDA,
            did_sig::<Test>(
                &crate::StateChange::RemoveRegistry(Cow::Borrowed(&removeregistry)),
                &kpa,
                DIDA,
                1,
            ),
        ))
        .collect();
        assert_eq!(
            RevoMod::remove_registry(Origin::signed(ABBA), removeregistry, rr_proof),
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
            | RevErr::AddOnly => {}
        }
    }
}

#[cfg(test)]
/// Tests every happy path for every public extrinsic call in the module.
/// If a happy path is not covered, thats a bug.
/// If a call is not covered, thats a bug.
///
/// Tests in this module are named after the calls they check.
/// For example, `#[test] fn new_registry` tests the happy path for Module::new_registry.
mod calls {
    use alloc::borrow::Cow;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
    use super::{
        Call as RevCall, Policy, Registries, Registry, RemoveRegistry, Revocations, Revoke,
        RevokeId, UnRevoke,
    };
    use crate::test_common::*;
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
            assert!(!Registries::<Test>::contains_key(reg_id));
            RevoMod::new_registry(Origin::signed(ABBA), reg_id, reg.clone()).unwrap();
            assert!(Registries::<Test>::contains_key(reg_id));
            let (created_reg, created_bloc) = Registries::<Test>::get(reg_id).unwrap();
            assert_eq!(created_reg, reg);
            assert_eq!(created_bloc, block_no());
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
        let mut nonce = block_no();
        let kpa = create_did(DIDA);

        RevoMod::new_registry(
            Origin::signed(ABBA),
            registry_id,
            Registry { policy, add_only },
        )
        .unwrap();

        let cases: &[&[RevokeId]] = &[
            &[],
            &[random()],
            &[random(), random()],
            &[random(), random(), random()],
            &[RA], // Test idempotence, step 1
            &[RA], // Test idempotence, step 2
        ];
        for ids in cases {
            nonce += 1;
            println!("Revoke ids: {:?}", ids);
            let revoke = Revoke {
                registry_id,
                revoke_ids: ids.iter().cloned().collect(),
                nonce,
            };
            let proof = once((
                DIDA,
                did_sig::<Test>(
                    &crate::StateChange::Revoke(Cow::Borrowed(&revoke)),
                    &kpa,
                    DIDA,
                    1,
                ),
            ))
            .collect();

            RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
            assert!(ids
                .iter()
                .all(|id| Revocations::contains_key(registry_id, id)));
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
        let mut nonce = block_no();
        let kpa = create_did(DIDA);

        enum Action {
            Revoke,
            UnRevo,
            AsrtRv, // assert revoked
            AsrtNR, // assert not revoked
        }

        RevoMod::new_registry(
            Origin::signed(ABBA),
            registry_id,
            Registry { policy, add_only },
        )
        .unwrap();

        let cases: &[(Action, &[RevokeId], u32)] = &[
            (Action::UnRevo, &[], line!()),
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
        for (action, ids, line_no) in cases {
            eprintln!("running action from line {}", line_no);
            let revoke_ids: BTreeSet<RevokeId> = ids.iter().cloned().collect();
            match action {
                Action::Revoke => {
                    nonce += 1;
                    let revoke = Revoke {
                        registry_id,
                        revoke_ids,
                        nonce,
                    };
                    let proof = once((
                        DIDA,
                        did_sig::<Test>(
                            &crate::StateChange::Revoke(Cow::Borrowed(&revoke)),
                            &kpa,
                            DIDA,
                            1,
                        ),
                    ))
                    .collect();
                    RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
                }
                Action::UnRevo => {
                    nonce += 1;
                    let unrevoke = UnRevoke {
                        registry_id,
                        revoke_ids: revoke_ids.clone(),
                        nonce,
                    };
                    let proof = once((
                        DIDA,
                        did_sig::<Test>(
                            &crate::StateChange::UnRevoke(Cow::Borrowed(&unrevoke)),
                            &kpa,
                            DIDA,
                            1,
                        ),
                    ))
                    .collect();
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
        let start = block_no();
        let kpa = create_did(DIDA);

        let reg = Registry { policy, add_only };
        RevoMod::new_registry(Origin::signed(ABBA), registry_id, reg).unwrap();
        assert!(Registries::<Test>::contains_key(registry_id));

        // destroy reg
        let rem = RemoveRegistry {
            registry_id,
            nonce: start + 1,
        };
        let proof = once((
            DIDA,
            did_sig::<Test>(
                &crate::StateChange::RemoveRegistry(Cow::Borrowed(&rem)),
                &kpa,
                DIDA,
                1,
            ),
        ))
        .collect();
        RevoMod::remove_registry(Origin::signed(ABBA), rem, proof).unwrap();

        // assert not exists
        assert!(!Registries::<Test>::contains_key(registry_id));
    }

    // Untested variants will be a match error.
    // To fix the match error, write a test for the variant then update the test.
    fn _all_included(dummy: RevCall<Test>) {
        match dummy {
            RevCall::new_registry(_, _)
            | RevCall::revoke(_, _)
            | RevCall::unrevoke(_, _)
            | RevCall::remove_registry(_, _)
            | RevCall::__PhantomItem(_, _) => {}
        }
    }
}

#[cfg(test)]
/// Miscellaneous tests
mod test {
    use alloc::borrow::Cow;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
    use super::{Did, Policy, Registry, Revoke, RevokeId};
    use crate::test_common::*;
    use alloc::collections::BTreeSet;
    use codec::Encode;
    use sp_core::sr25519;

    #[test]
    /// Exercises Module::ensure_auth, both success and failure cases.
    fn ensure_auth() {
        if !in_ext() {
            return ext().execute_with(ensure_auth);
        }

        let (a, b, c): (Did, Did, Did) = (random(), random(), random());
        let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));
        let rev = Revoke {
            registry_id: RGA,
            revoke_ids: BTreeSet::new(),
            nonce: 0,
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
        for (line_no, policy, signers, expect_success) in cases.iter().clone() {
            eprintln!("running case from line {}", line_no);
            let command = crate::StateChange::Revoke(Cow::Borrowed(&rev));
            let proof = signers
                .iter()
                .map(|(did, kp)| (did.clone(), did_sig::<Test>(&command, &kp, *did, 1)))
                .collect();
            let res = RevoMod::ensure_auth(&command.encode(), &proof, &policy);
            assert_eq!(res.is_ok(), *expect_success);
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

        assert_eq!(RevoMod::get_revocation_registry(registry_id), None);
        RevoMod::new_registry(Origin::signed(ABBA), registry_id, reg.clone()).unwrap();
        assert_eq!(
            RevoMod::get_revocation_registry(registry_id),
            Some((reg, block_no()))
        );
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
        let nonce = block_no();
        RevoMod::new_registry(Origin::signed(ABBA), registry_id, reg).unwrap();
        let revoke = Revoke {
            registry_id,
            revoke_ids: once(revid).collect(),
            nonce: (nonce + 1).into(),
        };
        let proof = once((
            DIDA,
            did_sig::<Test>(
                &crate::StateChange::Revoke(Cow::Borrowed(&revoke)),
                &kpa,
                DIDA,
                1,
            ),
        ))
        .collect();

        assert_eq!(RevoMod::get_revocation_status(registry_id, revid), None);
        RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
        assert_eq!(RevoMod::get_revocation_status(registry_id, revid), Some(()));
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use crate::benchmark_utils::{
        get_data_for_remove, get_data_for_revocation, get_data_for_unrevocation, REV_DATA_SIZE,
    };
    use crate::did::{Dids, KeyDetail, DID_BYTE_SIZE};
    use frame_benchmarking::{account, benchmarks};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const SEED: u32 = 0;
    const MAX_USER_INDEX: u32 = 1000;

    /// create a OneOf policy. Redefining from test as cannot import
    pub fn oneof(dids: &[Did]) -> Policy {
        Policy::OneOf(dids.iter().cloned().collect())
    }

    benchmarks! {
        _ {
            // Origin
            let u in 1 .. MAX_USER_INDEX => ();
            // DID
            let d in 0 .. 255 => ();
            // Registry id
            let r in 0 .. 255 => ();
            let i in 0 .. (REV_DATA_SIZE - 1) as u32 => ();
        }

        new_registry {
            let u in ...;
            let d in ...;
            let r in ...;

            let caller = account("caller", u, SEED);
            let did = [d as u8; DID_BYTE_SIZE];
            let reg_id = [r as u8; 32];
            let reg = Registry {
                policy: oneof(&[did]),
                add_only: false,
            };

        }: _(RawOrigin::Signed(caller), reg_id, reg)
        verify {
            let value = Registries::<T>::get(reg_id);
            assert!(value.is_some());
        }

        revoke {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let (n, pk, revoke_ids, signature) = get_data_for_revocation(i as usize);
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::<T>::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));

            let rev_cmd = Revoke {registry_id: reg_id, revoke_ids: revoke_ids.clone().into_iter().collect(), nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rev_cmd, p_auth)
        verify {
            assert!(revoke_ids
                .iter()
                .all(|id| Revocations::contains_key(reg_id, id)));
        }

        unrevoke {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let (n, pk, revoke_ids, signature) = get_data_for_unrevocation(i as usize);
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::<T>::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));
            for r_id in &revoke_ids {
                Revocations::insert(reg_id, r_id, ());
            }
            let rev_cmd = UnRevoke {registry_id: reg_id, revoke_ids: revoke_ids.clone().into_iter().collect(), nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rev_cmd, p_auth)
        verify {
            assert!(revoke_ids
                .iter()
                .all(|id| !Revocations::contains_key(reg_id, id)));
        }

        remove_registry {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let did = [0u8; 32];
            let reg_id = [0u8; 32];

            let (n, pk, signature) = get_data_for_remove();
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            Registries::<T>::insert(reg_id, (Registry {policy: oneof(&[did]), add_only: false}, block_number));
            for k in 0..i {
                Revocations::insert(reg_id, [k as u8; 32], ());
            }
            let rem_cmd = RemoveRegistry {registry_id: reg_id, nonce: n};
            let mut p_auth = BTreeMap::new();
            p_auth.insert(did, signature);
        }: _(RawOrigin::Signed(caller), rem_cmd, p_auth)
    }
}
