use crate::did::{self, Did};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use frame_support::{decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::ensure_signed;

/// Points to an on-chain revocation registry.
pub type RegistryId = [u8; 32];

/// Points to a revocation which may or may not exist in a registry.
pub type RevokeId = [u8; 32];

/// Proof of authorization to modify a registry.
pub type PAuth = BTreeMap<Did, did::Signature>;

/// Authorization logic for a registry.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub enum Policy {
    OneOf {
        /// Set of dids allowed to modify a registry.
        controllers: BTreeSet<Did>,
    },
}

impl Policy {
    /// Check for user error in the construction of self.
    /// if self is invalid, return `false`, else return `true`.
    fn valid(&self) -> bool {
        match self {
            Self::OneOf { controllers } => !controllers.is_empty(),
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

/// Metadata about a revocation scope.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
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
pub struct Revoke {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    /// For replay protection
    pub last_modified: crate::BlockNumber,
}

/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct UnRevoke {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    /// For replay protection
    pub last_modified: crate::BlockNumber,
}

/// Command to remove an entire registy. Removes all revocations in the registry as well as
/// registry metadata.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
pub struct RemoveRegistry {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// For replay protection
    pub last_modified: crate::BlockNumber,
}

pub trait Trait: system::Trait + did::Trait {}

decl_error! {
    /// Revocation Error
    pub enum RevErr for Module<T: Trait> {
        /// The authorization policy provided was illegal.
        InvalidPolicy,
        /// Proof of authorization does not meet policy requirements.
        NotAuthorized,
        /// A revocation registry with that name already exists.
        RegExists,
        /// A revocation registry with that name does not exist.
        NoReg,
        /// `last_modified` is incorrect. This is related to replay protection.
        WrongNonce,
        /// This registry is marked as add_only. Deletion of revocations is not allowed. Deletion of
        /// the registry is not allowed.
        AddOnly,
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as TemplateModule {
        /// Registry metadata
        Registries get(get_revocation_registry):
            map RegistryId => Option<(Registry, T::BlockNumber)>;

        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        /// The single global revocation set
        Revocations get(get_revocation_status):
            double_map RegistryId, blake2_256(RevokeId) => Option<()>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = RevErr<T>;

        /// Create a new revocation registry named `id` with `registry` metadata.
        ///
        /// # Errors
        ///
        /// Returns an error if `id` is already in use as a registry id.
        ///
        /// Returns an error if `registry.policy` is invalid.
        pub fn new_registry(origin, id: RegistryId, registry: Registry) -> DispatchResult {
            Module::<T>::new_registry_(origin, id, registry)
        }

        /// Create some revocations according to the `revoke`` command.
        ///
        /// # Errors
        ///
        /// Returns an error if `revoke.last_modified` does not match the block number when the
        /// registy referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registy
        /// referenced by `revoke.registry_id`.
        pub fn revoke(origin, revoke: Revoke, proof: PAuth) -> DispatchResult {
            Module::<T>::revoke_(origin, revoke, proof)
        }

        /// Delete some revocations according to the `unrevoke` command.
        ///
        /// # Errors
        ///
        /// Returns an error if the registy referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `unrevoke.last_modified` does not match the block number when the
        /// registy referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registy
        /// referenced by `unrevoke.registry_id`.
        pub fn unrevoke(origin, unrevoke: UnRevoke, proof: PAuth) -> DispatchResult {
            Module::<T>::unrevoke_(origin, unrevoke, proof)
        }

        /// Delete an entire registry. Deletes all revcations within the registry, as well as
        /// registry metadata. Once the registy is deleted, it can be reclaimed by any party using
        /// a call to `new_registry`.
        ///
        /// # Errors
        ///
        /// Returns an error if the registy referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `removal.last_modified` does not match the block number when the
        /// registy referenced by `removal.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registy
        /// referenced by `removal.registry_id`.
        pub fn remove_registry(origin, removal: RemoveRegistry, proof: PAuth) -> DispatchResult {
            Module::<T>::remove_registry_(origin, removal, proof)
        }
    }
}

impl<T: Trait> Module<T> {
    fn new_registry_(
        origin: <T as system::Trait>::Origin,
        id: RegistryId,
        registry: Registry,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        ensure!(registry.policy.valid(), RevErr::<T>::InvalidPolicy);
        ensure!(!Registries::<T>::exists(&id), RevErr::<T>::RegExists);

        // execute
        Registries::<T>::insert(&id, (registry, system::Module::<T>::block_number()));

        Ok(())
    }

    fn revoke_(
        origin: <T as system::Trait>::Origin,
        revoke: Revoke,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&revoke.registry_id).ok_or(RevErr::<T>::NoReg)?;

        // check
        ensure!(
            T::BlockNumber::from(revoke.last_modified) == last_modified_actual,
            RevErr::<T>::WrongNonce
        );
        Self::ensure_auth(
            &super::StateChange::Revoke(revoke.clone()),
            &proof,
            &registry.policy,
        )?;

        // execute
        for cred_id in &revoke.revoke_ids {
            Revocations::insert(&revoke.registry_id, cred_id, ());
        }
        Registries::<T>::insert(
            &revoke.registry_id,
            (registry, system::Module::<T>::block_number()),
        );

        Ok(())
    }

    fn unrevoke_(
        origin: <T as system::Trait>::Origin,
        unrevoke: UnRevoke,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&unrevoke.registry_id).ok_or(RevErr::<T>::NoReg)?;

        // check
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);
        ensure!(
            T::BlockNumber::from(unrevoke.last_modified) == last_modified_actual,
            RevErr::<T>::WrongNonce
        );
        Self::ensure_auth(
            &super::StateChange::UnRevoke(unrevoke.clone()),
            &proof,
            &registry.policy,
        )?;

        // execute
        for cred_id in &unrevoke.revoke_ids {
            Revocations::remove(&unrevoke.registry_id, cred_id);
        }
        Registries::<T>::insert(
            &unrevoke.registry_id,
            (registry, system::Module::<T>::block_number()),
        );

        Ok(())
    }

    fn remove_registry_(
        origin: <T as system::Trait>::Origin,
        removal: RemoveRegistry,
        proof: PAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // setup
        let (registry, last_modified_actual) =
            Registries::<T>::get(&removal.registry_id).ok_or(RevErr::<T>::NoReg)?;

        // check
        ensure!(!registry.add_only, RevErr::<T>::AddOnly);
        ensure!(
            T::BlockNumber::from(removal.last_modified) == last_modified_actual,
            RevErr::<T>::WrongNonce
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

    /// Check whether `proof` authorizes `command` according to `policy`.
    ///
    /// Returns Ok if command is authorzed, otherwise returns Err.
    fn ensure_auth(command: &super::StateChange, proof: &PAuth, policy: &Policy) -> DispatchResult {
        // check the signer set satisfies policy
        let signers: Vec<_> = proof.keys().collect();
        ensure!(policy.satisfied_by(&signers), RevErr::<T>::NotAuthorized);

        // check each signature is valid over payload and signed by the claimed signer
        let payload = command.encode();
        for (signer, sig) in proof {
            let valid = did::Module::<T>::verify_sig_from_did(&sig, &payload, &signer)?;
            ensure!(valid, RevErr::<T>::NotAuthorized);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use frame_support::{impl_outer_origin, parameter_types, weights::Weight};
    use sp_core::{sr25519, Pair, H256};
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup, OnFinalize, OnInitialize},
        Perbill,
    };

    type System = system::Module<Test>;
    type TestMod = super::Module<Test>;

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    #[derive(Clone, Eq, Debug, PartialEq)]
    pub struct Test;

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::one();
    }

    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Call = ();
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type AvailableBlockRatio = AvailableBlockRatio;
        type MaximumBlockLength = MaximumBlockLength;
        type Version = ();
        type ModuleToIndex = ();
    }

    impl did::Trait for Test {
        type Event = ();
    }

    impl super::Trait for Test {}

    const ABBA: u64 = 0;
    const BORL: u64 = 1;
    const CAPN: u64 = 2;
    const ARG: RegistryId = [0u8; 32];
    const BRG: RegistryId = [1u8; 32];
    const CRG: RegistryId = [2u8; 32];
    const AR: RevokeId = [0u8; 32];
    const BR: RevokeId = [1u8; 32];
    const CR: RevokeId = [2u8; 32];
    const DIDA: Did = [0u8; 32];
    const DIDB: Did = [1u8; 32];
    const DIDC: Did = [2u8; 32];

    /// check whether test externalies are available
    fn in_ext() -> bool {
        std::panic::catch_unwind(|| sp_io::storage::exists(&[])).is_ok()
    }

    #[test]
    fn meta_in_ext() {
        assert!(!in_ext());
        ext().execute_with(|| assert!(in_ext()));
    }

    fn ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    // increment block number
    fn incbn() {
        System::set_block_number(System::block_number() + 1);
    }

    // create a OneOf policy
    fn oneof(dids: &[Did]) -> Policy {
        Policy::OneOf {
            controllers: dids.iter().cloned().collect(),
        }
    }

    /// generate a random keypair
    fn gen_kp() -> sr25519::Pair {
        sr25519::Pair::generate_with_phrase(None).0
    }

    // Create did for `did`. Return the randomly generated signing key.
    // The did public key is controlled by some non-existent account (normally a security
    // concern), but that doesn't matter for our purposes.
    fn create_did(did: did::Did) -> sr25519::Pair {
        let kp = gen_kp();
        did::Module::<Test>::new(
            Origin::signed(ABBA),
            did,
            did::KeyDetail::new(
                [100; 32],
                did::PublicKey::Sr25519(did::Bytes32 {
                    value: kp.public().0,
                }),
            ),
        )
        .unwrap();
        kp
    }

    #[test]
    fn policy_satisfied_by() {
        let cases: &[(Policy, &[Did], bool)] = &[
            (oneof(&[]), &[], false),
            (oneof(&[]), &[DIDA], false),
            (oneof(&[DIDA]), &[], false),
            (oneof(&[DIDA]), &[DIDA], true),
            (oneof(&[DIDA, DIDB]), &[DIDA], true),
            (oneof(&[DIDA, DIDB]), &[DIDB], true),
            (oneof(&[DIDA]), &[DIDB], false),
            (oneof(&[DIDA, DIDB]), &[DIDC], false),
            (oneof(&[]), &[DIDA, DIDB], false),
            (oneof(&[DIDA, DIDB]), &[DIDA, DIDB], false),
        ];

        for (pol, set, result) in cases {
            let set: Vec<&Did> = set.iter().collect();
            dbg!((&pol, &set));
            assert_eq!(pol.satisfied_by(&set), *result);
        }
    }

    mod errors {
        use super::*;

        #[test]
        fn invalidpolicy() {
            if !in_ext() {
                return ext().execute_with(invalidpolicy);
            }

            let err = TestMod::new_registry(
                Origin::signed(ABBA),
                ARG,
                Registry {
                    policy: oneof(&[]),
                    add_only: false,
                },
            )
            .unwrap_err();
            assert_eq!(err, RevErr::<Test>::InvalidPolicy.into());
        }

        #[test]
        fn notauthorized() {
            if !in_ext() {
                return ext().execute_with(notauthorized);
            }

            let abba = Origin::signed(ABBA);
            let kpa = create_did(DIDA);
            TestMod::new_registry(
                abba.clone(),
                ARG,
                Registry {
                    policy: oneof(&[DIDA]),
                    add_only: false,
                },
            )
            .unwrap();

            let kpb = create_did(DIDB);
            let revoke = Revoke {
                registry_id: ARG,
                revoke_ids: BTreeSet::new(),
                last_modified: 1u32,
            };
            let sig = did::Signature::Sr25519(did::Bytes64 {
                value: kpb
                    .sign(&crate::StateChange::Revoke(revoke.clone()).encode())
                    .0,
            });
            let err = TestMod::revoke(abba, revoke, BTreeMap::new()).unwrap_err();
            assert_eq!(err, RevErr::<Test>::NotAuthorized.into());

            todo!("sign unrelated commands and make sure they fail");
            todo!("sign with the wrong key");
            todo!("sign with the wrong algo");
        }

        #[test]
        fn regexists() {
            todo!()
        }

        #[test]
        fn noreg() {
            todo!()
        }

        #[test]
        fn wrongnonce() {
            todo!()
        }

        #[test]
        fn addonly() {
            todo!()
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
                | RevErr::WrongNonce
                | RevErr::AddOnly => {}
            }
        }
    }

    mod calls {
        // new_registry
        // revoke
        // unrevoke
        // remove_registry
    }
}
