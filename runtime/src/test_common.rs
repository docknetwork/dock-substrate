//! Boilerplate for runtime module unit tests

use crate::did;
use crate::did::{Did, DidSignature};
use crate::revoke::{Policy, RegistryId, RevokeId};
use codec::Encode;
use frame_support::{impl_outer_origin, parameter_types, weights::Weight};
use sp_core::{Pair, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    Perbill,
};

pub use frame_support::dispatch::DispatchError;
pub use rand::random;
pub use sp_core::sr25519;
pub use std::iter::once;

pub type RevoMod = crate::revoke::Module<Test>;

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
    type Call = ();
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type DbWeight = ();
    type BlockExecutionWeight = ();
    type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type ModuleToIndex = ();
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
}

impl crate::did::Trait for Test {
    type Event = ();
}

impl crate::revoke::Trait for Test {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
}

impl crate::blob::Trait for Test {
    type MaxBlobSize = MaxBlobSize;
}

pub const ABBA: u64 = 0;
pub const RGA: RegistryId = [0u8; 32];
pub const RA: RevokeId = [0u8; 32];
pub const RB: RevokeId = [1u8; 32];
pub const RC: RevokeId = [2u8; 32];
pub const DIDA: Did = [0u8; 32];
pub const DIDB: Did = [1u8; 32];
pub const DIDC: Did = [2u8; 32];

/// check whether test externalies are available
pub fn in_ext() -> bool {
    std::panic::catch_unwind(|| sp_io::storage::exists(&[])).is_ok()
}

#[test]
pub fn meta_in_ext() {
    assert!(!in_ext());
    ext().execute_with(|| assert!(in_ext()));
}

pub fn ext() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}

// create a OneOf policy
pub fn oneof(dids: &[Did]) -> Policy {
    Policy::OneOf(dids.iter().cloned().collect())
}

/// generate a random keypair
pub fn gen_kp() -> sr25519::Pair {
    sr25519::Pair::generate_with_phrase(None).0
}

// Create did for `did`. Return the randomly generated signing key.
// The did public key is controlled by some non-existent account (normally a security
// concern), but that doesn't matter for our purposes.
pub fn create_did(did: did::Did) -> sr25519::Pair {
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

/// create a did with a random id and random signing key
pub fn newdid() -> (Did, sr25519::Pair) {
    let d: Did = rand::random();
    (d, create_did(d))
}

pub fn sign(payload: &crate::StateChange, keypair: &sr25519::Pair) -> DidSignature {
    DidSignature::Sr25519(did::Bytes64 {
        value: keypair.sign(&payload.encode()).0,
    })
}
