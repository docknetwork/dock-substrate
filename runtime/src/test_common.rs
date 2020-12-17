//! Boilerplate for runtime module unit tests

use crate::did::{self, Did, DidSignature};
use crate::revoke::{Policy, RegistryId, RevokeId};
use codec::{Decode, Encode};
use frame_support::{
    dispatch::{DispatchInfo, DispatchResultWithPostInfo, Dispatchable, PostDispatchInfo},
    impl_outer_origin, parameter_types,
    traits::UnfilteredDispatchable,
    weights::{DispatchClass, GetDispatchInfo, Pays, Weight},
};
use frame_system as system;
pub use rand::random;
use sp_core::{sr25519, Pair, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    Perbill,
};
pub use std::iter::once;

pub type RevoMod = crate::revoke::Module<Test>;

impl_outer_origin! {
    pub enum Origin for Test {}
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
pub enum TestCall {
    Master(crate::master::Call<Test>),
    System(system::Call<Test>),
}

impl Dispatchable for TestCall {
    type Origin = Origin;
    type Trait = ();
    type Info = ();
    type PostInfo = PostDispatchInfo;
    fn dispatch(self, origin: Self::Origin) -> sp_runtime::DispatchResultWithInfo<Self::PostInfo> {
        match self {
            TestCall::Master(mc) => mc.dispatch_bypass_filter(origin),
            TestCall::System(sc) => sc.dispatch_bypass_filter(origin),
        }
    }
}

impl UnfilteredDispatchable for TestCall {
    type Origin = Origin;

    fn dispatch_bypass_filter(self, origin: Self::Origin) -> DispatchResultWithPostInfo {
        match self {
            TestCall::Master(mc) => mc.dispatch_bypass_filter(origin),
            TestCall::System(sc) => sc.dispatch_bypass_filter(origin),
        }
    }
}

impl GetDispatchInfo for TestCall {
    fn get_dispatch_info(&self) -> DispatchInfo {
        DispatchInfo {
            weight: 101u64,
            class: DispatchClass::Normal,
            pays_fee: Pays::Yes,
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
pub enum TestEvent {
    Master(crate::master::Event<Test>),
    Anchor(crate::anchor::Event<Test>),
    Unknown,
}

impl From<system::Event<Test>> for TestEvent {
    fn from(_: system::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<()> for TestEvent {
    fn from((): ()) -> Self {
        Self::Unknown
    }
}

impl From<crate::master::Event<Test>> for TestEvent {
    fn from(other: crate::master::Event<Test>) -> Self {
        Self::Master(other)
    }
}

impl From<crate::anchor::Event<Test>> for TestEvent {
    fn from(other: crate::anchor::Event<Test>) -> Self {
        Self::Anchor(other)
    }
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
    type BaseCallFilter = ();
    type Origin = Origin;
    type Call = ();
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = TestEvent;
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type DbWeight = ();
    type BlockExecutionWeight = ();
    type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type PalletInfo = ();
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
}

impl crate::did::Trait for Test {
    type Event = ();
}

impl crate::revoke::Trait for Test {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const StorageWeight: Weight = 1100;
}

impl crate::blob::Trait for Test {
    type MaxBlobSize = MaxBlobSize;
    type StorageWeight = StorageWeight;
}

impl crate::master::Trait for Test {
    type Event = TestEvent;
    type Call = TestCall;
}

impl crate::anchor::Trait for Test {
    type Event = TestEvent;
}

impl crate::attest::Trait for Test {
    type StorageWeight = StorageWeight;
}

pub const ABBA: u64 = 0;
pub const RGA: RegistryId = [0u8; 32];
pub const RA: RevokeId = [0u8; 32];
pub const RB: RevokeId = [1u8; 32];
pub const RC: RevokeId = [2u8; 32];
pub const DIDA: Did = [0u8; 32];
pub const DIDB: Did = [1u8; 32];
pub const DIDC: Did = [2u8; 32];

/// check whether test externalities are available
pub fn in_ext() -> bool {
    std::panic::catch_unwind(|| sp_io::storage::exists(&[])).is_ok()
}

#[test]
pub fn meta_in_ext() {
    assert!(!in_ext());
    ext().execute_with(|| assert!(in_ext()));
}

pub fn ext() -> sp_io::TestExternalities {
    let mut ret: sp_io::TestExternalities = system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into();
    ret.execute_with(|| {
        system::Module::<Test>::initialize(
            &1, // system module will not store events if block_number == 0
            &[0u8; 32].into(),
            &[0u8; 32].into(),
            &Default::default(),
            system::InitKind::Full,
        );
    });
    ret
}

// get the current block number from the system module
pub fn block_no() -> u64 {
    system::Module::<Test>::block_number()
}

/// create a OneOf policy
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
    println!("did pk: {:?}", kp.public().0);
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

/// create a random byte array with set len
pub fn random_bytes(len: usize) -> Vec<u8> {
    let ret: Vec<u8> = (0..len).map(|_| rand::random()).collect();
    assert_eq!(ret.len(), len);
    ret
}
