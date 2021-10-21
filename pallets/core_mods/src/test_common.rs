//! Boilerplate for runtime module unit tests

use crate::anchor;
use crate::attest;
use crate::bbs_plus;
use crate::blob;
use crate::did::{self, Did, DidSignature};
use crate::master;
use crate::revoke;

use crate::revoke::{Policy, RegistryId, RevokeId};
use codec::{Decode, Encode};
use frame_support::{
    parameter_types,
    traits::{OnFinalize, OnInitialize},
    weights::Weight,
};
use frame_system as system;
pub use rand::random;
use sp_core::{sr25519, Pair, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
pub use std::iter::once;

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        DIDModule: did::{Module, Call, Storage, Event, Config},
        RevoMod: revoke::{Module, Call, Storage},
        BlobMod: blob::{Module, Call, Storage},
        MasterMod: master::{Module, Call, Storage, Event<T>, Config},
        AnchorMod: anchor::{Module, Call, Storage, Event<T>},
        AttestMod: attest::{Module, Call, Storage},
        BBSPlusMod: bbs_plus::{Module, Call, Storage, Event}
    }
);

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

parameter_types! {
    pub const BlockHashCount: u64 = 250;
}

impl system::Config for Test {
    type BaseCallFilter = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = TestEvent;
    type BlockHashCount = BlockHashCount;
    type DbWeight = ();
    type BlockWeights = ();
    type BlockLength = ();
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
}

impl crate::did::Trait for Test {
    type Event = ();
}

impl crate::revoke::Trait for Test {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const StorageWeight: Weight = 1100;
    pub const ParamsMaxSize: u32 = 512;
    pub const ParamsPerByteWeight: Weight = 10;
    pub const PublicKeyMaxSize: u32 = 128;
    pub const PublicKeyPerByteWeight: Weight = 10;
}

impl crate::blob::Trait for Test {
    type MaxBlobSize = MaxBlobSize;
    type StorageWeight = StorageWeight;
}

impl crate::master::Trait for Test {
    type Event = TestEvent;
    type Call = Call;
}

impl crate::anchor::Trait for Test {
    type Event = TestEvent;
}

impl crate::attest::Trait for Test {
    type StorageWeight = StorageWeight;
}

impl crate::bbs_plus::Config for Test {
    type Event = ();
    type ParamsMaxSize = ParamsMaxSize;
    type ParamsPerByteWeight = ParamsPerByteWeight;
    type PublicKeyMaxSize = PublicKeyMaxSize;
    type PublicKeyPerByteWeight = PublicKeyPerByteWeight;
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

/// Changes the block number. Calls `on_finalize` and `on_initialize`
pub fn run_to_block(n: u64) {
    while System::block_number() < n {
        if System::block_number() > 1 {
            System::on_finalize(System::block_number());
        }
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
    }
}
