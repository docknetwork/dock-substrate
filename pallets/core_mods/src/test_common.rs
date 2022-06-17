//! Boilerplate for runtime module unit tests

use crate::accumulator;
use crate::anchor;
use crate::attest;
use crate::bbs_plus;
use crate::blob;
use crate::did::{self, Did, DidKey, DidSignature};
use crate::master;
use crate::revoke;
use crate::Action;
use crate::{keys_and_sigs, util};

use crate::keys_and_sigs::SigValue;
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
        // DIDModule: did::{Module, Call, Storage, Event, Config},
        DIDModule: did::{Module, Call, Storage, Event},
        RevoMod: revoke::{Module, Call, Storage, Event},
        BlobMod: blob::{Module, Call, Storage},
        // MasterMod: master::{Module, Call, Storage, Event<T>, Config},
        MasterMod: master::{Module, Call, Storage, Event<T>},
        AnchorMod: anchor::{Module, Call, Storage, Event<T>},
        AttestMod: attest::{Module, Call, Storage},
        BBSPlusMod: bbs_plus::{Module, Call, Storage, Event},
        AccumMod: accumulator::{Module, Call, Storage, Event}
    }
);

#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
pub enum TestEvent {
    Did(crate::did::Event),
    Revoke(crate::revoke::Event),
    Master(crate::master::Event<Test>),
    Anchor(crate::anchor::Event<Test>),
    Unknown,
    BBSPlus(bbs_plus::Event),
    Accum(accumulator::Event),
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

impl From<crate::did::Event> for TestEvent {
    fn from(other: crate::did::Event) -> Self {
        Self::Did(other)
    }
}

impl From<crate::revoke::Event> for TestEvent {
    fn from(other: crate::revoke::Event) -> Self {
        Self::Revoke(other)
    }
}

impl From<crate::anchor::Event<Test>> for TestEvent {
    fn from(other: crate::anchor::Event<Test>) -> Self {
        Self::Anchor(other)
    }
}

impl From<crate::master::Event<Test>> for TestEvent {
    fn from(other: crate::master::Event<Test>) -> Self {
        Self::Master(other)
    }
}

impl From<bbs_plus::Event> for TestEvent {
    fn from(other: bbs_plus::Event) -> Self {
        Self::BBSPlus(other)
    }
}

impl From<accumulator::Event> for TestEvent {
    fn from(other: accumulator::Event) -> Self {
        Self::Accum(other)
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

impl crate::did::Config for Test {
    type Event = TestEvent;
    type MaxDidDocRefSize = MaxDidDocRefSize;
    type DidDocRefPerByteWeight = DidDocRefPerByteWeight;
    type MaxServiceEndpointIdSize = MaxServiceEndpointIdSize;
    type ServiceEndpointIdPerByteWeight = ServiceEndpointIdPerByteWeight;
    type MaxServiceEndpointOrigins = MaxServiceEndpointOrigins;
    type MaxServiceEndpointOriginSize = MaxServiceEndpointOriginSize;
    type ServiceEndpointOriginPerByteWeight = ServiceEndpointOriginPerByteWeight;
}

impl crate::revoke::Config for Test {
    type Event = TestEvent;
}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const StorageWeight: Weight = 1100;
    pub const LabelMaxSize: u32 = 512;
    pub const LabelPerByteWeight: Weight = 10;
    pub const ParamsMaxSize: u32 = 512;
    pub const ParamsPerByteWeight: Weight = 10;
    pub const PublicKeyMaxSize: u32 = 128;
    pub const PublicKeyPerByteWeight: Weight = 10;
    pub const AccumulatedMaxSize: u32 = 256;
    pub const AccumulatedPerByteWeight: Weight = 10;
    pub const MaxDidDocRefSize: u16 = 128;
    pub const DidDocRefPerByteWeight: Weight = 10;
    pub const MaxServiceEndpointIdSize: u16 = 256;
    pub const ServiceEndpointIdPerByteWeight: Weight = 10;
    pub const MaxServiceEndpointOrigins: u16 = 20;
    pub const MaxServiceEndpointOriginSize: u16 = 256;
    pub const ServiceEndpointOriginPerByteWeight: Weight = 10;
}

impl crate::anchor::Config for Test {
    type Event = TestEvent;
}

impl crate::blob::Config for Test {
    type MaxBlobSize = MaxBlobSize;
    type StorageWeight = StorageWeight;
}

impl crate::master::Config for Test {
    type Event = TestEvent;
    type Call = Call;
}

impl crate::attest::Config for Test {
    type StorageWeight = StorageWeight;
}

impl bbs_plus::Config for Test {
    type Event = TestEvent;
    type LabelMaxSize = LabelMaxSize;
    type LabelPerByteWeight = LabelPerByteWeight;
    type ParamsMaxSize = ParamsMaxSize;
    type ParamsPerByteWeight = ParamsPerByteWeight;
    type PublicKeyMaxSize = PublicKeyMaxSize;
    type PublicKeyPerByteWeight = PublicKeyPerByteWeight;
}

impl accumulator::Config for Test {
    type Event = TestEvent;
    type LabelMaxSize = LabelMaxSize;
    type LabelPerByteWeight = LabelPerByteWeight;
    type ParamsMaxSize = ParamsMaxSize;
    type ParamsPerByteWeight = ParamsPerByteWeight;
    type PublicKeyMaxSize = PublicKeyMaxSize;
    type PublicKeyPerByteWeight = PublicKeyPerByteWeight;
    type AccumulatedMaxSize = AccumulatedMaxSize;
    type AccumulatedPerByteWeight = AccumulatedPerByteWeight;
}

pub const ABBA: u64 = 0;
pub const DIDA: Did = Did([0u8; 32]);
pub const DIDB: Did = Did([1u8; 32]);
pub const DIDC: Did = Did([2u8; 32]);
pub const RGA: RegistryId = [0u8; 32];
pub const RA: RevokeId = [0u8; 32];
pub const RB: RevokeId = [1u8; 32];
pub const RC: RevokeId = [2u8; 32];

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
    did::Module::<Test>::new_onchain(
        Origin::signed(ABBA),
        did,
        vec![DidKey::new_with_all_relationships(
            keys_and_sigs::PublicKey::Sr25519(util::Bytes32 {
                value: kp.public().0,
            }),
        )],
        vec![].into_iter().collect(),
    )
    .unwrap();
    kp
}

/// create a did with a random id and random signing key
pub fn newdid() -> (Did, sr25519::Pair) {
    let d: Did = Did(rand::random());
    (d, create_did(d))
}

pub fn sign<T: frame_system::Config>(
    payload: &crate::StateChange<T>,
    keypair: &sr25519::Pair,
) -> SigValue {
    SigValue::Sr25519(util::Bytes64 {
        value: keypair.sign(&payload.encode()).0,
    })
}

pub fn did_sig<T: frame_system::Config, A: Action<T>, D: Into<Did>>(
    change: &A,
    keypair: &sr25519::Pair,
    did: D,
    key_id: u32,
) -> DidSignature<D> {
    let sig = sign(&change.to_state_change(), keypair);
    DidSignature {
        did,
        key_id: key_id.into(),
        sig,
    }
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
