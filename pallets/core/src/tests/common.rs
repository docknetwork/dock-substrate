//! Boilerplate for runtime module unit tests

use crate::{
    accumulator, anchor, attest, blob,
    common::{self, StateChange, ToStateChange},
    did::{self, Did, DidKey, DidSignature},
    master, offchain_signatures, revoke, status_list_credential,
};

use crate::{
    common::SigValue,
    revoke::{RegistryId, RevokeId},
};
use codec::{Decode, Encode};
use frame_support::{
    parameter_types,
    traits::{Contains, OnFinalize, OnInitialize},
    weights::Weight,
};
use frame_system::RawOrigin;
use pallet_evm::EnsureAddressOrigin;
pub use rand::random;
use sp_core::{sr25519, Pair, H160, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, ConstU32, IdentityLookup},
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
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
        DIDModule: did::{Pallet, Call, Storage, Event<T>, Config<T>},
        RevoMod: revoke::{Pallet, Call, Storage, Event},
        BlobMod: blob::{Pallet, Call, Storage},
        MasterMod: master::{Pallet, Call, Storage, Event<T>, Config<T>},
        AnchorMod: anchor::{Pallet, Call, Storage, Event<T>},
        AttestMod: attest::{Pallet, Call, Storage},
        SignatureMod: offchain_signatures::{Pallet, Call, Storage, Event},
        AccumMod: accumulator::{Pallet, Call, Storage, Event},
        StatusListCredentialMod: status_list_credential::{Pallet, Call, Storage, Event},
        EVM: pallet_evm::{Pallet, Config, Call, Storage, Event<T>},
    }
);

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug, Eq)]
pub enum TestEvent {
    Did(crate::did::Event<Test>),
    Revoke(crate::revoke::Event),
    Master(crate::master::Event<Test>),
    Anchor(crate::anchor::Event<Test>),
    Unknown,
    OffchainSignature(offchain_signatures::Event),
    Accum(accumulator::Event),
    StatusListCredential(status_list_credential::Event),
}

impl From<frame_system::Event<Test>> for TestEvent {
    fn from(_: frame_system::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<pallet_balances::Event<Test>> for TestEvent {
    fn from(_: pallet_balances::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<pallet_evm::Event<Test>> for TestEvent {
    fn from(_: pallet_evm::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<()> for TestEvent {
    fn from((): ()) -> Self {
        Self::Unknown
    }
}

impl From<crate::did::Event<Test>> for TestEvent {
    fn from(other: crate::did::Event<Test>) -> Self {
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

impl From<crate::status_list_credential::Event> for TestEvent {
    fn from(other: crate::status_list_credential::Event) -> Self {
        Self::StatusListCredential(other)
    }
}

impl From<offchain_signatures::Event> for TestEvent {
    fn from(other: offchain_signatures::Event) -> Self {
        Self::OffchainSignature(other)
    }
}

impl From<accumulator::Event> for TestEvent {
    fn from(other: accumulator::Event) -> Self {
        Self::Accum(other)
    }
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaxPolicyControllers: u32 = 15;
    pub const MaxStatusListCredentialSize: u32 = 1_000;
    pub const MinStatusListCredentialSize: u32 = 10;
    pub const ByteReadWeight: Weight = Weight::from_ref_time(10);
}

pub struct BaseFilter;
impl Contains<Call> for BaseFilter {
    fn contains(_call: &Call) -> bool {
        true
    }
}

impl frame_system::Config for Test {
    type OnSetCode = ();
    type MaxConsumers = ConstU32<10>;
    type BaseCallFilter = BaseFilter;
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
    type AccountData = pallet_balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ();
    type WeightInfo = ();
}

pub struct DummyCallOrigin;
impl<OuterOrigin> EnsureAddressOrigin<OuterOrigin> for DummyCallOrigin
where
    OuterOrigin: Into<Result<RawOrigin<u64>, OuterOrigin>> + From<RawOrigin<u64>>,
{
    type Success = u64;

    fn try_address_origin(_: &H160, _: OuterOrigin) -> Result<u64, OuterOrigin> {
        unimplemented!()
    }
}

/// Identity address mapping.
pub struct DummyAddressMapping;
impl pallet_evm::AddressMapping<u64> for DummyAddressMapping {
    fn into_account_id(_: H160) -> u64 {
        unimplemented!()
    }
}

impl pallet_evm::Config for Test {
    type FeeCalculator = ();
    type GasWeightMapping = ();
    type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
    type CallOrigin = DummyCallOrigin;
    type WithdrawOrigin = DummyCallOrigin;
    type AddressMapping = DummyAddressMapping;
    type Currency = Balances;
    type Event = TestEvent;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type ByteReadWeight = ByteReadWeight;
    type PrecompilesType = ();
    type PrecompilesValue = ();
    type ChainId = ();
    type BlockGasLimit = ();
    type OnChargeTransaction = ();
    type FindAuthor = ();
}

impl pallet_balances::Config for Test {
    type ReserveIdentifier = ();
    type MaxReserves = ();
    type MaxLocks = ();
    type Balance = u64;
    type Event = TestEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxMasterMembers: u32 = 100;
}

impl crate::common::Limits for Test {
    type MaxDidDocRefSize = MaxDidDocRefSize;
    type MaxDidServiceEndpointIdSize = MaxDidServiceEndpointIdSize;
    type MaxDidServiceEndpointOrigins = MaxDidServiceEndpointOrigins;
    type MaxDidServiceEndpointOriginSize = MaxDidServiceEndpointOriginSize;

    type MaxAccumulatorLabelSize = MaxAccumulatorLabelSize;
    type MaxAccumulatorParamsSize = MaxAccumulatorParamsSize;
    type MaxAccumulatorPublicKeySize = MaxBBSPublicKeySize;
    type MaxAccumulatorAccumulatedSize = MaxAccumulatorAccumulatedSize;

    type MaxStatusListCredentialSize = MaxStatusListCredentialSize;
    type MinStatusListCredentialSize = MinStatusListCredentialSize;

    type MaxIriSize = MaxIriSize;
    type MaxBlobSize = MaxBlobSize;

    type MaxOffchainParamsLabelSize = MaxAccumulatorParamsSize;
    type MaxOffchainParamsBytesSize = MaxAccumulatorParamsSize;
    type MaxBBSPublicKeySize = MaxBBSPublicKeySize;
    type MaxBBSPlusPublicKeySize = MaxBBSPublicKeySize;
    type MaxPSPublicKeySize = MaxPSPublicKeySize;

    type MaxMasterMembers = MaxMasterMembers;
    type MaxPolicyControllers = MaxPolicyControllers;
}

impl crate::did::Config for Test {
    type Event = TestEvent;
    type OnDidRemoval = SignatureMod;
}

impl crate::revoke::Config for Test {
    type Event = TestEvent;
}
impl crate::status_list_credential::Config for Test {
    type Event = TestEvent;
}
impl crate::blob::Config for Test {}
impl crate::attest::Config for Test {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const MaxIriSize: u32 = 1024;
    pub const MaxAccumulatorLabelSize: u32 = 512;
    pub const MaxAccumulatorParamsSize: u32 = 512;
    pub const MaxBBSPublicKeySize: u32 = 128;
    pub const MaxPSPublicKeySize: u32 = 128;
    pub const MaxAccumulatorAccumulatedSize: u32 = 256;
    pub const MaxDidDocRefSize: u16 = 128;
    pub const MaxDidServiceEndpointIdSize: u16 = 256;
    pub const MaxDidServiceEndpointOrigins: u16 = 20;
    pub const MaxDidServiceEndpointOriginSize: u16 = 256;
}

impl crate::anchor::Config for Test {
    type Event = TestEvent;
}

impl crate::master::Config for Test {
    type Event = TestEvent;
    type Call = Call;
}

impl offchain_signatures::Config for Test {
    type Event = TestEvent;
}

impl accumulator::Config for Test {
    type Event = TestEvent;
}

pub const ABBA: u64 = 0;
pub const DIDA: Did = Did([0u8; 32]);
pub const DIDB: Did = Did([1u8; 32]);
pub const DIDC: Did = Did([2u8; 32]);
pub const RGA: RegistryId = RegistryId([0u8; 32]);
pub const RA: RevokeId = RevokeId([0u8; 32]);
pub const RB: RevokeId = RevokeId([1u8; 32]);
pub const RC: RevokeId = RevokeId([2u8; 32]);

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
    let mut ret: sp_io::TestExternalities = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into();
    ret.execute_with(|| {
        frame_system::Pallet::<Test>::initialize(
            &1, // system module will not store events if block_number == 0
            &[0u8; 32].into(),
            &Default::default(),
        );
    });
    ret
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
    did::Pallet::<Test>::new_onchain(
        Origin::signed(ABBA),
        did,
        vec![
            DidKey::new_with_all_relationships(common::PublicKey::Sr25519(kp.public().0.into()))
                .into(),
        ],
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

pub fn sign<T: crate::did::Config>(payload: &StateChange<T>, keypair: &sr25519::Pair) -> SigValue {
    SigValue::Sr25519(keypair.sign(&payload.encode()).0.into())
}

pub fn did_sig<T: crate::did::Config, A: ToStateChange<T>, D: Into<Did>>(
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

pub fn did_sig_on_bytes<D: Into<Did>>(
    msg_bytes: &[u8],
    keypair: &sr25519::Pair,
    did: D,
    key_id: u32,
) -> DidSignature<D> {
    let sig = SigValue::Sr25519(keypair.sign(msg_bytes).0.into());

    DidSignature {
        did,
        key_id: key_id.into(),
        sig,
    }
}

/// create a random byte array with set len
pub fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random()).collect()
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

pub fn check_nonce(d: &Did, nonce: u64) {
    let did_detail = DIDModule::onchain_did_details(d).unwrap();
    assert_eq!(did_detail.nonce, nonce);
}

pub fn inc_nonce(d: &Did) {
    let mut did_detail = DIDModule::onchain_did_details(d).unwrap();
    did_detail.nonce = did_detail.next_nonce().unwrap();
    DIDModule::insert_did_details(*d, did_detail);
}
