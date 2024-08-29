use super::*;
use crate as dock_agreement;

use codec::{Decode, Encode};
use frame_support::{
    parameter_types,
    sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    },
    weights::{
        constants::{RocksDbWeight, WEIGHT_PER_SECOND},
        Weight,
    },
};
use sp_core::H256;

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
        Agreement: dock_agreement::{Pallet, Call, Event},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = WEIGHT_PER_SECOND.saturating_mul(2);
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const TransactionByteFee: u64 = 1;
    // Not accepting any uncles
    pub const UncleGenerations: u32 = 0;
    pub const MinimumPeriod: u64 = 1000;
}

#[derive(Encode, Decode, scale_info::TypeInfo, Clone, PartialEq, Debug, Eq)]
pub enum TestEvent {
    Agreement(dock_agreement::Event),
}

impl From<frame_system::Event<Test>> for TestEvent {
    fn from(_: frame_system::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<dock_agreement::Event> for TestEvent {
    fn from(event: dock_agreement::Event) -> Self {
        Self::Agreement(event)
    }
}

impl frame_system::Config for Test {
    type OnSetCode = ();
    type MaxConsumers = sp_runtime::traits::ConstU32<10>;
    type BaseCallFilter = frame_support::traits::Everything;
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
    type DbWeight = RocksDbWeight;
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

impl Config for Test {
    type Event = TestEvent;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}
