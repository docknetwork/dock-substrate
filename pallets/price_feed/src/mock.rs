use crate as price_feed;

use frame_support::parameter_types;
use frame_system as system;
use pallet_evm::{AddressMapping, EnsureAddressNever};
use sp_core::{Hasher, H160, H256, U256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};

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
        Balances: balances::{Pallet, Call, Storage},
        EVM: pallet_evm::{Pallet, Config, Call, Storage, Event<T>},
        PriceFeedModule: price_feed::{Pallet, Call, Storage, Event},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 21;
    pub const DockChainId: u64 = 2021;
    pub const MinimumPeriod: u64 = 1000;
    pub BlockGasLimit: U256 = U256::from(u32::max_value());
}

impl system::Config for Test {
    type OnSetCode = ();
    type MaxConsumers = sp_runtime::traits::ConstU32<10>;
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
}

impl balances::Config for Test {
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = ();
}

impl timestamp::Config for Test {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

pub struct TestAddressMapping<H>(sp_std::marker::PhantomData<H>);
impl<H: Hasher<Out = H256>> AddressMapping<u64> for TestAddressMapping<H> {
    fn into_account_id(address: H160) -> u64 {
        // The result should be unique to avoid `CreateCollision` error
        let a = address.as_bytes().to_vec();
        let s: [u8; 8] = [a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]];
        let b = u64::from_le_bytes(s);
        b
    }
}

impl pallet_evm::Config for Test {
    type FeeCalculator = ();
    type GasWeightMapping = ();
    // type ByteReadWeight = ();
    /// Don't care about these origins
    type CallOrigin = EnsureAddressNever<Self::AccountId>;
    type WithdrawOrigin = EnsureAddressNever<Self::AccountId>;
    type AddressMapping = TestAddressMapping<BlakeTwo256>;
    type Currency = Balances;
    type Event = ();
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type PrecompilesType = ();
    type PrecompilesValue = ();
    type ChainId = DockChainId;
    type OnChargeTransaction = ();
    type BlockGasLimit = BlockGasLimit;
    type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
    type FindAuthor = ();
}

impl price_feed::Config for Test {
    type Event = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}
