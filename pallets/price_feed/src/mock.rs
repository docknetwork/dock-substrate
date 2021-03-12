use crate as price_feed;

use frame_support::parameter_types;
use frame_system as system;
use sp_core::{Hasher, H160, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

use pallet_evm::{AddressMapping, EnsureAddressNever};

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        Balances: balances::{Module, Call, Storage},
        EVM: pallet_evm::{Module, Config, Call, Storage, Event<T>},
        PriceFeedModule: price_feed::{Module, Call, Storage, Event, Config},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 21;
    pub const DockChainId: u64 = 2021;
    pub const MinimumPeriod: u64 = 1000;
}

impl system::Config for Test {
    type BaseCallFilter = ();
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
    type PalletInfo = ();
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
    /// Don't care about these origins
    type CallOrigin = EnsureAddressNever<Self::AccountId>;
    type WithdrawOrigin = EnsureAddressNever<Self::AccountId>;
    type AddressMapping = TestAddressMapping<BlakeTwo256>;
    type Currency = Balances;
    type Event = ();
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type Precompiles = ();
    type ChainId = DockChainId;
    type OnChargeTransaction = ();
}

/*/// Dummy session handler as the pallet's trait needs the session pallet's trait
pub struct TestSessionHandler;
type ValidatorId = u64;
impl pallet_session::SessionHandler<ValidatorId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [KeyTypeId] = &[key_types::DUMMY];

    fn on_genesis_session<K: OpaqueKeys>(_validators: &[(ValidatorId, K)]) {}

    fn on_new_session<K: OpaqueKeys>(
        _changed: bool,
        _validators: &[(ValidatorId, K)],
        _queued_validators: &[(ValidatorId, K)],
    ) {
    }

    fn on_disabled(_validator_index: usize) {}
}

impl pallet_session::Config for Test {
    type Event = ();
    type ValidatorId = AccountId;
    type ValidatorIdOf = ();
    type ShouldEndSession = PoAModule;
    type NextSessionRotation = ();
    type SessionManager = PoAModule;
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type DisabledValidatorsThreshold = ();
    type WeightInfo = ();
}

impl pallet_authorship::Config for Test {
    type FindAuthor = ();
    type UncleGenerations = ();
    type FilterUncle = ();
    type EventHandler = ();
}

impl poa::Trait for TestRuntime {
    type Event = ();
    type Currency = balances::Module<Self>;
}*/

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
