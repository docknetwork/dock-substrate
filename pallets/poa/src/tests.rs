#![cfg(test)]

use super::*;
use crate as poa;

use frame_support::{
    assert_err, assert_ok, parameter_types,
    sp_runtime::{
        testing::{Header, UintAuthorityId},
        traits::{BlakeTwo256, ConvertInto, IdentityLookup, OpaqueKeys},
        ConsensusEngineId, KeyTypeId, Perbill,
    },
    traits::FindAuthor,
    weights::{
        constants::{RocksDbWeight, WEIGHT_PER_SECOND},
        Weight,
    },
};
use frame_system::{self as system, RawOrigin};
use sp_core::{crypto::key_types, H256};

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<TestRuntime>;
type Block = frame_system::mocking::MockBlock<TestRuntime>;
frame_support::construct_runtime!(
    pub enum TestRuntime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        Balances: balances::{Module, Call, Storage},
        PoAModule: poa::{Module, Call, Storage, Config<T>},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 2 * WEIGHT_PER_SECOND;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const TransactionByteFee: u64 = 1;
    // Not accepting any uncles
    pub const UncleGenerations: u32 = 0;
    pub const MinimumPeriod: u64 = 1000;
}

impl system::Config for TestRuntime {
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
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type DbWeight = RocksDbWeight;
    type BlockWeights = ();
    type BlockLength = ();
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
}

impl balances::Config for TestRuntime {
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
}

impl Trait for TestRuntime {
    type Currency = Balances;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<TestRuntime>()
        .unwrap();
    crate::GenesisConfig::<TestRuntime> {
        emission_supply: 0,
        poa_last_block: H256::zero(),
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let ext: sp_io::TestExternalities = t.into();
    ext
}

#[test]
fn expected_treasury_account_id() {
    use sp_runtime::traits::AccountIdConversion;
    assert_eq!(
        AccountIdConversion::<[u8; 32]>::into_account(&TREASURY_ID),
        *b"modlTreasury\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
}