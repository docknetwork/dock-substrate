#![cfg(test)]

use super::*;
use crate as dock_poa;

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
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<TestRuntime>;
type Block = frame_system::mocking::MockBlock<TestRuntime>;
frame_support::construct_runtime!(
    pub enum TestRuntime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: balances::{Pallet, Call, Storage},
        PoAModule: dock_poa::{Pallet, Storage},
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

impl frame_system::Config for TestRuntime {
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
    type MaxReserves = ();
    type ReserveIdentifier = ();
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
}

impl Config for TestRuntime {
    type Currency = Balances;
}

#[test]
fn expected_treasury_account_id() {
    use sp_runtime::traits::AccountIdConversion;
    assert_eq!(
        AccountIdConversion::<[u8; 32]>::into_account_truncating(&TREASURY_ID),
        *b"modlTreasury\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
}
