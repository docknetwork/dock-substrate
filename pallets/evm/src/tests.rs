#![cfg(test)]

use super::*;

use std::{str::FromStr, collections::BTreeMap};
use frame_support::{
	assert_ok, impl_outer_origin, parameter_types, impl_outer_dispatch
};
use sp_core::{Blake2Hasher, H256};
use sp_runtime::{
	Perbill,
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
// use frame_system::Origin;

impl_outer_origin! {
	pub enum Origin for Test where system = frame_system {}
}

impl_outer_dispatch! {
	pub enum OuterCall for Test where origin: Origin {
		self::EVM,
	}
}

#[derive(Clone, Eq, PartialEq)]
pub struct Test;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}
impl frame_system::Trait for Test {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Call = OuterCall;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId32;
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
	type PalletInfo = ();
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}
impl pallet_balances::Trait for Test {
	type MaxLocks = ();
	type Balance = u64;
	type DustRemoval = ();
	type Event = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
}

parameter_types! {
	pub const MinimumPeriod: u64 = 1000;
}
impl pallet_timestamp::Trait for Test {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

/// Fixed gas price of `0`.
pub struct FixedGasPrice;
impl FeeCalculator for FixedGasPrice {
	fn min_gas_price() -> U256 {
		// Gas price is always one token per gas.
		0.into()
	}
}

impl Trait for Test {
	type FeeCalculator = FixedGasPrice;

	type CallOrigin = EnsureAddressRoot<Self::AccountId>;
	type WithdrawOrigin = EnsureAddressTruncated;

	type AddressMapping = HashedAddressMapping<Blake2Hasher>;
	type Currency = Balances;

	type Event = Event<Test>;
	type Precompiles = ();
	type ChainId = SystemChainId;
}

type System = frame_system::Module<Test>;
type Balances = pallet_balances::Module<Test>;
type EVM = Module<Test>;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	let mut accounts = BTreeMap::new();
	accounts.insert(
		H160::from_str("1000000000000000000000000000000000000001").unwrap(),
		GenesisAccount {
			nonce: U256::from(1),
			balance: U256::from(1000000),
			storage: Default::default(),
			code: vec![
				0x00, // STOP
			],
		}
	);
	accounts.insert(
		H160::from_str("1000000000000000000000000000000000000002").unwrap(),
		GenesisAccount {
			nonce: U256::from(1),
			balance: U256::from(1000000),
			storage: Default::default(),
			code: vec![
				0xff, // INVALID
			],
		}
	);

	pallet_balances::GenesisConfig::<Test>::default().assimilate_storage(&mut t).unwrap();
	GenesisConfig { accounts }.assimilate_storage::<Test>(&mut t).unwrap();
	t.into()
}

#[test]
fn fail_call_return_ok() {
	new_test_ext().execute_with(|| {
		assert_ok!(EVM::call(
			Origin::root(),
			H160::default(),
			H160::from_str("1000000000000000000000000000000000000001").unwrap(),
			Vec::new(),
			U256::default(),
			1000000,
			U256::default(),
			None,
		));

		assert_ok!(EVM::call(
			Origin::root(),
			H160::default(),
			H160::from_str("1000000000000000000000000000000000000002").unwrap(),
			Vec::new(),
			U256::default(),
			1000000,
			U256::default(),
			None,
		));
	});
}

#[test]
fn mutate_account_works() {
	new_test_ext().execute_with(|| {
		EVM::mutate_account_basic(
			&H160::from_str("1000000000000000000000000000000000000001").unwrap(),
			Account {
				nonce: U256::from(10),
				balance: U256::from(1000),
			},
		);

		assert_eq!(EVM::account_basic(
			&H160::from_str("1000000000000000000000000000000000000001").unwrap()
		), Account {
			nonce: U256::from(10),
			balance: U256::from(1000),
		});
	});
}

#[test]
fn deposit_withdraw_works() {
	new_test_ext().execute_with(|| {
		let (acc_1_h160, acc_1_evm, acc_1) = {
			let mut a = [0u8; 32];
			a.copy_from_slice(b"10000000000000000000000000000000");
			let mut h = [0u8; 20];
			h.copy_from_slice(&a[0..20]);
			let h: H160 = h.into();
			let e = <Test as Trait>::AddressMapping::into_account_id(h.clone());
			(h, e, a.into())
		};
		let (acc_2_h160, acc_2_evm, acc_2) = {
			let mut a = [0u8; 32];
			a.copy_from_slice(b"20000000000000000000000000000000");
			let mut h = [0u8; 20];
			h.copy_from_slice(&a[0..20]);
			let h: H160 = h.into();
			let e = <Test as Trait>::AddressMapping::into_account_id(h.clone());
			(h, e, a.into())
		};
		let _ = <Test as Trait>::Currency::deposit_creating(&acc_1, 1000);
		let _ = <Test as Trait>::Currency::deposit_creating(&acc_2, 2000);

		assert!(EVM::deposit(Origin::signed(acc_1.clone()), acc_2_h160, 10).is_err());
		assert_ok!(EVM::deposit(Origin::signed(acc_1.clone()), acc_1_h160, 10));

		assert!(EVM::deposit(Origin::signed(acc_2.clone()), acc_1_h160, 30).is_err());
		assert_ok!(EVM::deposit(Origin::signed(acc_2.clone()), acc_2_h160, 30));

		assert_eq!(Balances::free_balance(acc_1_evm.clone()), 10);
		assert_eq!(Balances::free_balance(acc_2_evm.clone()), 30);

		assert_eq!(Balances::free_balance(acc_1.clone()), 990);
		assert_eq!(Balances::free_balance(acc_2.clone()), 1970);

		assert!(EVM::withdraw(Origin::signed(acc_1.clone()), acc_1_h160, 15).is_err());
		assert!(EVM::withdraw(Origin::signed(acc_1.clone()), acc_2_h160, 10).is_err());
		assert_ok!(EVM::withdraw(Origin::signed(acc_1.clone()), acc_1_h160, 10));

		assert!(EVM::withdraw(Origin::signed(acc_2.clone()), acc_2_h160, 50).is_err());
		assert!(EVM::withdraw(Origin::signed(acc_2.clone()), acc_1_h160, 10).is_err());
		assert_ok!(EVM::withdraw(Origin::signed(acc_2.clone()), acc_2_h160, 30));

		assert_eq!(Balances::free_balance(acc_1_evm.clone()), 0);
		assert_eq!(Balances::free_balance(acc_2_evm.clone()), 0);

		assert_eq!(Balances::free_balance(acc_1.clone()), 1000);
		assert_eq!(Balances::free_balance(acc_2.clone()), 2000);
	})
}