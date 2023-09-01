use crate as token_migration;

use super::*;

use super::Call as MigrateCall;
use frame_support::{
    assert_err, assert_ok, parameter_types,
    sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, ConvertInto, IdentityLookup, SaturatedConversion},
        Perbill,
    },
    weights::{constants::WEIGHT_PER_SECOND, DispatchClass, DispatchInfo, Weight},
};
use frame_system::{self as system, RawOrigin};
use sp_core::H256;
use std::cell::RefCell;

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
        MigrationModule: token_migration::{Pallet, Call, Storage, Event<T>},
    }
);

type Balance = u64;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = WEIGHT_PER_SECOND.saturating_mul(2);
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const TransactionByteFee: Balance = 1;
}

impl system::Config for TestRuntime {
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<10>;
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
    type DbWeight = ();
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
    type MaxReserves = ();
    type ReserveIdentifier = ();
}

thread_local! {
    static VESTING_MILESTONES: RefCell<u8> = RefCell::new(3);
    static VESTING_DURATION: RefCell<u32> = RefCell::new(5270400);
}

pub struct VestingMilestones;

impl Get<u8> for VestingMilestones {
    fn get() -> u8 {
        VESTING_MILESTONES.with(|v| *v.borrow())
    }
}

pub struct VestingDuration;

// For testing only
impl VestingDuration {
    fn set(value: u32) {
        VESTING_DURATION.with(|v| v.replace(value));
    }
}

impl Get<u32> for VestingDuration {
    fn get() -> u32 {
        VESTING_DURATION.with(|v| *v.borrow())
    }
}

impl Config for TestRuntime {
    type Event = ();
    type Currency = balances::Pallet<Self>;
    type BlockNumberToBalance = ConvertInto;
    type VestingMilestones = VestingMilestones;
    type VestingDuration = VestingDuration;
}

fn new_test_ext() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<TestRuntime>()
        .unwrap()
        .into()
}

#[test]
fn add_migrator() {
    new_test_ext().execute_with(|| {
        let acc_1 = 1;

        // Non root cannot add
        assert!(MigrationModule::add_migrator(RawOrigin::Signed(100).into(), acc_1, 30).is_err());

        assert_ok!(MigrationModule::add_migrator(
            RawOrigin::Root.into(),
            acc_1,
            30
        ));
        assert_err!(
            MigrationModule::add_migrator(RawOrigin::Root.into(), acc_1, 30),
            Error::<TestRuntime>::MigratorAlreadyPresent
        );
        assert_eq!(MigrationModule::migrators(&acc_1).unwrap(), 30);
    })
}

#[test]
fn remove_migrator() {
    new_test_ext().execute_with(|| {
        let acc_1 = 1;
        assert_err!(
            MigrationModule::remove_migrator(RawOrigin::Root.into(), acc_1),
            Error::<TestRuntime>::UnknownMigrator
        );
        MigrationModule::add_migrator(RawOrigin::Root.into(), acc_1, 30).unwrap();

        // Non root cannot remove
        assert!(MigrationModule::remove_migrator(RawOrigin::Signed(100).into(), acc_1).is_err());

        assert_ok!(MigrationModule::remove_migrator(
            RawOrigin::Root.into(),
            acc_1
        ));
    });
}

#[test]
fn expand_migrator() {
    new_test_ext().execute_with(|| {
        let acc_1 = 1;
        assert_err!(
            MigrationModule::expand_migrator(RawOrigin::Root.into(), acc_1, 10),
            Error::<TestRuntime>::UnknownMigrator
        );
        MigrationModule::add_migrator(RawOrigin::Root.into(), acc_1, 10).unwrap();

        // Non root cannot expand
        assert!(
            MigrationModule::expand_migrator(RawOrigin::Signed(100).into(), acc_1, 35).is_err()
        );

        assert_ok!(MigrationModule::expand_migrator(
            RawOrigin::Root.into(),
            acc_1,
            35
        ));
        assert_eq!(MigrationModule::migrators(&acc_1).unwrap(), 45);
        // Overflow check
        assert_err!(
            MigrationModule::expand_migrator(RawOrigin::Root.into(), acc_1, 65500),
            Error::<TestRuntime>::CannotExpandMigrator
        );
    });
}

#[test]
fn contract_migrator() {
    new_test_ext().execute_with(|| {
        let acc_1 = 1;
        assert_err!(
            MigrationModule::contract_migrator(RawOrigin::Root.into(), acc_1, 10),
            Error::<TestRuntime>::UnknownMigrator
        );
        MigrationModule::add_migrator(RawOrigin::Root.into(), acc_1, 10).unwrap();

        // Non root cannot contract
        assert!(
            MigrationModule::contract_migrator(RawOrigin::Signed(100).into(), acc_1, 35).is_err()
        );

        assert_ok!(MigrationModule::contract_migrator(
            RawOrigin::Root.into(),
            acc_1,
            5
        ));
        assert_eq!(MigrationModule::migrators(&acc_1).unwrap(), 5);
        // Underflow check
        assert_err!(
            MigrationModule::contract_migrator(RawOrigin::Root.into(), acc_1, 6),
            Error::<TestRuntime>::CannotContractMigrator
        );
    });
}

#[test]
fn migrate() {
    new_test_ext().execute_with(|| {
        let recip_acc_1 = 1;
        let recip_acc_2 = 2;
        let recip_acc_3 = 3;
        let recip_acc_4 = 4;
        let recip_acc_5 = 5;
        let migrator_acc = 10;

        let _ = <TestRuntime as Config>::Currency::deposit_creating(&migrator_acc, 100);
        MigrationModule::add_migrator(RawOrigin::Root.into(), migrator_acc, 4).unwrap();

        // No of recipients more than allowed migrations
        let mut recips_1 = BTreeMap::new();
        recips_1.insert(recip_acc_1, 10);
        recips_1.insert(recip_acc_2, 1);
        recips_1.insert(recip_acc_3, 50);
        recips_1.insert(recip_acc_4, 30);
        recips_1.insert(recip_acc_5, 2);
        assert_err!(
            MigrationModule::migrate(RawOrigin::Signed(migrator_acc).into(), recips_1),
            Error::<TestRuntime>::ExceededMigrations
        );
        assert_eq!(MigrationModule::migrators(&migrator_acc).unwrap(), 4);

        let mut recips_2 = BTreeMap::new();
        recips_2.insert(recip_acc_1, 10);
        recips_2.insert(recip_acc_2, 1);
        assert_ok!(MigrationModule::migrate(
            RawOrigin::Signed(migrator_acc).into(),
            recips_2
        ));
        assert_eq!(MigrationModule::migrators(&migrator_acc).unwrap(), 2);
        assert_eq!(
            <TestRuntime as Config>::Currency::free_balance(&migrator_acc).saturated_into::<u64>(),
            89
        );

        // Insufficient balance of migrator
        let mut recips_3 = BTreeMap::new();
        recips_3.insert(recip_acc_1, 85);
        recips_3.insert(recip_acc_2, 5);
        assert!(
            MigrationModule::migrate(RawOrigin::Signed(migrator_acc).into(), recips_3).is_err()
        );
        assert_eq!(MigrationModule::migrators(&migrator_acc).unwrap(), 2);
        assert_eq!(
            <TestRuntime as Config>::Currency::free_balance(&migrator_acc).saturated_into::<u64>(),
            89
        );

        let mut recips_4 = BTreeMap::new();
        recips_4.insert(recip_acc_1, 85);
        recips_4.insert(recip_acc_2, 4);
        assert_ok!(MigrationModule::migrate(
            RawOrigin::Signed(migrator_acc).into(),
            recips_4
        ));
        assert_eq!(MigrationModule::migrators(&migrator_acc).unwrap(), 0);
        assert_eq!(
            <TestRuntime as Config>::Currency::free_balance(&migrator_acc).saturated_into::<u64>(),
            0
        );

        // TODO: Check for overflow as well
    });
}

#[test]
fn signed_extension_test() {
    // Check that the signed extension `OnlyMigrator` only allows registered migrator
    new_test_ext().execute_with(|| {
        // Migrators
        let migrator_acc_1 = 1;
        let migrator_acc_2 = 2;
        let migrator_acc_3 = 3;

        // Register migrators and fuel them
        let _ = <TestRuntime as Config>::Currency::deposit_creating(&migrator_acc_1, 100);
        let _ = <TestRuntime as Config>::Currency::deposit_creating(&migrator_acc_2, 90);
        MigrationModule::add_migrator(RawOrigin::Root.into(), migrator_acc_1, 4).unwrap();
        MigrationModule::add_migrator(RawOrigin::Root.into(), migrator_acc_2, 5).unwrap();

        let signed_extension = OnlyMigrator::<TestRuntime>(PhantomData);

        // The call made by migrator. The recipients being empty is irrelevant for this test.
        let call_1: <TestRuntime as system::Config>::Call =
            Call::MigrationModule(MigrateCall::migrate {
                recipients: BTreeMap::new(),
            });
        // The call made by migrator. The bonus vectors being empty is irrelevant for this test.
        let call_2: <TestRuntime as system::Config>::Call =
            Call::MigrationModule(MigrateCall::give_bonuses {
                swap_bonus_recips: Vec::new(),
                vesting_bonus_recips: Vec::new(),
            });

        let tx_info = DispatchInfo {
            weight: Weight::from_ref_time(3),
            class: DispatchClass::Normal,
            pays_fee: Pays::No,
        };

        // Registered migrators should pass signed extension
        for call in [&call_1, &call_2].iter() {
            assert!(signed_extension
                .validate(&migrator_acc_1, call, &tx_info, 20)
                .is_ok());
            assert!(signed_extension
                .validate(&migrator_acc_2, call, &tx_info, 20)
                .is_ok());
        }

        // Unregistered migrator should not pass signed extension
        for call in [&call_1, &call_2].iter() {
            assert!(signed_extension
                .validate(&migrator_acc_3, call, &tx_info, 20)
                .is_err());
        }

        MigrationModule::add_migrator(RawOrigin::Root.into(), migrator_acc_3, 6).unwrap();

        // Call from a previously unregistered but currently registered migrator
        for call in [&call_1, &call_2].iter() {
            assert!(signed_extension
                .validate(&migrator_acc_3, call, &tx_info, 20)
                .is_ok());
        }

        assert_ok!(MigrationModule::remove_migrator(
            RawOrigin::Root.into(),
            migrator_acc_1
        ));

        // Call from a previously registered but currently unregistered migrator
        for call in [&call_1, &call_2].iter() {
            assert!(signed_extension
                .validate(&migrator_acc_1, call, &tx_info, 20)
                .is_err());
        }
    });
}

#[test]
fn give_bonuses() {
    // Check bonus
    new_test_ext().execute_with(|| {
        let recip_1 = 1;
        let recip_2 = 2;
        let recip_3 = 3;
        let recip_4 = 4;
        let recip_5 = 5;
        let recip_6 = 6;

        let sender_1 = 10;
        let sender_2 = 11;

        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender_1, 1000);
        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender_2, 100);
        MigrationModule::add_migrator(RawOrigin::Root.into(), sender_1, 30).unwrap();
        MigrationModule::add_migrator(RawOrigin::Root.into(), sender_2, 5).unwrap();

        let recip_1_bal_1 = Balances::free_balance(&recip_1);
        let recip_2_bal_1 = Balances::free_balance(&recip_2);
        let recip_3_bal_1 = Balances::free_balance(&recip_3);

        // Cannot give bonuses beyond migration limit
        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![
                    (recip_1, 2, 5),
                    (recip_2, 4, 0),
                    (recip_3, 5, 1),
                    (recip_4, 1, 10),
                    (recip_5, 5, 20),
                    (recip_6, 3, 0)
                ],
                vec![]
            ),
            Error::<TestRuntime>::ExceededMigrations
        );
        assert_eq!(MigrationModule::migrators(&sender_2).unwrap(), 5);
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        // Cannot give bonuses beyond migration limit even with repeated accounts
        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![
                    (recip_1, 2, 5),
                    (recip_1, 4, 0),
                    (recip_1, 5, 1),
                    (recip_2, 1, 10),
                    (recip_2, 5, 20),
                    (recip_3, 3, 0)
                ],
                vec![]
            ),
            Error::<TestRuntime>::ExceededMigrations
        );
        assert_eq!(MigrationModule::migrators(&sender_2).unwrap(), 5);
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        // Cannot give bonuses beyond migration limit even with accounts divided between vesting and swap
        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![(recip_1, 2, 5), (recip_2, 4, 0), (recip_3, 5, 1)],
                vec![(recip_4, 1, 10), (recip_5, 5, 20), (recip_6, 3, 0)]
            ),
            Error::<TestRuntime>::ExceededMigrations
        );
        assert_eq!(MigrationModule::migrators(&sender_2).unwrap(), 5);
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        // Cannot give bonuses beyond balance
        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![(recip_1, 20, 5), (recip_2, 45, 0), (recip_3, 50, 1)],
                vec![]
            ),
            Error::<TestRuntime>::InsufficientBalance
        );
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![],
                vec![(recip_1, 20, 5), (recip_2, 45, 0), (recip_3, 50, 1)]
            ),
            Error::<TestRuntime>::InsufficientBalance
        );
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        assert_err!(
            MigrationModule::give_bonuses(
                RawOrigin::Signed(sender_2).into(),
                vec![(recip_1, 20, 5), (recip_2, 45, 0)],
                vec![(recip_3, 50, 1)]
            ),
            Error::<TestRuntime>::InsufficientBalance
        );
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        // No entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert!(MigrationModule::bonus(&recip_2).is_none());

        MigrationModule::give_bonuses(
            RawOrigin::Signed(sender_2).into(),
            vec![(recip_1, 10, 5), (recip_1, 5, 7), (recip_2, 25, 1)],
            vec![(recip_2, 20, 2)],
        )
        .unwrap();

        // Entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_some());
        assert!(MigrationModule::bonus(&recip_2).is_some());

        // Free balance changes as bonus credited
        assert_eq!(15, Balances::reserved_balance(&recip_1));
        assert_eq!(45, Balances::reserved_balance(&recip_2));

        // Free balance does not change as bonus credited but reserved
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        // Migrator's free balance changed as well
        assert_eq!(Balances::free_balance(&sender_2), 40);
        // Did 4 migrations
        assert_eq!(MigrationModule::migrators(&sender_2).unwrap(), 1);

        // Both swap and vesting bonuses should unlock at the correct block number
        System::set_block_number(1);
        MigrationModule::claim_bonus(RawOrigin::Signed(recip_2).into()).unwrap();
        // Entry in storage exists until some unclaimed bonus exists
        assert!(MigrationModule::bonus(&recip_2).is_some());
        assert_eq!(recip_2_bal_1 + 25, Balances::free_balance(&recip_2));

        assert!(MigrationModule::claim_bonus(RawOrigin::Signed(recip_2).into()).is_err());

        System::set_block_number(5);
        MigrationModule::claim_bonus(RawOrigin::Signed(recip_1).into()).unwrap();
        // Entry in storage exists until some unclaimed bonus exists
        assert!(MigrationModule::bonus(&recip_1).is_some());
        assert_eq!(recip_1_bal_1 + 10, Balances::free_balance(&recip_1));

        System::set_block_number(7);
        MigrationModule::claim_bonus(RawOrigin::Signed(recip_1).into()).unwrap();
        // Entry in storage is removed when all bonus is claimed bonus
        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert_eq!(recip_1_bal_1 + 10 + 5, Balances::free_balance(&recip_1));

        assert!(MigrationModule::claim_bonus(RawOrigin::Signed(recip_1).into()).is_err());
    });
}

#[test]
fn swap_bonus_claims() {
    // Check swap bonus
    new_test_ext().execute_with(|| {
        let recip_1 = 1;
        let recip_2 = 2;
        let recip_3 = 3;

        let sender_1 = 10;
        let sender_2 = 11;

        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender_1, 10000);
        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender_2, 10000);

        assert_eq!(System::block_number(), 0);

        let recip_1_bal_1 = Balances::free_balance(&recip_1);

        let amount_1 = 5;
        let unlock_1 = 10;

        // No entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_none());

        MigrationModule::add_swap_bonus(sender_1, recip_1, amount_1, unlock_1).unwrap();

        // Entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_some());
        // Swap bonuses vector is not empty
        assert_eq!(
            MigrationModule::bonus(&recip_1).unwrap().swap_bonuses.len(),
            1
        );
        // Vesting bonuses vector is empty
        assert!(MigrationModule::bonus(&recip_1)
            .unwrap()
            .vesting_bonuses
            .is_empty());
        // Adding bonus does not change free balance
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));

        System::set_block_number(unlock_1 - 1);
        assert!(MigrationModule::unlock_swap_bonus(recip_1).is_err());
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));

        System::set_block_number(unlock_1);
        assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));

        MigrationModule::unlock_swap_bonus(recip_1).unwrap();
        // Entry removed from storage
        assert!(MigrationModule::bonus(&recip_1).is_none());
        let recip_1_bal_2 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_1 + amount_1, recip_1_bal_2);
        assert!(MigrationModule::unlock_swap_bonus(recip_1).is_err());
        let recip_2_bal_1 = Balances::free_balance(&recip_2);
        let recip_3_bal_1 = Balances::free_balance(&recip_3);

        // No entry in storage
        assert!(MigrationModule::bonus(&recip_2).is_none());
        assert!(MigrationModule::bonus(&recip_2).is_none());

        let amount_2 = 10;
        let unlock_2 = 20;
        let unlock_3 = 30;
        MigrationModule::add_swap_bonus(sender_1, recip_2, amount_2, unlock_2).unwrap();
        MigrationModule::add_swap_bonus(sender_1, recip_3, amount_2, unlock_2).unwrap();
        MigrationModule::add_swap_bonus(sender_2, recip_2, amount_2, unlock_3).unwrap();
        MigrationModule::add_swap_bonus(sender_2, recip_3, amount_2, unlock_3).unwrap();

        // Entry in storage
        assert!(MigrationModule::bonus(&recip_2).is_some());
        assert!(MigrationModule::bonus(&recip_3).is_some());
        // Swap bonuses vector is not empty, 2 entries
        assert_eq!(
            MigrationModule::bonus(&recip_2).unwrap().swap_bonuses.len(),
            2
        );
        assert_eq!(
            MigrationModule::bonus(&recip_3).unwrap().swap_bonuses.len(),
            2
        );
        // Vesting bonuses vector is empty
        assert!(MigrationModule::bonus(&recip_2)
            .unwrap()
            .vesting_bonuses
            .is_empty());
        assert!(MigrationModule::bonus(&recip_3)
            .unwrap()
            .vesting_bonuses
            .is_empty());
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        System::set_block_number(unlock_2 - 1);
        assert!(MigrationModule::unlock_swap_bonus(recip_2).is_err());
        assert!(MigrationModule::unlock_swap_bonus(recip_3).is_err());
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_1, Balances::free_balance(&recip_3));

        System::set_block_number(unlock_2);
        MigrationModule::unlock_swap_bonus(recip_2).unwrap();
        MigrationModule::unlock_swap_bonus(recip_3).unwrap();

        // Swap bonuses vector has only 1 entry now as 1 bonus is already claimed
        assert_eq!(
            MigrationModule::bonus(&recip_2).unwrap().swap_bonuses.len(),
            1
        );
        assert_eq!(
            MigrationModule::bonus(&recip_3).unwrap().swap_bonuses.len(),
            1
        );
        let recip_2_bal_2 = Balances::free_balance(&recip_2);
        let recip_3_bal_2 = Balances::free_balance(&recip_3);
        assert_eq!(recip_2_bal_1 + amount_2, recip_2_bal_2);
        assert_eq!(recip_3_bal_1 + amount_2, recip_3_bal_2);

        assert!(MigrationModule::unlock_swap_bonus(recip_2).is_err());
        assert!(MigrationModule::unlock_swap_bonus(recip_3).is_err());

        System::set_block_number(unlock_3 - 1);
        assert!(MigrationModule::unlock_swap_bonus(recip_2).is_err());
        assert!(MigrationModule::unlock_swap_bonus(recip_3).is_err());
        assert_eq!(recip_2_bal_2, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_2, Balances::free_balance(&recip_3));

        System::set_block_number(unlock_3);
        MigrationModule::unlock_swap_bonus(recip_2).unwrap();
        MigrationModule::unlock_swap_bonus(recip_3).unwrap();
        // Entry removed from storage as swap bonuses claimed
        assert!(MigrationModule::bonus(&recip_2).is_none());
        assert!(MigrationModule::bonus(&recip_3).is_none());
        assert_eq!(recip_2_bal_2 + amount_2, Balances::free_balance(&recip_2));
        assert_eq!(recip_3_bal_2 + amount_2, Balances::free_balance(&recip_3));
        assert!(MigrationModule::unlock_swap_bonus(recip_2).is_err());
        assert!(MigrationModule::unlock_swap_bonus(recip_3).is_err());

        let amount_3 = 10;
        let unlock_4 = 20;
        MigrationModule::add_swap_bonus(sender_1, recip_1, amount_3, unlock_4).unwrap();
        MigrationModule::add_swap_bonus(sender_1, recip_1, amount_3, unlock_4).unwrap();
        MigrationModule::add_swap_bonus(sender_1, recip_1, amount_3, unlock_4).unwrap();

        // 3 entries for swap bonus
        assert_eq!(
            MigrationModule::bonus(&recip_1).unwrap().swap_bonuses.len(),
            3
        );

        System::set_block_number(unlock_4 - 1);
        assert!(MigrationModule::unlock_swap_bonus(recip_1).is_err());
        assert_eq!(recip_1_bal_2, Balances::free_balance(&recip_1));

        System::set_block_number(unlock_4);
        MigrationModule::unlock_swap_bonus(recip_1).unwrap();

        // Storage cleared as all swap bonuses claimed
        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert_eq!(
            recip_1_bal_2 + 3 * amount_3,
            Balances::free_balance(&recip_1)
        );
        assert!(MigrationModule::unlock_swap_bonus(recip_1).is_err());
    });
}

#[test]
fn vesting_bonus_claims_1() {
    // Check vesting bonus. Bonus duration divides milestone count exactly and no start offset
    new_test_ext().execute_with(|| {
        let recip = 1;
        let sender = 10;
        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender, 10000);

        assert_eq!(System::block_number(), 0);

        let recip_bal_1 = Balances::free_balance(&recip);

        // No entry in storage
        assert!(MigrationModule::bonus(&recip).is_none());

        let amount_1 = 15;
        // Override for testing
        <TestRuntime as Config>::VestingDuration::set(300);
        MigrationModule::add_vesting_bonus(sender, recip, amount_1, 101).unwrap();

        // Entry in storage
        assert!(MigrationModule::bonus(&recip).is_some());
        // Swap bonuses vector is empty
        assert!(MigrationModule::bonus(&recip)
            .unwrap()
            .swap_bonuses
            .is_empty());

        // Vesting bonuses vector not is empty
        assert_eq!(
            MigrationModule::bonus(&recip)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        // Cannot claim before vesting starts
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_1, Balances::free_balance(&recip));
        assert_eq!(amount_1, Balances::reserved_balance(&recip));

        // Cannot claim even 1 block before milestone
        System::set_block_number(199);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_1, Balances::free_balance(&recip));

        // Can claim at milestone
        System::set_block_number(200);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_2 = Balances::free_balance(&recip);
        assert_eq!(
            recip_bal_1 + (amount_1 / <TestRuntime as Config>::VestingMilestones::get() as u64),
            recip_bal_2
        );
        // Vesting bonuses vector is still not empty as vesting isn't complete
        assert_eq!(
            MigrationModule::bonus(&recip)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        // Cannot claim even 1 block before milestone
        System::set_block_number(299);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_2, Balances::free_balance(&recip));

        // Can claim at milestone
        System::set_block_number(300);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_3 = Balances::free_balance(&recip);
        assert_eq!(
            recip_bal_2 + (amount_1 / <TestRuntime as Config>::VestingMilestones::get() as u64),
            recip_bal_3
        );
        // Vesting bonuses vector is still not empty as vesting isn't complete
        assert_eq!(
            MigrationModule::bonus(&recip)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        System::set_block_number(301);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_3, Balances::free_balance(&recip));

        // Cannot claim before milestone
        System::set_block_number(305);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_3, Balances::free_balance(&recip));

        // Cannot claim before milestone
        System::set_block_number(399);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_3, Balances::free_balance(&recip));

        // Can claim at milestone
        System::set_block_number(400);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_4 = Balances::free_balance(&recip);
        assert_eq!(
            recip_bal_3 + (amount_1 / <TestRuntime as Config>::VestingMilestones::get() as u64),
            recip_bal_4
        );
        assert_eq!(recip_bal_1 + amount_1, recip_bal_4);

        // Entry removed from storage as vesting is complete
        assert!(MigrationModule::bonus(&recip).is_none());

        // Cannot claim after all bonus given
        System::set_block_number(500);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_4, Balances::free_balance(&recip));

        System::set_block_number(600);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_4, Balances::free_balance(&recip));

        // Test vesting all at once
        let amount_2 = 100;
        // Override for testing
        <TestRuntime as Config>::VestingDuration::set(300);
        MigrationModule::add_vesting_bonus(sender, recip, amount_2, 601).unwrap();

        assert_eq!(
            MigrationModule::bonus(&recip)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        System::set_block_number(605);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_4, Balances::free_balance(&recip));

        // Claim all bonus at once
        System::set_block_number(900);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_5 = Balances::free_balance(&recip);
        assert_eq!(recip_bal_4 + amount_2, recip_bal_5);

        // Entry removed from storage as vesting is complete
        assert!(MigrationModule::bonus(&recip).is_none());

        // Test vesting few blocks after milestone

        let amount_3 = 60;
        MigrationModule::add_vesting_bonus(sender, recip, amount_3, 1001).unwrap();

        System::set_block_number(1005);
        assert!(MigrationModule::unlock_vesting_bonus(recip).is_err());
        assert_eq!(recip_bal_5, Balances::free_balance(&recip));

        // Can claim few blocks after milestone
        System::set_block_number(1103);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_6 = Balances::free_balance(&recip);
        assert_eq!(
            recip_bal_5 + (amount_3 / <TestRuntime as Config>::VestingMilestones::get() as u64),
            recip_bal_6
        );

        // Can claim few blocks after milestone
        System::set_block_number(1302);
        MigrationModule::unlock_vesting_bonus(recip).unwrap();
        let recip_bal_7 = Balances::free_balance(&recip);
        assert_eq!(recip_bal_5 + amount_3, recip_bal_7);
    });
}

#[test]
fn vesting_bonus_claims_2() {
    // Check vesting bonus. Bonus duration does not divide milestone count exactly and with and without
    // start offset
    new_test_ext().execute_with(|| {
        let recip_1 = 1;
        let recip_2 = 2;

        let sender = 10;

        let _ = <TestRuntime as Config>::Currency::deposit_creating(&sender, 10000);

        // Amount divides milestone count exactly
        for amount in [15, 20] {
            System::set_block_number(0);

            let start = 1;
            let end = 100;
            let milestone_1 = 33;
            let milestone_2 = 66;
            let milestone_3 = 99;
            // Override for testing
            <TestRuntime as Config>::VestingDuration::set(end - start + 1);

            let recip_1_bal_1 = Balances::free_balance(&recip_1);
            let recip_2_bal_1 = Balances::free_balance(&recip_2);

            let offset = 5;
            MigrationModule::add_vesting_bonus(sender, recip_1, amount, start as u64).unwrap();
            MigrationModule::add_vesting_bonus(sender, recip_2, amount, (start + offset) as u64)
                .unwrap();

            System::set_block_number(milestone_1 - 1);
            assert!(MigrationModule::unlock_vesting_bonus(recip_1).is_err());
            assert!(MigrationModule::unlock_vesting_bonus(recip_2).is_err());
            assert_eq!(recip_1_bal_1, Balances::free_balance(&recip_1));
            assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));

            System::set_block_number(milestone_1);
            MigrationModule::unlock_vesting_bonus(recip_1).unwrap();
            let recip_1_bal_2 = Balances::free_balance(&recip_1);
            assert_eq!(
                recip_1_bal_1 + (amount / <TestRuntime as Config>::VestingMilestones::get() as u64),
                recip_1_bal_2
            );
            assert!(MigrationModule::unlock_vesting_bonus(recip_2).is_err());
            assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));

            System::set_block_number(milestone_1 + offset as u64);
            MigrationModule::unlock_vesting_bonus(recip_2).unwrap();
            let recip_2_bal_2 = Balances::free_balance(&recip_2);
            assert_eq!(
                recip_2_bal_1 + (amount / <TestRuntime as Config>::VestingMilestones::get() as u64),
                recip_2_bal_2
            );
            assert!(MigrationModule::unlock_vesting_bonus(recip_1).is_err());
            assert_eq!(recip_1_bal_2, Balances::free_balance(&recip_1));

            System::set_block_number(milestone_2 - 1);
            assert!(MigrationModule::unlock_vesting_bonus(recip_1).is_err());
            assert!(MigrationModule::unlock_vesting_bonus(recip_2).is_err());
            assert_eq!(recip_1_bal_2, Balances::free_balance(&recip_1));
            assert_eq!(recip_2_bal_2, Balances::free_balance(&recip_2));

            System::set_block_number(milestone_2);
            MigrationModule::unlock_vesting_bonus(recip_1).unwrap();
            let recip_1_bal_3 = Balances::free_balance(&recip_1);
            assert_eq!(
                recip_1_bal_2 + (amount / <TestRuntime as Config>::VestingMilestones::get() as u64),
                recip_1_bal_3
            );
            assert!(MigrationModule::unlock_vesting_bonus(recip_2).is_err());
            assert_eq!(recip_2_bal_2, Balances::free_balance(&recip_2));

            System::set_block_number(milestone_2 + offset as u64);
            MigrationModule::unlock_vesting_bonus(recip_2).unwrap();
            let recip_2_bal_3 = Balances::free_balance(&recip_2);
            assert_eq!(
                recip_2_bal_2 + (amount / <TestRuntime as Config>::VestingMilestones::get() as u64),
                recip_2_bal_3
            );
            assert!(MigrationModule::unlock_vesting_bonus(recip_1).is_err());
            assert_eq!(recip_1_bal_3, Balances::free_balance(&recip_1));

            // All the bonus should credit by last milestone
            System::set_block_number(milestone_3);
            MigrationModule::unlock_vesting_bonus(recip_1).unwrap();
            let recip_1_bal_4 = Balances::free_balance(&recip_1);
            assert_eq!(recip_1_bal_1 + amount, recip_1_bal_4);
            assert!(MigrationModule::unlock_vesting_bonus(recip_2).is_err());
            assert_eq!(recip_2_bal_3, Balances::free_balance(&recip_2));

            System::set_block_number(milestone_3 + offset as u64);
            MigrationModule::unlock_vesting_bonus(recip_2).unwrap();
            let recip_2_bal_4 = Balances::free_balance(&recip_2);
            assert_eq!(recip_2_bal_1 + amount, recip_2_bal_4);
            assert!(MigrationModule::unlock_vesting_bonus(recip_1).is_err());
            assert_eq!(recip_1_bal_4, Balances::free_balance(&recip_1));
        }
    });
}

#[test]
fn bonus_claim_extrinsics() {
    new_test_ext().execute_with(|| {
        let recip_1 = 1;
        let recip_2 = 2;

        let migrator = 10;

        let _ = <TestRuntime as Config>::Currency::deposit_creating(&migrator, 10000);

        assert_eq!(System::block_number(), 0);

        // Override for testing
        <TestRuntime as Config>::VestingDuration::set(100);

        let recip_1_bal_1 = Balances::free_balance(&recip_1);
        let recip_2_bal_1 = Balances::free_balance(&recip_2);

        MigrationModule::add_migrator(RawOrigin::Root.into(), migrator, 100).unwrap();

        // No entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert!(MigrationModule::bonus(&recip_2).is_none());

        MigrationModule::give_bonuses(
            RawOrigin::Signed(migrator).into(),
            vec![(recip_1, 10, 0), (recip_2, 40, 10)],
            vec![],
        )
        .unwrap();

        // Entry in storage
        assert!(MigrationModule::bonus(&recip_1).is_some());
        assert!(MigrationModule::bonus(&recip_2).is_some());

        MigrationModule::claim_swap_bonus(RawOrigin::Signed(recip_1).into()).unwrap();
        let recip_1_bal_2 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_1 + 10, recip_1_bal_2);

        assert!(MigrationModule::claim_swap_bonus(RawOrigin::Signed(recip_2).into()).is_err());
        assert!(MigrationModule::claim_swap_bonus_for_other(
            RawOrigin::Signed(recip_1).into(),
            recip_2
        )
        .is_err());
        assert_eq!(recip_2_bal_1, Balances::free_balance(&recip_2));
        assert_eq!(recip_1_bal_2, Balances::free_balance(&recip_1));

        System::set_block_number(10);
        MigrationModule::claim_swap_bonus_for_other(RawOrigin::Signed(recip_1).into(), recip_2)
            .unwrap();
        let recip_2_bal_2 = Balances::free_balance(&recip_2);
        assert_eq!(recip_2_bal_1 + 40, recip_2_bal_2);
        assert_eq!(recip_1_bal_2, Balances::free_balance(&recip_1));

        MigrationModule::give_bonuses(
            RawOrigin::Signed(migrator).into(),
            vec![],
            vec![(recip_1, 20, 5), (recip_2, 50, 10)],
        )
        .unwrap();
        assert!(MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_1).into()).is_err());
        assert!(MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_2).into()).is_err());
        assert!(MigrationModule::claim_vesting_bonus_for_other(
            RawOrigin::Signed(recip_1).into(),
            recip_2
        )
        .is_err());
        assert!(MigrationModule::claim_vesting_bonus_for_other(
            RawOrigin::Signed(recip_2).into(),
            recip_1
        )
        .is_err());

        System::set_block_number(12);
        assert!(MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_1).into()).is_err());
        assert!(MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_2).into()).is_err());
        assert!(MigrationModule::claim_vesting_bonus_for_other(
            RawOrigin::Signed(recip_1).into(),
            recip_2
        )
        .is_err());
        assert!(MigrationModule::claim_vesting_bonus_for_other(
            RawOrigin::Signed(recip_2).into(),
            recip_1
        )
        .is_err());

        System::set_block_number(49);
        MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_1).into()).unwrap();
        let recip_1_bal_3 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_2 + 6, recip_1_bal_3);

        System::set_block_number(53);
        MigrationModule::claim_vesting_bonus(RawOrigin::Signed(recip_2).into()).unwrap();
        let recip_2_bal_3 = Balances::free_balance(&recip_2);
        assert_eq!(recip_2_bal_2 + 16, recip_2_bal_3);

        // Claim remaining at once after bonus ends
        System::set_block_number(130);
        MigrationModule::claim_vesting_bonus_for_other(RawOrigin::Signed(recip_2).into(), recip_1)
            .unwrap();
        let recip_1_bal_4 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_3 + 14, recip_1_bal_4);
        MigrationModule::claim_vesting_bonus_for_other(RawOrigin::Signed(recip_1).into(), recip_2)
            .unwrap();
        let recip_2_bal_4 = Balances::free_balance(&recip_2);
        assert_eq!(recip_2_bal_3 + 34, recip_2_bal_4);

        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert!(MigrationModule::bonus(&recip_2).is_none());

        MigrationModule::give_bonuses(
            RawOrigin::Signed(migrator).into(),
            vec![(recip_1, 10, 5), (recip_2, 40, 10)],
            vec![(recip_1, 100, 5), (recip_2, 200, 10)],
        )
        .unwrap();
        // Bonus vectors are not empty
        assert_eq!(
            MigrationModule::bonus(&recip_1).unwrap().swap_bonuses.len(),
            1
        );
        assert_eq!(
            MigrationModule::bonus(&recip_1)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );
        assert_eq!(
            MigrationModule::bonus(&recip_2).unwrap().swap_bonuses.len(),
            1
        );
        assert_eq!(
            MigrationModule::bonus(&recip_2)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        assert!(MigrationModule::claim_bonus(RawOrigin::Signed(recip_1).into()).is_err());
        assert!(MigrationModule::claim_bonus(RawOrigin::Signed(recip_2).into()).is_err());

        System::set_block_number(140);
        MigrationModule::claim_bonus(RawOrigin::Signed(recip_2).into()).unwrap();
        let recip_2_bal_5 = Balances::free_balance(&recip_2);
        assert_eq!(recip_2_bal_4 + 40, recip_2_bal_5);
        MigrationModule::claim_bonus_for_other(RawOrigin::Signed(recip_2).into(), recip_1).unwrap();
        let recip_1_bal_5 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_4 + 10, recip_1_bal_5);

        assert!(MigrationModule::bonus(&recip_1)
            .unwrap()
            .swap_bonuses
            .is_empty());
        assert!(MigrationModule::bonus(&recip_2)
            .unwrap()
            .swap_bonuses
            .is_empty());
        assert_eq!(
            MigrationModule::bonus(&recip_1)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );
        assert_eq!(
            MigrationModule::bonus(&recip_2)
                .unwrap()
                .vesting_bonuses
                .len(),
            1
        );

        System::set_block_number(250);
        MigrationModule::claim_bonus(RawOrigin::Signed(recip_2).into()).unwrap();
        let recip_2_bal_6 = Balances::free_balance(&recip_2);
        assert_eq!(recip_2_bal_5 + 200, recip_2_bal_6);
        MigrationModule::claim_bonus_for_other(RawOrigin::Signed(recip_2).into(), recip_1).unwrap();
        let recip_1_bal_6 = Balances::free_balance(&recip_1);
        assert_eq!(recip_1_bal_5 + 100, recip_1_bal_6);

        assert!(MigrationModule::bonus(&recip_1).is_none());
        assert!(MigrationModule::bonus(&recip_2).is_none());
    });
}
