#![cfg(test)]

use super::*;

use frame_support::{
    assert_err, assert_ok, impl_outer_origin, parameter_types,
    sp_runtime::{
        testing::{Header, UintAuthorityId},
        traits::{BlakeTwo256, ConvertInto, IdentityLookup, OpaqueKeys},
        ConsensusEngineId, KeyTypeId, Perbill,
    },
    traits::FindAuthor,
    weights::{constants::WEIGHT_PER_SECOND, Weight},
};
use frame_system::{self as system, RawOrigin};
use sp_core::{crypto::key_types, H256};

impl_outer_origin! {
    pub enum Origin for TestRuntime {}
}

#[derive(Clone, Eq, Debug, PartialEq)]
pub struct TestRuntime;

type PoAModule = Module<TestRuntime>;

type System = system::Module<TestRuntime>;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 2 * WEIGHT_PER_SECOND;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const TransactionByteFee: Balance = 1;
}

impl system::Trait for TestRuntime {
    type BaseCallFilter = ();
    type Origin = Origin;
    type Call = ();
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
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
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
}

impl balances::Trait for TestRuntime {
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
}

impl Trait for TestRuntime {
    type Event = ();
    type Currency = balances::Module<Self>;
}

pub type ValidatorId = u64;

/// Dummy session handler as the pallet's trait needs the session pallet's trait
pub struct TestSessionHandler;

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

impl pallet_session::Trait for TestRuntime {
    type Event = ();
    type ValidatorId = <Self as system::Trait>::AccountId;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = PoAModule;
    type NextSessionRotation = ();
    type SessionManager = PoAModule;
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type DisabledValidatorsThreshold = ();
    type WeightInfo = ();
}

/// Dummy author as the pallet's trait needs the authorship pallet's trait
pub struct TestAuthor;

impl FindAuthor<ValidatorId> for TestAuthor {
    fn find_author<'a, I>(_digests: I) -> Option<ValidatorId>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        None
    }
}

parameter_types! {
    // Not accepting any uncles
    pub const UncleGenerations: u32 = 0;
}

impl pallet_authorship::Trait for TestRuntime {
    type FindAuthor = TestAuthor;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = ();
    type EventHandler = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = system::GenesisConfig::default()
        .build_storage::<TestRuntime>()
        .unwrap();
    GenesisConfig::<TestRuntime> {
        min_epoch_length: 25,
        max_active_validators: 4,
        // Most of them values are kept 0 as the tests below will set it.
        active_validators: vec![],
        emission_supply: 0,
        max_emm_validator_epoch: 0,
        treasury_reward_pc: 0,
        validator_reward_lock_pc: 0,
        emission_status: true,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    let ext: sp_io::TestExternalities = t.into();
    ext
}

#[test]
fn current_epoch_end() {
    new_test_ext().execute_with(|| {
        // Minimum epoch length is 25
        for (starting_slot, validator_count, ending_slot) in &[
            (1, 2, 26),
            (1, 3, 27),
            (1, 4, 28),
            (1, 5, 25),
            (1, 6, 30),
            (1, 7, 28),
            (1, 8, 32),
            (1, 9, 27),
            (1, 10, 30),
            (1, 11, 33),
            (1, 12, 36),
            (27, 2, 52),
            (28, 3, 54),
            (29, 4, 56),
            (26, 5, 50),
            (31, 6, 60),
            (29, 7, 56),
            (33, 8, 64),
            (28, 9, 54),
            (31, 10, 60),
            (34, 11, 66),
            (37, 12, 72),
            (53, 2, 78),
            (55, 3, 81),
            (57, 4, 84),
            (51, 5, 75),
            (61, 6, 90),
            (57, 7, 84),
            (65, 8, 96),
            (55, 9, 81),
            (61, 10, 90),
            (67, 11, 99),
            (73, 12, 108),
            (100, 3, 126),
            (101, 3, 127),
            (38, 3, 64),
            (60, 3, 86),
            (75, 3, 101),
            (100, 4, 127),
            (35, 4, 62),
            (81, 4, 108),
            (23, 4, 50),
            (39, 4, 66),
        ][..]
        {
            let epoch_end = PoAModule::set_next_epoch_end(*starting_slot, *validator_count);
            assert_eq!(epoch_end, *ending_slot);
            assert_eq!(PoAModule::epoch_ends_at(), epoch_end);
        }
    });
}

#[test]
fn short_circuit_epoch() {
    new_test_ext().execute_with(|| {
        // Minimum epoch length is 25
        let current_epoch_no = 1;
        Epoch::put(current_epoch_no);
        for (validator_count, starting_slot, current_slot_no, expected_epoch_end) in &[
            (2, 1, 10, 10),
            (2, 1, 9, 10),
            (2, 1, 11, 12),
            (2, 1, 23, 24),
            (3, 1, 10, 12),
            (3, 1, 8, 9),
            (3, 1, 24, 24),
            (3, 1, 25, 27),
            (3, 1, 26, 27),
            (4, 1, 8, 8),
            (4, 1, 9, 12),
            (4, 1, 11, 12),
            (4, 1, 21, 24),
            (4, 1, 25, 28),
            (5, 1, 8, 10),
            (5, 1, 11, 15),
            (5, 1, 19, 20),
            (5, 1, 20, 20),
            (5, 1, 21, 25),
        ] {
            Epochs::insert(
                current_epoch_no,
                // expected ending slot has a dummy value as its not being tested in here
                EpochDetail::new(*validator_count, *starting_slot, 0),
            );
            let epoch_end = PoAModule::update_current_epoch_end_on_short_circuit(*current_slot_no);
            assert_eq!(epoch_end, *expected_epoch_end);
            assert_eq!(PoAModule::epoch_ends_at(), epoch_end);
        }
    });
}

// XXX: Not testing add_validator and remove_validator with short circuit since that requires
// fetching the slot no. Test with integration test.

#[test]
fn add_validator_basic() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;

        // Enqueue validators
        let mut queued_validators = vec![];
        for id in &[val_id1, val_id2, val_id3, val_id4, val_id5] {
            // Adding a validator should work
            assert_ok!(PoAModule::add_validator_(*id, false));
            // Cannot add the same validator when validator is already active validator
            assert_err!(
                PoAModule::add_validator_(*id, false),
                Error::<TestRuntime>::AlreadyQueuedForAddition
            );

            queued_validators.push(*id);
            // Validators should be added to the queue
            assert_eq!(PoAModule::validators_to_add(), queued_validators);
            // Active validator set should not change
            assert!(PoAModule::active_validators().is_empty());
        }

        // Active validator set should change
        let (active_validator_set_changed, active_validator_count) =
            PoAModule::update_active_validators_if_needed();
        assert!(active_validator_set_changed);
        // Since max validators allowed are 4
        assert_eq!(active_validator_count, 4);
        // There should be only 4 validators as active and in order
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id3, val_id4]
        );
        // There should be only 1 validator in queue
        assert_eq!(PoAModule::validators_to_add(), vec![val_id5]);

        // Cannot enqueue validator already in queue
        assert_err!(
            PoAModule::add_validator_(val_id4, false),
            Error::<TestRuntime>::AlreadyActiveValidator
        );

        // Active validator set should not change as already max validators
        let (active_validator_set_changed, active_validator_count) =
            PoAModule::update_active_validators_if_needed();
        assert!(!active_validator_set_changed);
        // Since max validators allowed are 4
        assert_eq!(active_validator_count, 4);
        // There should be the same 1 validator in queue
        assert_eq!(PoAModule::validators_to_add(), vec![val_id5]);
        // There should be the same 4 validators as active and in order
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id3, val_id4]
        );
    });
}

#[test]
fn remove_validator_basic() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;
        let val_id6 = 6;

        // Add validators in queue and then to active validator set
        for id in &[val_id1, val_id2, val_id3, val_id4, val_id5] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        assert_ok!(PoAModule::remove_validator_(val_id5, false));
        // Reject if already queued for removal
        assert_err!(
            PoAModule::remove_validator_(val_id5, false),
            Error::<TestRuntime>::AlreadyQueuedForRemoval
        );

        // Track removal
        assert_eq!(PoAModule::validators_to_remove(), vec![val_id5]);
        // Validator queue should not be impacted yet
        assert_eq!(PoAModule::validators_to_add(), vec![val_id5]);

        PoAModule::update_active_validators_if_needed();

        // Queued validator is removed
        assert!(PoAModule::validators_to_add().is_empty());
        assert!(PoAModule::validators_to_remove().is_empty());

        // Active validator set is not impacted immediately
        assert_ok!(PoAModule::remove_validator_(val_id4, false));
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id3, val_id4]
        );

        PoAModule::update_active_validators_if_needed();

        // Removal should reflect in active validators
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id3]
        );

        // Remove validator which is neither active nor queued
        assert_ok!(PoAModule::remove_validator_(val_id6, false));
        assert_eq!(PoAModule::validators_to_remove(), vec![val_id6]);

        PoAModule::update_active_validators_if_needed();

        // Validator removal queue is empty
        assert!(PoAModule::validators_to_remove().is_empty());

        // Cannot remove all validators
        assert_ok!(PoAModule::remove_validator_(val_id3, false));
        assert_ok!(PoAModule::remove_validator_(val_id2, false));
        assert_err!(
            PoAModule::remove_validator_(val_id1, false),
            Error::<TestRuntime>::NeedAtLeast1Validator
        );
    });
}

#[test]
fn add_remove_validator() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;
        let val_id6 = 6;

        // Add same validator, `val_id3`, for both addition and removal
        for id in &[val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::remove_validator_(val_id3, false).unwrap();

        PoAModule::update_active_validators_if_needed();

        // The validator `val_id3` should not be added to active validators
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id4]
        );

        // Change active validator set completely
        PoAModule::add_validator_(val_id3, false).unwrap();
        PoAModule::add_validator_(val_id5, false).unwrap();
        PoAModule::add_validator_(val_id6, false).unwrap();
        PoAModule::remove_validator_(val_id1, false).unwrap();
        PoAModule::remove_validator_(val_id2, false).unwrap();
        PoAModule::remove_validator_(val_id4, false).unwrap();

        PoAModule::update_active_validators_if_needed();

        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id3, val_id5, val_id6]
        );

        PoAModule::add_validator_(val_id4, false).unwrap();
        PoAModule::remove_validator_(val_id3, false).unwrap();
        PoAModule::remove_validator_(val_id4, false).unwrap();
        PoAModule::remove_validator_(val_id5, false).unwrap();
        assert_err!(
            PoAModule::remove_validator_(val_id6, false),
            Error::<TestRuntime>::NeedAtLeast1Validator
        );
    });
}

#[test]
fn swap_validator() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;
        let val_id6 = 6;

        for id in &[val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        // Cannot swap out validator id not already active
        assert_err!(
            PoAModule::swap_validator_(val_id5, val_id6),
            Error::<TestRuntime>::SwapOutFailed
        );

        // Cannot swap in validator id already active
        assert_err!(
            PoAModule::swap_validator_(val_id3, val_id4),
            Error::<TestRuntime>::SwapInFailed
        );
        assert_err!(
            PoAModule::swap_validator_(val_id5, val_id4),
            Error::<TestRuntime>::SwapInFailed
        );

        assert_ok!(PoAModule::swap_validator_(val_id4, val_id5));

        // `Some` needed
        assert!(PoAModule::swap_if_needed(None).is_none());

        let swap = <HotSwap<TestRuntime>>::take();
        assert_eq!(PoAModule::swap_if_needed(swap), Some(4));
        // Swap has taken effect
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id3, val_id5]
        );
    });
}

#[test]
fn add_remove_swap_validator() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;
        let val_id6 = 6;

        for id in &[val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        // Validator set does not change as epoch has not ended and no swap needed
        let (changed, count) = PoAModule::update_validator_set(13, 15, None);
        assert!(!changed);
        assert_eq!(count, 4);

        // Validator set changes as swap needed
        let (changed, count) = PoAModule::update_validator_set(13, 15, Some((val_id3, val_id5)));
        assert!(changed);
        assert_eq!(count, 4);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id2, val_id5, val_id4]
        );

        // Validator set changes as swap needed
        let (changed, count) = PoAModule::update_validator_set(14, 14, Some((val_id2, val_id6)));
        assert!(changed);
        assert_eq!(count, 4);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id6, val_id5, val_id4]
        );

        // Validator set changes as epoch ended
        PoAModule::add_validator_(val_id2, false).unwrap();
        PoAModule::remove_validator_(val_id1, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, None);
        assert!(changed);
        assert_eq!(count, 4);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id6, val_id5, val_id4, val_id2]
        );

        // Validator set changes as both epoch ended and swap needed

        // Validators to add and remove and swap but swap and add/remove are disjoint
        PoAModule::add_validator_(val_id3, false).unwrap();
        PoAModule::remove_validator_(val_id2, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id5, val_id1)));
        assert!(changed);
        assert_eq!(count, 4);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id6, val_id1, val_id4, val_id3]
        );

        // No validators to add or remove but only swap
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id6, val_id2)));
        assert!(changed);
        assert_eq!(count, 4);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id2, val_id1, val_id4, val_id3]
        );

        // A validator to remove and a swap and remove and swap are disjoint
        PoAModule::remove_validator_(val_id2, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id4, val_id5)));
        assert!(changed);
        assert_eq!(count, 3);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id5, val_id3]
        );

        // A validator to remove and a swap and remove and swap intersect. Both take effect
        PoAModule::remove_validator_(val_id4, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id3, val_id4)));
        assert!(changed);
        // Validator swapped in removed
        assert_eq!(count, 2);
        assert_eq!(PoAModule::active_validators(), vec![val_id1, val_id5]);

        // A validator to remove and a swap and remove and swap intersect but validator to remove is swapped out.
        PoAModule::remove_validator_(val_id1, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id1, val_id2)));
        assert!(changed);
        // Validator swapped in removed
        assert_eq!(count, 2);
        assert_eq!(PoAModule::active_validators(), vec![val_id2, val_id5]);

        PoAModule::add_validator_(val_id3, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id2, val_id3)));
        assert!(changed);
        // Validator swapped in removed
        assert_eq!(count, 2);
        assert_eq!(PoAModule::active_validators(), vec![val_id3, val_id5]);
    });
}

#[test]
fn txn_fees() {
    new_test_ext().execute_with(|| {
        // Txn fees for the block is 0 initially.
        assert_eq!(<TxnFees<TestRuntime>>::get(), 0);

        // Deposits should increase the accumulated fees
        PoAModule::update_txn_fees_for_block(5);
        assert_eq!(<TxnFees<TestRuntime>>::get(), 5);

        // More deposits increase the accumulated fees more
        PoAModule::update_txn_fees_for_block(20);
        assert_eq!(<TxnFees<TestRuntime>>::get(), 25);

        // Clean up
        <TxnFees<TestRuntime>>::take();

        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;

        for id in &[val_id1, val_id2] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        let balance_id1 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>();
        let balance_id2 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>();

        // Since no fees yet, `award_txn_fees_if_any` would return None
        assert!(PoAModule::award_txn_fees_if_any(&val_id1).is_none());
        assert!(PoAModule::award_txn_fees_if_any(&val_id2).is_none());

        // Balance does not change
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>()
                - balance_id1,
            0
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>()
                - balance_id2,
            0
        );

        // Put some txn fees to award
        let fees = 100;
        <TxnFees<TestRuntime>>::put(fees);

        // Award fees to author
        assert_eq!(
            PoAModule::award_txn_fees_if_any(&val_id1),
            Some(fees as Balance)
        );

        // Only the author's balance should change
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>()
                - balance_id1,
            fees
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>()
                - balance_id2,
            0
        );

        // Calling the function again has no more impact
        assert!(PoAModule::award_txn_fees_if_any(&val_id1).is_none());
        assert!(PoAModule::award_txn_fees_if_any(&val_id2).is_none());

        // Balance same as before
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>()
                - balance_id1,
            fees
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>()
                - balance_id2,
            0
        );
    });
}

#[test]
fn epoch_details_and_block_count() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;

        for id in &[val_id1, val_id2] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_details_for_ending_epoch(1);
        PoAModule::update_active_validators_if_needed();
        PoAModule::set_next_epoch_end(1, 2);

        PoAModule::update_details_on_new_epoch(1, 1, 2);

        // Epoch details, i.e. `Epoch` and `Epochs` should be updated
        assert_eq!(PoAModule::epoch(), 1);
        assert_eq!(PoAModule::get_epoch_detail(1), EpochDetail::new(2, 1, 26));

        // No blocks authored
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id1),
            ValidatorStatsPerEpoch {
                block_count: 0,
                locked_reward: None,
                unlocked_reward: None
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id2),
            ValidatorStatsPerEpoch {
                block_count: 0,
                locked_reward: None,
                unlocked_reward: None
            }
        );

        // After val_id1 authors
        PoAModule::increment_current_epoch_block_count(val_id1);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id1),
            ValidatorStatsPerEpoch {
                block_count: 1,
                locked_reward: None,
                unlocked_reward: None
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id2),
            ValidatorStatsPerEpoch {
                block_count: 0,
                locked_reward: None,
                unlocked_reward: None
            }
        );

        // After val_id2 authors
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id1),
            ValidatorStatsPerEpoch {
                block_count: 1,
                locked_reward: None,
                unlocked_reward: None
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id2),
            ValidatorStatsPerEpoch {
                block_count: 1,
                locked_reward: None,
                unlocked_reward: None
            }
        );

        // They author few more blocks
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id1),
            ValidatorStatsPerEpoch {
                block_count: 3,
                locked_reward: None,
                unlocked_reward: None
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(1, &val_id2),
            ValidatorStatsPerEpoch {
                block_count: 3,
                locked_reward: None,
                unlocked_reward: None
            }
        );

        // Epoch changes, slot becomes 7
        PoAModule::update_details_for_ending_epoch(7);
        PoAModule::set_next_epoch_end(7, 2);
        PoAModule::update_details_on_new_epoch(2, 7, 2);
        // Epoch details, i.e. `Epoch` and `Epochs` should be updated
        assert_eq!(PoAModule::epoch(), 2);
        assert_eq!(PoAModule::get_epoch_detail(2), EpochDetail::new(2, 7, 32));
        // Previous epoch's end marked
        let epoch_1 = PoAModule::get_epoch_detail(1);
        assert_eq!(epoch_1.expected_ending_slot, 26);
        assert_eq!(epoch_1.ending_slot, Some(6));

        // They author few more blocks
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(2, &val_id1),
            ValidatorStatsPerEpoch {
                block_count: 2,
                locked_reward: None,
                unlocked_reward: None
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(2, &val_id2),
            ValidatorStatsPerEpoch {
                block_count: 2,
                locked_reward: None,
                unlocked_reward: None
            }
        );
    });
}

#[test]
fn slots_per_validator() {
    new_test_ext().execute_with(|| {
        let epoch_detail = EpochDetail::new(2, 1, 26);

        // Both validator claimed all given slots
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 26, &BlockCount::SameBlocks(13)),
            13
        );
        // One validator did not get 1 slot, swap
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 25, &BlockCount::MaxBlocks(13)),
            12
        );
        // Both validators did not get 1 slot, swap or short circuit
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 24, &BlockCount::SameBlocks(12)),
            12
        );
        // Only 1 validator got a slot before the swap happened
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 1, &BlockCount::MaxBlocks(1)),
            0
        );
        // Both validators got 1 slot each before swap or epoch termination
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 2, &BlockCount::SameBlocks(1)),
            1
        );

        // Both validators got a slot before the network stopped
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 27, &BlockCount::SameBlocks(1)),
            1
        );
        // Only 1 validator got a slot before the network stopped
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 27, &BlockCount::MaxBlocks(1)),
            0
        );
        // No validator got any slot
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 27, &BlockCount::MaxBlocks(0)),
            0
        );

        let epoch_detail = EpochDetail::new(3, 11, 37);

        // All validator claimed all given slots
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 37, &BlockCount::SameBlocks(9)),
            9
        );
        // One validator did not get 1 slot, swap
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 36, &BlockCount::MaxBlocks(9)),
            8
        );
        // 2 validators did not get 1 slot, swap
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 35, &BlockCount::MaxBlocks(9)),
            8
        );

        // All validators did not get 1 slot, swap or short circuit
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 34, &BlockCount::SameBlocks(8)),
            8
        );
        // Only 1 validator got a slot before the swap happened
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 11, &BlockCount::MaxBlocks(1)),
            0
        );
        // Only 2 validators got a slot before the swap happened
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 12, &BlockCount::MaxBlocks(1)),
            0
        );
        // All validators got 1 slot each before swap or epoch termination
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 13, &BlockCount::SameBlocks(1)),
            1
        );

        // All validators got a slot before the network stopped
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 40, &BlockCount::SameBlocks(1)),
            1
        );
        // Only 1 validator got a slot before the network stopped
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 40, &BlockCount::MaxBlocks(1)),
            0
        );
        // Only 2 validators got a slot before the network stopped
        assert_eq!(
            PoAModule::get_slots_per_validator(&epoch_detail, 40, &BlockCount::MaxBlocks(1)),
            0
        );
    });
}

#[test]
fn validator_block_counts() {
    new_test_ext().execute_with(|| {
        let val_id1 = 1;
        let val_id2 = 2;

        for id in &[val_id1, val_id2] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();
        PoAModule::update_details_on_new_epoch(1, 2, 2);

        // No blocks produced yet
        let (block_count, map) = PoAModule::count_validator_blocks(1);
        assert!(matches!(block_count, BlockCount::SameBlocks(0)));
        assert_eq!(map.get(&val_id1), Some(&0));
        assert_eq!(map.get(&val_id2), Some(&0));

        // Both validator produced 1 block
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);

        let (block_count, map) = PoAModule::count_validator_blocks(1);
        assert!(matches!(block_count, BlockCount::SameBlocks(1)));
        assert_eq!(map.get(&val_id1), Some(&1));
        assert_eq!(map.get(&val_id2), Some(&1));

        // Only 1 validator produced an additional block
        PoAModule::increment_current_epoch_block_count(val_id1);
        let (block_count, map) = PoAModule::count_validator_blocks(1);
        assert!(matches!(block_count, BlockCount::MaxBlocks(2)));
        assert_eq!(map.get(&val_id1), Some(&2));
        assert_eq!(map.get(&val_id2), Some(&1));

        // Another validator produced an additional block
        PoAModule::increment_current_epoch_block_count(val_id2);
        let (block_count, map) = PoAModule::count_validator_blocks(1);
        assert!(matches!(block_count, BlockCount::SameBlocks(2)));
        assert_eq!(map.get(&val_id1), Some(&2));
        assert_eq!(map.get(&val_id2), Some(&2));

        PoAModule::increment_current_epoch_block_count(val_id1);
        let (block_count, map) = PoAModule::count_validator_blocks(1);
        assert!(matches!(block_count, BlockCount::MaxBlocks(3)));
        assert_eq!(map.get(&val_id1), Some(&3));
        assert_eq!(map.get(&val_id2), Some(&2));
    });
}

#[test]
fn emission_reward_for_shorter_epoch() {
    new_test_ext().execute_with(|| {
        let max_emm = 500;
        <MaxEmmValidatorEpoch<TestRuntime>>::put(max_emm);

        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 10) as u64,
            500
        );
        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 0) as u64,
            0
        );
        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 1) as u64,
            50
        );
        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 2) as u64,
            100
        );
        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 3) as u64,
            150
        );
        assert_eq!(
            PoAModule::get_max_emission_reward_per_validator_per_epoch(10, 4) as u64,
            200
        );
    });
}

#[test]
fn treasury_emission_reward() {
    new_test_ext().execute_with(|| {
        TreasuryRewardsPercent::put(60);

        let mut balance_current = PoAModule::treasury_balance().saturated_into::<Balance>();
        assert_eq!(balance_current, 0);

        for (validator_reward, treasury_reward) in &[
            (100, 60),
            (101, 60),
            (102, 61),
            (103, 61),
            (104, 62),
            (10000, 6000),
            (10010, 6006),
            (10020, 6012),
            (10050, 6030),
        ] {
            let reward = PoAModule::mint_treasury_emission_rewards(*validator_reward);
            assert_eq!(reward, *treasury_reward);
            let balance_new = PoAModule::treasury_balance().saturated_into::<Balance>();
            assert_eq!(balance_new - balance_current, reward);
            balance_current = balance_new;
        }
    });
}

#[test]
fn treasury_withdrawal() {
    new_test_ext().execute_with(|| {
        TreasuryRewardsPercent::put(60);
        let acc_id = 1;

        assert_eq!(PoAModule::treasury_balance().saturated_into::<Balance>(), 0);
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&acc_id).saturated_into::<Balance>(),
            0
        );

        PoAModule::mint_treasury_emission_rewards(1000);
        assert_eq!(
            PoAModule::treasury_balance().saturated_into::<Balance>(),
            600
        );

        PoAModule::withdraw_from_treasury_(acc_id, 100).unwrap();
        assert_eq!(
            PoAModule::treasury_balance().saturated_into::<Balance>(),
            500
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&acc_id).saturated_into::<Balance>(),
            100
        );

        PoAModule::mint_treasury_emission_rewards(200);
        assert_eq!(
            PoAModule::treasury_balance().saturated_into::<Balance>(),
            620
        );

        PoAModule::withdraw_from_treasury_(acc_id, 600).unwrap();
        assert_eq!(
            PoAModule::treasury_balance().saturated_into::<Balance>(),
            20
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&acc_id).saturated_into::<Balance>(),
            700
        );

        // Cannot withdraw beyond the treasury's balance
        assert!(PoAModule::withdraw_from_treasury_(acc_id, 21).is_err());
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&acc_id).saturated_into::<Balance>(),
            700
        );
    });
}

#[test]
fn validator_rewards_credit() {
    new_test_ext().execute_with(|| {
        let val_id = 1;

        let balance_f_1 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id).saturated_into::<Balance>();
        let balance_r_1 =
            <TestRuntime as Trait>::Currency::reserved_balance(&val_id).saturated_into::<Balance>();
        assert_eq!(balance_f_1, 0);
        assert_eq!(balance_r_1, 0);

        // Credit some locked and unlocked balance to an account
        let locked_1 = 100;
        let unlocked_1 = 1000;
        PoAModule::credit_emission_rewards_to_validator(&val_id, locked_1, unlocked_1);

        // The locked and unlocked balances should be reflected as reserve and free balances respectively
        let balance_f_2 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id).saturated_into::<Balance>();
        let balance_r_2 =
            <TestRuntime as Trait>::Currency::reserved_balance(&val_id).saturated_into::<Balance>();
        assert_eq!(balance_f_2, unlocked_1);
        assert_eq!(balance_r_2, locked_1);

        // Credit some more locked and unlocked balance to an account
        let locked_2 = 99509;
        let unlocked_2 = 235;
        PoAModule::credit_emission_rewards_to_validator(&val_id, locked_2, unlocked_2);

        // The locked and unlocked balances should be reflected as reserve and free balances respectively
        let balance_f_3 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id).saturated_into::<Balance>();
        let balance_r_3 =
            <TestRuntime as Trait>::Currency::reserved_balance(&val_id).saturated_into::<Balance>();
        assert_eq!(balance_f_3, unlocked_1 + unlocked_2);
        assert_eq!(balance_r_3, locked_1 + locked_2);

        // Unreserve some funds and check they can be unreserved and free and reserved balances get updated
        let unreserve = 125;
        let cannot_unreserve =
            <TestRuntime as Trait>::Currency::unreserve(&val_id, 125).saturated_into::<Balance>();
        assert_eq!(cannot_unreserve, 0);

        let balance_f_4 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id).saturated_into::<Balance>();
        let balance_r_4 =
            <TestRuntime as Trait>::Currency::reserved_balance(&val_id).saturated_into::<Balance>();
        assert_eq!(balance_f_4, unlocked_1 + unlocked_2 + unreserve);
        assert_eq!(balance_r_4, locked_1 + locked_2 - unreserve);
    });
}

#[test]
fn validator_rewards_for_non_empty_epoch() {
    new_test_ext().execute_with(|| {
        let max_emm = 500;
        let lock_pc = 20;
        <MaxEmmValidatorEpoch<TestRuntime>>::put(max_emm);
        ValidatorRewardsLockPercent::put(lock_pc);

        let val_id1 = 1;
        let val_id2 = 2;

        let current_epoch_no = 1;

        for id in &[val_id1, val_id2] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();
        PoAModule::update_details_on_new_epoch(current_epoch_no, 1, 2);

        let (_, validator_block_counts) = PoAModule::count_validator_blocks(current_epoch_no);

        // No slots are used by any validators and they both get no reward
        let expected_slots_per_validator = 10;
        let slots_per_validator = 10;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts,
            );
        assert_eq!(total_validator_reward, 0);
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>(),
            0
        );
        assert_eq!(
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>(),
            0
        );

        // Both validator produce 10 blocks
        for _ in 0..10 {
            PoAModule::increment_current_epoch_block_count(val_id1);
            PoAModule::increment_current_epoch_block_count(val_id2);
        }
        let (_, validator_block_counts) = PoAModule::count_validator_blocks(current_epoch_no);

        // The epoch was shortened but all slots are used by both validators and they both get 100% reward as per the shortened epoch
        let expected_slots_per_validator = 20;
        let slots_per_validator = 10;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts.clone(),
            );
        // Only 50% of the expected slots were taken
        assert_eq!(total_validator_reward, 500);
        // 20% balance remains reserved, rest is free
        let bal_id1_f0 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r0 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f0 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r0 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f0, 200);
        assert_eq!(bal_id1_r0, 50);
        assert_eq!(bal_id2_f0, 200);
        assert_eq!(bal_id2_r0, 50);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(50),
                unlocked_reward: Some(200)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(50),
                unlocked_reward: Some(200)
            }
        );

        // The epoch was not shortened and all slots are used by both validators and they both get 100% reward (of `max_emm`)
        let expected_slots_per_validator = 10;
        let slots_per_validator = 10;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts.clone(),
            );
        assert_eq!(total_validator_reward, 1000);
        // 20% balance remains reserved, rest is free
        let bal_id1_f1 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r1 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f1 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r1 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f1 - bal_id1_f0, 400);
        assert_eq!(bal_id1_r1 - bal_id1_r0, 100);
        assert_eq!(bal_id2_f1 - bal_id2_f0, 400);
        assert_eq!(bal_id2_r1 - bal_id2_r0, 100);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(100),
                unlocked_reward: Some(400)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(100),
                unlocked_reward: Some(400)
            }
        );

        // The epoch was not shortened and ~83% slots are used by both validators and they both get ~83% reward (of `max_emm`)
        let expected_slots_per_validator = 12;
        let slots_per_validator = 12;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts.clone(),
            );
        assert_eq!(total_validator_reward, 832);
        // 20% balance remains reserved, rest is free
        let bal_id1_f2 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r2 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f2 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r2 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f2 - bal_id1_f1, 333);
        assert_eq!(bal_id1_r2 - bal_id1_r1, 83);
        assert_eq!(bal_id2_f2 - bal_id2_f1, 333);
        assert_eq!(bal_id2_r2 - bal_id2_r1, 83);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(83),
                unlocked_reward: Some(333)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(83),
                unlocked_reward: Some(333)
            }
        );

        // The epoch was not shortened and ~63% slots are used by both validators and they both get ~63% reward (of `max_emm`)
        let expected_slots_per_validator = 16;
        let slots_per_validator = 16;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts,
            );
        assert_eq!(total_validator_reward, 624);
        // 20% balance remains reserved, rest is free
        let bal_id1_f3 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r3 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f3 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r3 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f3 - bal_id1_f2, 250);
        assert_eq!(bal_id1_r3 - bal_id1_r2, 62);
        assert_eq!(bal_id2_f3 - bal_id2_f2, 250);
        assert_eq!(bal_id2_r3 - bal_id2_r2, 62);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(62),
                unlocked_reward: Some(250)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(62),
                unlocked_reward: Some(250)
            }
        );

        // One validator produces 5 more blocks
        for _ in 0..5 {
            PoAModule::increment_current_epoch_block_count(val_id1);
        }
        let (_, validator_block_counts) = PoAModule::count_validator_blocks(current_epoch_no);

        // The epoch was not shortened and all slots are used by 1 validator only and it get 100% reward (of `max_emm`) and the other gets less
        let expected_slots_per_validator = 15;
        let slots_per_validator = 15;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts.clone(),
            );
        assert_eq!(total_validator_reward, 833);
        // 20% balance remains reserved, rest is free
        let bal_id1_f4 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r4 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f4 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r4 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f4 - bal_id1_f3, 400);
        assert_eq!(bal_id1_r4 - bal_id1_r3, 100);
        assert_eq!(bal_id2_f4 - bal_id2_f3, 267);
        assert_eq!(bal_id2_r4 - bal_id2_r3, 66);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 15,
                locked_reward: Some(100),
                unlocked_reward: Some(400)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(66),
                unlocked_reward: Some(267)
            }
        );

        // No validators used all slots and both used different slots
        let expected_slots_per_validator = 18;
        let slots_per_validator = 18;
        let total_validator_reward =
            PoAModule::mint_and_track_validator_rewards_for_non_empty_epoch(
                current_epoch_no,
                expected_slots_per_validator,
                slots_per_validator,
                validator_block_counts,
            );
        assert_eq!(total_validator_reward, 693);
        // 20% balance remains reserved, rest is free
        let bal_id1_f5 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id1).saturated_into::<Balance>();
        let bal_id1_r5 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id1)
            .saturated_into::<Balance>();
        let bal_id2_f5 =
            <TestRuntime as Trait>::Currency::free_balance(&val_id2).saturated_into::<Balance>();
        let bal_id2_r5 = <TestRuntime as Trait>::Currency::reserved_balance(&val_id2)
            .saturated_into::<Balance>();
        assert_eq!(bal_id1_f5 - bal_id1_f4, 333);
        assert_eq!(bal_id1_r5 - bal_id1_r4, 83);
        assert_eq!(bal_id2_f5 - bal_id2_f4, 222);
        assert_eq!(bal_id2_r5 - bal_id2_r4, 55);
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id1),
            ValidatorStatsPerEpoch {
                block_count: 15,
                locked_reward: Some(83),
                unlocked_reward: Some(333)
            }
        );
        assert_eq!(
            PoAModule::get_validator_stats_for_epoch(current_epoch_no, val_id2),
            ValidatorStatsPerEpoch {
                block_count: 10,
                locked_reward: Some(55),
                unlocked_reward: Some(222)
            }
        );
    });
}

#[test]
fn rewards_for_non_empty_epoch() {
    new_test_ext().execute_with(|| {
        let emission_supply = 1_000_000;
        let max_emm = 500;
        let v_lock_pc = 20;
        let t_lock_pc = 60;
        <EmissionSupply<TestRuntime>>::put(emission_supply);
        <MaxEmmValidatorEpoch<TestRuntime>>::put(max_emm);
        ValidatorRewardsLockPercent::put(v_lock_pc);
        TreasuryRewardsPercent::put(t_lock_pc);

        let val_id1 = 1;
        let val_id2 = 2;

        let current_epoch_no = 1;
        for id in &[val_id1, val_id2] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();
        PoAModule::update_details_on_new_epoch(current_epoch_no, 1, 2);

        let (_, validator_block_counts) = PoAModule::count_validator_blocks(current_epoch_no);

        // No slots are used by any validators and they both get no reward and emission supply does not change
        let slots_per_validator = 10;
        let mut epoch_detail = EpochDetail::new(2, 1, 26);
        PoAModule::mint_rewards_for_non_empty_epoch(
            &mut epoch_detail,
            current_epoch_no,
            slots_per_validator,
            validator_block_counts,
        );
        assert_eq!(epoch_detail.total_emission, Some(0));
        assert_eq!(epoch_detail.emission_for_treasury, Some(0));
        assert_eq!(epoch_detail.emission_for_validators, Some(0));
        assert_eq!(PoAModule::emission_supply(), emission_supply);

        // Both validator produce 10 blocks
        for _ in 0..10 {
            PoAModule::increment_current_epoch_block_count(val_id1);
            PoAModule::increment_current_epoch_block_count(val_id2);
        }
        let (_, validator_block_counts) = PoAModule::count_validator_blocks(current_epoch_no);

        // All slots are used by both validators and they both get 100% reward (of `max_emm`). Emission supply changes
        let slots_per_validator = 10;
        // Expecting 13 slots per validator
        let mut epoch_detail = EpochDetail::new(2, 1, 26);
        PoAModule::mint_rewards_for_non_empty_epoch(
            &mut epoch_detail,
            current_epoch_no,
            slots_per_validator,
            validator_block_counts,
        );
        assert_eq!(epoch_detail.total_emission, Some(1228));
        assert_eq!(epoch_detail.emission_for_treasury, Some(460));
        assert_eq!(epoch_detail.emission_for_validators, Some(768));
        assert_eq!(
            PoAModule::emission_supply(),
            emission_supply - epoch_detail.total_emission.unwrap() as u64
        );
    });
}

#[test]
fn emission_rewards_status() {
    new_test_ext().execute_with(|| {
        assert_eq!(PoAModule::emission_status(), true);
        assert_ok!(PoAModule::set_emission_status(
            RawOrigin::Root.into(),
            false
        ));
        assert_eq!(PoAModule::emission_status(), false);
        assert_ok!(PoAModule::set_emission_status(RawOrigin::Root.into(), true));
        assert_eq!(PoAModule::emission_status(), true);
        // Setting it to existing value
        assert_ok!(PoAModule::set_emission_status(RawOrigin::Root.into(), true));
        assert_eq!(PoAModule::emission_status(), true);

        // Emission rewards are enabled
        let emission_supply = 1_000_000;
        let max_emm = 500;
        let v_lock_pc = 20;
        let t_lock_pc = 60;
        <EmissionSupply<TestRuntime>>::put(emission_supply);
        <MaxEmmValidatorEpoch<TestRuntime>>::put(max_emm);
        ValidatorRewardsLockPercent::put(v_lock_pc);
        TreasuryRewardsPercent::put(t_lock_pc);

        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;

        let current_epoch_no = 1;
        for id in &[val_id1, val_id2, val_id3] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();
        PoAModule::update_details_on_new_epoch(current_epoch_no, 1, 3);

        // All validator produce 10 blocks
        for _ in 0..10 {
            PoAModule::increment_current_epoch_block_count(val_id1);
            PoAModule::increment_current_epoch_block_count(val_id2);
            PoAModule::increment_current_epoch_block_count(val_id3);
        }
        let mut epoch_detail = EpochDetail::new(3, 1, 39);
        assert!(PoAModule::mint_emission_rewards_if_needed(
            current_epoch_no,
            30,
            &mut epoch_detail
        ));

        // Emission rewards being generated
        assert!(epoch_detail.total_emission.unwrap() > 0);
        assert!(epoch_detail.emission_for_treasury.unwrap() > 0);
        assert!(epoch_detail.emission_for_validators.unwrap() > 0);

        assert_ok!(PoAModule::set_emission_status(
            RawOrigin::Root.into(),
            false
        ));
        assert_eq!(PoAModule::emission_status(), false);

        // Emission rewards are disabled
        let current_epoch_no = 2;
        PoAModule::update_details_on_new_epoch(current_epoch_no, 31, 3);

        // All validator produce 10 blocks
        for _ in 0..10 {
            PoAModule::increment_current_epoch_block_count(val_id1);
            PoAModule::increment_current_epoch_block_count(val_id2);
            PoAModule::increment_current_epoch_block_count(val_id3);
        }

        let mut epoch_detail = EpochDetail::new(3, 40, 78);
        assert!(!PoAModule::mint_emission_rewards_if_needed(
            current_epoch_no,
            60,
            &mut epoch_detail
        ));

        // No emission rewards were generated
        assert!(epoch_detail.total_emission.is_none());
        assert!(epoch_detail.emission_for_treasury.is_none());
        assert!(epoch_detail.emission_for_validators.is_none());
    });
}

#[test]
fn config_set_by_master() {
    new_test_ext().execute_with(|| {
        // Set epoch length
        assert_eq!(PoAModule::min_epoch_length(), 25);
        assert_eq!(PoAModule::min_epoch_length_tentative(), 0);
        assert_ok!(PoAModule::set_min_epoch_length(RawOrigin::Root.into(), 30));
        // Tentative value changed
        assert_eq!(PoAModule::min_epoch_length_tentative(), 30);
        // Actual value unchanged
        assert_eq!(PoAModule::min_epoch_length(), 25);

        // Epoch end
        assert_eq!(PoAModule::get_and_set_min_epoch_length_on_epoch_end(), 30);
        // Actual value changed
        assert_eq!(PoAModule::min_epoch_length(), 30);
        // Tentative value reset
        assert_eq!(PoAModule::min_epoch_length_tentative(), 0);

        // Set max validators
        assert_eq!(PoAModule::max_active_validators(), 4);
        assert_eq!(PoAModule::max_active_validators_tentative(), 0);
        assert_ok!(PoAModule::set_max_active_validators(
            RawOrigin::Root.into(),
            10
        ));
        // Tentative value changed
        assert_eq!(PoAModule::max_active_validators_tentative(), 10);
        // Actual value unchanged
        assert_eq!(PoAModule::max_active_validators(), 4);

        // Epoch end
        assert_eq!(
            PoAModule::get_and_set_max_active_validators_on_epoch_end(),
            10
        );
        // Actual value changed
        assert_eq!(PoAModule::max_active_validators(), 10);
        // Tentative value reset
        assert_eq!(PoAModule::max_active_validators_tentative(), 0);

        // Max emission reward per validator
        assert_eq!(PoAModule::max_emm_validator_epoch(), 0);
        assert_ok!(PoAModule::set_max_emm_validator_epoch(
            RawOrigin::Root.into(),
            1000
        ));
        assert_eq!(PoAModule::max_emm_validator_epoch(), 1000);
        assert_ok!(PoAModule::set_max_emm_validator_epoch(
            RawOrigin::Root.into(),
            0
        ));
        assert_eq!(PoAModule::max_emm_validator_epoch(), 0);

        // Validator reward lock percentage
        assert_eq!(PoAModule::validator_reward_lock_pc(), 0);
        assert_ok!(PoAModule::set_validator_reward_lock_pc(
            RawOrigin::Root.into(),
            30
        ));
        assert_eq!(PoAModule::validator_reward_lock_pc(), 30);

        // Can't set percentage > 100
        assert_err!(
            PoAModule::set_validator_reward_lock_pc(RawOrigin::Root.into(), 101),
            Error::<TestRuntime>::PercentageGreaterThan100
        );
        assert_eq!(PoAModule::validator_reward_lock_pc(), 30);

        assert_ok!(PoAModule::set_validator_reward_lock_pc(
            RawOrigin::Root.into(),
            0
        ));

        // Treasury reward percentage
        assert_eq!(PoAModule::treasury_reward_pc(), 0);
        assert_ok!(PoAModule::set_treasury_reward_pc(
            RawOrigin::Root.into(),
            45
        ));
        assert_eq!(PoAModule::treasury_reward_pc(), 45);

        // Can't set percentage > 100
        assert_err!(
            PoAModule::set_treasury_reward_pc(RawOrigin::Root.into(), 101),
            Error::<TestRuntime>::PercentageGreaterThan100
        );
        assert_eq!(PoAModule::treasury_reward_pc(), 45);

        assert_ok!(PoAModule::set_treasury_reward_pc(RawOrigin::Root.into(), 0));
        assert_eq!(PoAModule::treasury_reward_pc(), 0);
    });
}

#[test]
fn validator_set_change_on_max_active_validator_change() {
    new_test_ext().execute_with(|| {
        // The active validator set should increase and decrease as `MaxActiveValidators` increases
        // or decreases

        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;
        let val_id3 = 3;
        let val_id4 = 4;
        let val_id5 = 5;

        // Add 5 validators
        for id in &[val_id1, val_id2, val_id3, val_id4, val_id5] {
            PoAModule::add_validator_(*id, false).unwrap();
        }
        // Only 4 become active as that is the maximum active validators
        let (active_validator_set_changed, active_validator_count) =
            PoAModule::update_active_validators_if_needed();
        assert!(active_validator_set_changed);
        assert_eq!(active_validator_count, 4);

        // Increase maximum active validators count to 5
        assert_ok!(PoAModule::set_max_active_validators(
            RawOrigin::Root.into(),
            5
        ));

        // 5 validators should be active now
        let (active_validator_set_changed, active_validator_count) =
            PoAModule::update_active_validators_if_needed();
        assert!(active_validator_set_changed);
        assert_eq!(active_validator_count, 5);

        // Decrease maximum active validators count to 3
        assert_ok!(PoAModule::set_max_active_validators(
            RawOrigin::Root.into(),
            3
        ));

        // 3 validators should be active now
        let (active_validator_set_changed, active_validator_count) =
            PoAModule::update_active_validators_if_needed();
        assert!(active_validator_set_changed);
        assert_eq!(active_validator_count, 3);

        assert_eq!(PoAModule::validators_to_add(), vec![val_id4, val_id5]);
    });
}

#[test]
fn expected_treasury_account_id() {
    use sp_runtime::traits::AccountIdConversion;
    assert_eq!(
        AccountIdConversion::<[u8; 32]>::into_account(&TREASURY_ID),
        *b"modlTreasury\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
}
