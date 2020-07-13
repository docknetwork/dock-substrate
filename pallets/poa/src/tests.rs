#![cfg(test)]

use super::*;

use frame_support::{
    assert_err, assert_ok, impl_outer_origin, parameter_types,
    traits::FindAuthor,
    weights::{constants::WEIGHT_PER_SECOND, Weight},
};
use sp_core::{crypto::key_types, H256};
use sp_runtime::{
    testing::{Header, UintAuthorityId},
    traits::{BlakeTwo256, ConvertInto, IdentityLookup, OpaqueKeys},
    ConsensusEngineId, KeyTypeId, Perbill,
};

impl_outer_origin! {
    pub enum Origin for Test {}
}

#[derive(Clone, Eq, Debug, PartialEq)]
pub struct Test;

type PoAModule = Module<Test>;

type System = system::Module<Test>;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 2 * WEIGHT_PER_SECOND;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
    pub const MinEpochLength: u64 = 25;
    pub const MaxActiveValidators: u8 = 4;
    pub const TransactionByteFee: u128 = 1;
}

impl system::Trait for Test {
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
    type ModuleToIndex = ();
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
}

impl balances::Trait for Test {
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
}

impl Trait for Test {
    type Event = ();
    type MinEpochLength = MinEpochLength;
    type MaxActiveValidators = MaxActiveValidators;
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

impl pallet_session::Trait for Test {
    type Event = ();
    type ValidatorId = <Self as system::Trait>::AccountId;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = PoAModule;
    type NextSessionRotation = ();
    type SessionManager = PoAModule;
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type DisabledValidatorsThreshold = ();
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

// TODO: Get rid of this and move fee deduction to poa module
impl pallet_authorship::Trait for Test {
    type FindAuthor = TestAuthor;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = ();
    type EventHandler = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}

#[test]
fn current_epoch_end() {
    new_test_ext().execute_with(|| {
        // Minimum epoch length is 25
        for (starting_slot, validator_count, ending_slot) in vec![
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
        ] {
            let epoch_end = PoAModule::set_current_epoch_end(starting_slot, validator_count);
            assert_eq!(epoch_end, ending_slot);
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
        for (validator_count, starting_slot, current_slot_no, expected_epoch_end) in vec![
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
                (validator_count, starting_slot, None as Option<u64>),
            );
            let epoch_end = PoAModule::update_current_epoch_end_on_short_circuit(current_slot_no);
            assert_eq!(epoch_end, expected_epoch_end);
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
        for id in vec![val_id1, val_id2, val_id3, val_id4, val_id5] {
            // Adding a validator should work
            assert_ok!(PoAModule::add_validator_(id, false));
            // Cannot add the same validator when validator is already active validator
            assert_err!(
                PoAModule::add_validator_(id, false),
                Error::<Test>::AlreadyQueuedForAddition
            );

            queued_validators.push(id.clone());
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
            Error::<Test>::AlreadyActiveValidator
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
        for id in vec![val_id1, val_id2, val_id3, val_id4, val_id5] {
            PoAModule::add_validator_(id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        assert_ok!(PoAModule::remove_validator_(val_id5, false));
        // Reject if already queued for removal
        assert_err!(
            PoAModule::remove_validator_(val_id5, false),
            Error::<Test>::AlreadyQueuedForRemoval
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
            Error::<Test>::NeedAtLeast1Validator
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
        for id in vec![val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(id, false).unwrap();
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
            Error::<Test>::NeedAtLeast1Validator
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

        for id in vec![val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        // Cannot swap out validator id not already active
        assert_err!(
            PoAModule::swap_validator_(val_id5, val_id6),
            Error::<Test>::SwapOutFailed
        );

        // Cannot swap in validator id already active
        assert_err!(
            PoAModule::swap_validator_(val_id3, val_id4),
            Error::<Test>::SwapInFailed
        );
        assert_err!(
            PoAModule::swap_validator_(val_id5, val_id4),
            Error::<Test>::SwapInFailed
        );

        assert_ok!(PoAModule::swap_validator_(val_id4, val_id5));

        // `Some` needed
        assert!(PoAModule::swap_if_needed(None).is_none());

        let swap = <HotSwap<Test>>::take();
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

        for id in vec![val_id1, val_id2, val_id3, val_id4] {
            PoAModule::add_validator_(id, false).unwrap();
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
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id1, val_id5]
        );

        // A validator to remove and a swap and remove and swap intersect but validator to remove is swapped out.
        PoAModule::remove_validator_(val_id1, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id1, val_id2)));
        assert!(changed);
        // Validator swapped in removed
        assert_eq!(count, 2);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id2, val_id5]
        );

        PoAModule::add_validator_(val_id3, false).unwrap();
        let (changed, count) = PoAModule::update_validator_set(15, 14, Some((val_id2, val_id3)));
        assert!(changed);
        // Validator swapped in removed
        assert_eq!(count, 2);
        assert_eq!(
            PoAModule::active_validators(),
            vec![val_id3, val_id5]
        );
    });
}

#[test]
fn txn_fees() {
    new_test_ext().execute_with(|| {
        // Max validators allowed is 4
        let val_id1 = 1;
        let val_id2 = 2;

        for id in vec![val_id1, val_id2] {
            PoAModule::add_validator_(id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        let balance_id1 = <Test as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>();
        let balance_id2 = <Test as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>();

        // Since no fees yet, `award_txn_fees_if_any` would return None
        assert!(PoAModule::award_txn_fees_if_any(&val_id1).is_none());
        assert!(PoAModule::award_txn_fees_if_any(&val_id2).is_none());

        // Balance does not change
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>() - balance_id1,
            0
        );
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>() - balance_id2,
            0
        );

        // Put some txn fees to award
        let fees = 100;
        <TxnFees<Test>>::put(fees);

        // Award fees to author
        assert_eq!(PoAModule::award_txn_fees_if_any(&val_id1), Some(fees));

        // Only the author's balance should change
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>() - balance_id1,
            fees
        );
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>() - balance_id2,
            0
        );

        // Calling the function again has no more impact
        assert!(PoAModule::award_txn_fees_if_any(&val_id1).is_none());
        assert!(PoAModule::award_txn_fees_if_any(&val_id2).is_none());

        // Balance same as before
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id1).saturated_into::<u64>() - balance_id1,
            fees
        );
        assert_eq!(
            <Test as Trait>::Currency::free_balance(&val_id2).saturated_into::<u64>() - balance_id2,
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

        for id in vec![val_id1, val_id2] {
            PoAModule::add_validator_(id, false).unwrap();
        }
        PoAModule::update_active_validators_if_needed();

        PoAModule::update_details_on_epoch_change(1, 1, 2);

        // Epoch details, i.e. `Epoch` and `Epochs` should be updated
        assert_eq!(PoAModule::epoch(), 1);
        assert_eq!(PoAModule::get_epoch_detail(1), (2, 1, None));

        // No blocks authored
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id1), 0);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id2), 0);

        // After val_id1 authors
        PoAModule::increment_current_epoch_block_count(val_id1);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id1), 1);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id2), 0);

        // After val_id2 authors
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id1), 1);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id2), 1);

        // They author few more blocks
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id1), 3);
        assert_eq!(PoAModule::get_block_count_for_validator(1, &val_id2), 3);

        // Epoch changes, slot becomes 7
        PoAModule::update_details_on_epoch_change(2, 7, 2);
        // Epoch details, i.e. `Epoch` and `Epochs` should be updated
        assert_eq!(PoAModule::epoch(), 2);
        assert_eq!(PoAModule::get_epoch_detail(2), (2, 7, None));
        // Previous epoch's end marked
        assert_eq!(PoAModule::get_epoch_detail(1), (2, 1, Some(6)));

        // They author few more blocks
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        PoAModule::increment_current_epoch_block_count(val_id1);
        PoAModule::increment_current_epoch_block_count(val_id2);
        assert_eq!(PoAModule::get_block_count_for_validator(2, &val_id1), 2);
        assert_eq!(PoAModule::get_block_count_for_validator(2, &val_id2), 2);
    });
}
