use super::{CheqdAddress, Config, Error, Event, Pallet as Migration, SubstrateWeight, WeightInfo};
use crate::mock::*;
use frame_support::{assert_noop, assert_ok, dispatch::WithPostDispatchInfo, traits::Get};
use frame_system::RawOrigin;

const ALICE: u64 = 1;
const ALICE_BALANCE: u64 = 100_000_000;

fn assert_event(expected_event: Event<Test>) {
    let events = System::events();
    let system_event = expected_event.into();

    assert!(events.iter().any(|event| &event.event == &system_event));
}

#[test]
fn migrate_works_for_valid_address() {
    new_test_ext().execute_with(|| {
        Balances::set_balance(RawOrigin::Root.into(), ALICE, ALICE_BALANCE, 100).unwrap();
        System::set_block_number(System::block_number() + 1); //otherwise event won't be registered.
        let cheqd_recipient = "cheqd1fktkf9nsj625jkxz7r7gmryna6uy8y2pptang4".to_string();
        assert_ok!(Migration::<Test>::migrate(
            Origin::signed(ALICE),
            cheqd_recipient.clone()
        ));
        assert_eq!(
            <Test as Config>::Currency::free_balance(&<Test as Config>::BurnDestination::get()),
            ALICE_BALANCE
        );
        assert_eq!(<Test as Config>::Currency::free_balance(&ALICE), 0);
        assert_eq!(<Test as Config>::Currency::reserved_balance(&ALICE), 100);
        assert_event(Event::Migrated {
            dock_account: ALICE,
            cheqd_account: CheqdAddress::new::<Test>(cheqd_recipient).unwrap(),
            dock_tokens_amount: ALICE_BALANCE,
            accepted_terms_and_conditions: true,
        });
    })
}

#[test]
fn migrate_fails_for_address_without_cheqd_prefix() {
    new_test_ext().execute_with(|| {
        let invalid_destination = "1umz9zuh47y8qqlhmntq9yvdwrh4w47jf8nuecc".to_string();
        assert_noop!(
            Migration::<Test>::migrate(Origin::signed(ALICE), invalid_destination),
            Error::<Test>::AddressMustBeValidBech32.with_weight(SubstrateWeight::<
                <Test as frame_system::Config>::DbWeight,
            >::migrate_validation_failure(
            ))
        );
        let invalid_destination = "cosmos12zddgw36trnvwm4s3x0etjd86r4lgqdthrzjdk".to_string();
        assert_noop!(
            Migration::<Test>::migrate(Origin::signed(ALICE), invalid_destination),
            Error::<Test>::AddressMustStartWithCheqd.with_weight(SubstrateWeight::<
                <Test as frame_system::Config>::DbWeight,
            >::migrate_validation_failure(
            ))
        );
    })
}

#[test]
fn migrate_fails_for_address_wrong_length() {
    new_test_ext().execute_with(|| {
        let invalid_destination = "cheqd123".to_string();
        assert_noop!(
            Migration::<Test>::migrate(Origin::signed(ALICE), invalid_destination),
            Error::<Test>::AddressMustBeValidBech32.with_weight(SubstrateWeight::<
                <Test as frame_system::Config>::DbWeight,
            >::migrate_validation_failure(
            ))
        );
    })
}

#[test]
fn migrate_fails_for_address_invalid_base32() {
    new_test_ext().execute_with(|| {
        let invalid_destination = "cheqd1Amz9zuh47y8qqlhmntq9yvdwrh4w47jf8nuecc".to_string();
        assert_noop!(
            Migration::<Test>::migrate(Origin::signed(ALICE), invalid_destination),
            Error::<Test>::AddressMustBeValidBech32.with_weight(SubstrateWeight::<
                <Test as frame_system::Config>::DbWeight,
            >::migrate_validation_failure(
            ))
        );
    })
}

#[test]
fn migrate_does_not_execute_when_balances_zero() {
    new_test_ext().execute_with(|| {
        let destination = "cheqd1fktkf9nsj625jkxz7r7gmryna6uy8y2pptang4".to_string();
        assert_noop!(
            Migration::<Test>::migrate(Origin::signed(99), destination),
            Error::<Test>::BalanceIsZero
        );
    })
}
