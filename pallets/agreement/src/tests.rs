use super::{Error, Event, Pallet as Remark};
use crate::mock::*;
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;
use sp_runtime::DispatchError;

#[test]
fn generates_event() {
    new_test_ext().execute_with(|| {
        let text = "Hello world".to_string();
        let url = Some("Test url".to_string());

        System::set_block_number(System::block_number() + 1); //otherwise event won't be registered.
        assert_ok!(Remark::<Test>::agree(
            RawOrigin::Root.into(),
            text.clone(),
            url.clone()
        ));

        let events = System::events();
        // this one we create as we expect it
        let system_event: <Test as frame_system::Config>::Event = Event::Agreed {
            on: text.clone(),
            url,
        }
        .into();
        // this one we actually go into the system pallet and get the last event
        // because we know its there from block +1
        let frame_system::EventRecord { event, .. } = &events[events.len() - 1];
        assert_eq!(event, &system_event);
    });
}

#[test]
fn does_not_agree_on_empty() {
    new_test_ext().execute_with(|| {
        System::set_block_number(System::block_number() + 1); //otherwise event won't be registered.
        assert_noop!(
            Remark::<Test>::agree(RawOrigin::Root.into(), "".to_string(), None),
            Error::<Test>::EmptyAgreement
        );
        assert_noop!(
            Remark::<Test>::agree(
                RawOrigin::Root.into(),
                "abc".to_string(),
                Some("".to_string())
            ),
            Error::<Test>::EmptyUrl
        );
        assert!(System::events().is_empty());
    });
}

#[test]
fn cant_be_called_not_by_root() {
    new_test_ext().execute_with(|| {
        let caller = 1;
        let text = "Invalid".to_string();
        System::set_block_number(System::block_number() + 1); //otherwise event won't be registered.
        assert_noop!(
            Remark::<Test>::agree(RawOrigin::Signed(caller).into(), text.clone(), None),
            DispatchError::BadOrigin
        );
        assert_noop!(
            Remark::<Test>::agree(RawOrigin::None.into(), text, None),
            DispatchError::BadOrigin
        );
        assert!(System::events().is_empty());
    });
}
