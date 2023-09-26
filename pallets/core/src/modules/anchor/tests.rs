use super::{Anchors, Error, Event};
use sp_runtime::traits::Hash;

use crate::tests::common::*;
use sp_core::H256;

#[test]
fn deploy_and_check() {
    ext().execute_with(|| {
        let bs = random_bytes(32);
        let h = <Test as frame_system::Config>::Hashing::hash(&bs);
        assert!(Anchors::<Test>::get(h).is_none());
        AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap();
        assert!(Anchors::<Test>::get(h).is_some());
    });
}

#[test]
fn deploy_twice_error() {
    ext().execute_with(|| {
        let bs = random_bytes(32);
        AnchorMod::deploy(Origin::signed(ABBA), bs.clone()).unwrap();
        let err = AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap_err();
        assert_eq!(err, Error::<Test>::AnchorExists.into());
    });
}

#[test]
fn deploy_and_observe_event() {
    ext().execute_with(|| {
        let bs = random_bytes(32);
        let h = <Test as frame_system::Config>::Hashing::hash(&bs);
        AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap();
        assert_eq!(
            &anchor_events(),
            &[Event::<Test>::AnchorDeployed(
                h,
                ABBA,
                System::block_number()
            )]
        );
    });
}

fn anchor_events() -> Vec<Event<Test>> {
    System::events()
        .iter()
        .filter_map(|event_record| {
            let frame_system::EventRecord::<TestEvent, H256> {
                phase,
                event,
                topics,
            } = event_record;
            assert_eq!(phase, &frame_system::Phase::Initialization);
            assert_eq!(topics, &vec![]);
            match event {
                TestEvent::Anchor(e) => Some(e.clone()),
                _ => None,
            }
        })
        .collect()
}
