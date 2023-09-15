use codec::Encode;
use sp_runtime::{traits::Get, BoundedBTreeSet};
// Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `tests::common`
use super::{
    Call as MasterCall, Error, Event, MasterVoteRaw, Members, Membership, PhantomData, Round,
};
use crate::{
    revoke::tests::{check_nonce_increase, get_nonces, get_pauth},
    tests::common::*,
};

use frame_support::weights::Weight;
use frame_system;
use sp_core::H256;

// XXX: To check both `execute` and `execute_unchecked_weight`, we can simply test `execute_` but
// thats less future proof in theory

/// set_members() may be called from within execute()
/// that should cause round number to be incremented twice
#[test]
fn execute_set_members() {
    ext().execute_with(|| {
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        let new_members = Membership {
            members: set(&[newdid().0]),
            vote_requirement: 1,
        };
        let call = Call::MasterMod(MasterCall::set_members {
            membership: new_members.clone(),
        });
        assert_eq!(Round::<Test>::get(), 0);
        MasterMod::execute(Origin::signed(0), Box::new(call), vec![]).unwrap();
        assert_eq!(Members::get(), new_members);
        assert_eq!(Round::<Test>::get(), 2);
    });
}

/// After a successful execution the round number is increased.
#[test]
fn round_inc() {
    ext().execute_with(|| {
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        assert_eq!(Round::<Test>::get(), 0);
        MasterMod::execute(Origin::signed(0), Box::new(call.clone()), vec![]).unwrap();
        assert_eq!(Round::<Test>::get(), 1);
        MasterMod::execute_unchecked_weight(
            Origin::signed(0),
            Box::new(call),
            vec![],
            Weight::from_ref_time(1),
        )
        .unwrap();
        assert_eq!(Round::<Test>::get(), 2);
    });
}

/// Running a command that requires a non-root origin fails.
/*#[test]
fn non_root_impossible() {
    ext().execute_with(|| {
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        let call = Call::System(frame_system::Call::<Test>::remark(vec![]));
        let err =
            MasterMod::execute(Origin::signed(0), Box::new(call), vec![])
                .unwrap_err();
        assert_eq!(err.error, DispatchError::BadOrigin);
    });
}*/

#[test]
fn test_events() {
    ext().execute_with(|| {
        MasterMod::set_members(
            frame_system::RawOrigin::Root.into(),
            Membership {
                members: set(&[newdid().0]),
                vote_requirement: 1,
            },
        )
        .unwrap();
        assert_eq!(master_events(), vec![Event::<Test>::UnderNewOwnership]);
    });

    ext().execute_with(|| {
        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        MasterMod::execute(Origin::signed(0), Box::new(call.clone()), vec![]).unwrap();
        assert_eq!(
            master_events(),
            vec![Event::<Test>::Executed(vec![], Box::new(call))]
        );
    });

    ext().execute_with(|| {
        run_to_block(10);

        let (dida, didak) = newdid();
        let (didb, _didbk) = newdid();
        let (didc, didck) = newdid();

        Members::<Test>::set(Membership {
            members: set(&[dida, didb, didc]),
            vote_requirement: 2,
        });

        run_to_block(15);

        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };

        let signers = [(dida, &didak), (didc, &didck)];

        let old_nonces = get_nonces(&signers);

        let pauth = get_pauth(&sc, &signers);
        MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();
        check_nonce_increase(old_nonces, &signers);
        assert_eq!(
            master_events(),
            vec![Event::<Test>::Executed(
                sorted(vec![dida, didc]),
                Box::new(call)
            )]
        );
    });

    ext().execute_with(|| {
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        let call = Call::MasterMod(MasterCall::set_members {
            membership: Membership {
                members: set(&[newdid().0]),
                vote_requirement: 1,
            },
        });
        MasterMod::execute(Origin::signed(0), Box::new(call.clone()), vec![]).unwrap();
        assert_eq!(
            master_events(),
            vec![
                Event::<Test>::UnderNewOwnership,
                Event::<Test>::Executed(vec![], Box::new(call)),
            ]
        );
    });

    /*ext().execute_with(|| {
        let call = Call::System(frame_system::Call::<Test>::remark(vec![]));
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 0,
        });
        let res = MasterMod::execute(
            Origin::signed(0),
            Box::new(call.clone()),
            vec![],
        );
        assert!(res.is_err());
        assert_eq!(
            master_events(),
            vec![Event::<Test>::ExecutionFailed(
                vec![],
                Box::new(call),
                DispatchError::BadOrigin
            )]
        );
    });*/
}

#[test]
fn no_members() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };
        Members::<Test>::set(Membership {
            members: set(&[]),
            vote_requirement: 1,
        });

        let pauth = get_pauth(&sc, &[(dida, &didak)]);

        let err = MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap_err();
        assert_eq!(err, Error::<Test>::NotMember.into());
    });
}

#[test]
fn valid_call() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        let (didb, _didbk) = newdid();
        let (didc, didck) = newdid();
        let kv = (vec![4; 200], vec![5; 200]);
        let call = Call::System(frame_system::Call::<Test>::set_storage {
            items: vec![kv.clone()],
        });
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };
        Members::<Test>::set(Membership {
            members: set(&[dida, didb, didc]),
            vote_requirement: 2,
        });

        assert_eq!(sp_io::storage::get(&kv.0), None);

        let signers = [(dida, &didak), (didc, &didck)];

        let old_nonces = get_nonces(&signers);

        let pauth = get_pauth(&sc, &signers);

        MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap();
        assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec().into()));
        check_nonce_increase(old_nonces, &signers);
    });
}

#[test]
fn all_members_vote() {
    ext().execute_with(|| {
        run_to_block(10);

        let (dida, didak) = newdid();
        let (didb, didbk) = newdid();
        let (didc, didck) = newdid();

        let kv = (vec![4; 200], vec![5; 200]);
        let call = Call::System(frame_system::Call::<Test>::set_storage {
            items: vec![kv.clone()],
        });

        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };
        Members::<Test>::set(Membership {
            members: set(&[dida, didb, didc]),
            vote_requirement: 3,
        });

        let signers = [(dida, &didak), (didb, &didbk), (didc, &didck)];

        let old_nonces = get_nonces(&signers);

        let pauth = get_pauth(&sc, &signers);

        MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap();
        assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec().into()));
        check_nonce_increase(old_nonces, &signers);
    });
}

#[test]
fn two_successful_rounds_of_voting() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        let (didb, didbk) = newdid();
        let (didc, didck) = newdid();
        Members::<Test>::set(Membership {
            members: set(&[dida, didb, didc]),
            vote_requirement: 2,
        });

        {
            let kv = (vec![4; 200], vec![5; 200]);
            let call = Call::System(frame_system::Call::<Test>::set_storage {
                items: vec![kv.clone()],
            });

            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: 0,
            };

            let signers = [(dida, &didak), (didc, &didck)];

            let old_nonces = get_nonces(&signers);

            let pauth = get_pauth(&sc, &signers);

            MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap();
            assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec().into()));
            check_nonce_increase(old_nonces, &signers);
        }

        {
            let kv = (vec![6; 200], vec![9; 200]);
            let call = Call::System(frame_system::Call::<Test>::set_storage {
                items: vec![kv.clone()],
            });

            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: 1,
            };

            let signers = [(dida, &didak), (didb, &didbk)];

            let old_nonces = get_nonces(&signers);

            let pauth = get_pauth(&sc, &signers);

            MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap();
            assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec().into()));
            check_nonce_increase(old_nonces, &signers);
        }
    });
}

#[test]
fn err_bad_sig() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        let (didb, _didbk) = newdid();
        let (didc, didck) = newdid();
        Members::<Test>::set(Membership {
            members: set(&[dida, didb]),
            vote_requirement: 1,
        });
        let call = Box::new(Call::System(frame_system::Call::<Test>::set_storage {
            items: vec![],
        }));
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: 0,
        };

        {
            // signing with wrong key
            let pauth = get_pauth(&sc, &[(didb, &didak)]);
            let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
            assert_eq!(err, Error::<Test>::BadSig.into());
        }

        {
            // signing with wrong key, not in member set
            let pauth = get_pauth(&sc, &[(didc, &didck)]);
            let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
            assert_eq!(err, Error::<Test>::NotMember.into());
        }

        {
            // wrong payload
            let sc = crate::revoke::RemoveRegistryRaw {
                registry_id: RGA,
                _marker: PhantomData,
            };
            let pauth = get_pauth(&sc, &[(dida, &didak)]);
            let err = MasterMod::execute(Origin::signed(0), call, pauth).unwrap_err();
            assert_eq!(err, Error::<Test>::BadSig.into());
        }
    });
}

#[test]
fn err_not_member() {
    ext().execute_with(|| {
        let (dida, _didak) = newdid();
        let (didc, didck) = newdid();
        Members::<Test>::set(Membership {
            members: set(&[dida]),
            vote_requirement: 1,
        });
        let call = Box::new(Call::System(frame_system::Call::<Test>::set_storage {
            items: vec![],
        }));
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: 0,
        };
        let pauth = get_pauth(&sc, &[(didc, &didck)]);
        let err = MasterMod::execute(Origin::signed(0), call, pauth).unwrap_err();
        assert_eq!(err, Error::<Test>::NotMember.into());
    });
}

#[test]
fn replay_protec() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        Members::<Test>::set(Membership {
            members: set(&[dida]),
            vote_requirement: 1,
        });
        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };
        let pauth = get_pauth(&sc, &[(dida, &didak)]);

        MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();

        let pauth = get_pauth(&sc, &[(dida, &didak)]);
        let err = MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap_err();
        assert_eq!(err, Error::<Test>::BadSig.into());
    });
}

#[test]
fn err_insufficient_votes() {
    ext().execute_with(|| {
        let (dida, didak) = newdid();
        let (didb, _didbk) = newdid();
        let call = Call::System(frame_system::Call::<Test>::set_storage { items: vec![] });
        let sc = MasterVoteRaw {
            _marker: PhantomData,
            proposal: call.encode(),
            round_no: Round::<Test>::get(),
        };
        Members::<Test>::set(Membership {
            members: set(&[dida, didb]),
            vote_requirement: 2,
        });

        let pauth = get_pauth(&sc, &[(dida, &didak)]);
        let err = MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap_err();
        assert_eq!(err, Error::<Test>::InsufficientVotes.into());
    });
}

#[test]
fn err_zero_vote_requirement() {
    ext().execute_with(|| {
        for m in [
            Membership {
                members: set(&[]),
                vote_requirement: 0,
            },
            Membership {
                members: set(&[newdid().0]),
                vote_requirement: 0,
            },
        ]
        .iter()
        .cloned()
        {
            let err = MasterMod::set_members(Origin::root(), m).unwrap_err();
            assert_eq!(err, Error::<Test>::ZeroVoteRequirement.into());
        }
    });
}

#[test]
fn err_vote_requirement_to_high() {
    ext().execute_with(|| {
        for m in [
            Membership {
                members: set(&[]),
                vote_requirement: 1,
            },
            Membership {
                members: set(&[newdid().0]),
                vote_requirement: 2,
            },
            Membership {
                members: set(&[newdid().0]),
                vote_requirement: 3,
            },
            Membership {
                members: set(&[newdid().0]),
                vote_requirement: u64::MAX,
            },
        ]
        .iter()
        .cloned()
        {
            let err = MasterMod::set_members(Origin::root(), m).unwrap_err();
            assert_eq!(err, Error::<Test>::VoteRequirementTooHigh.into());
        }
    });
}

fn master_events() -> Vec<Event<Test>> {
    frame_system::Pallet::<Test>::events()
        .iter()
        .filter_map(|event_record| {
            let frame_system::EventRecord::<TestEvent, H256> {
                phase,
                event,
                topics: _,
            } = event_record;
            assert_eq!(phase, &frame_system::Phase::Initialization);
            match event {
                TestEvent::Master(e) => Some(e.clone()),
                _ => None,
            }
        })
        .collect()
}

fn set<E: Clone + Ord, Size: Get<u32>>(slice: &[E]) -> BoundedBTreeSet<E, Size> {
    use sp_runtime::traits::TryCollect;
    slice.iter().cloned().try_collect().unwrap()
}

fn sorted<T: Ord>(mut inp: Vec<T>) -> Vec<T> {
    inp.sort();
    inp
}
