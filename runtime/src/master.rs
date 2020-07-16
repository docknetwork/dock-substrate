//! Simulates a multisig root account.
//!
//! Each substrate runtime module declares a "Call" enum. The "Call" enum is created by the
//! `decl_module!` macro. Let's call that enum `module::Call`. Each `module::Call` is a reified
//! invocation of one of the modules methods. The `module::Call` for this:
//!
//! ```
//! # mod a {
//! # use frame_support::{decl_module, dispatch::DispatchResult};
//! # type Foo = ();
//! # type Bar = ();
//! # trait Trait: system::Trait {}
//! decl_module! {
//!     pub struct Module<T: Trait> for enum Call where origin: T::Origin {
//!         #[weight = 100_000]
//!         pub fn frob(origin, foo: Foo) -> DispatchResult { Ok(()) }
//!         #[weight = 100_000]
//!         pub fn unfrob(origin, foo: Foo, bar: Bar) -> DispatchResult { Ok(()) }
//!     }
//! }
//! # }
//! ```
//!
//! looks something like this:
//!
//! ```
//! # type Foo = ();
//! # type Bar = ();
//! enum Call {
//!     frob(Foo),
//!     unfrob(Foo, Bar),
//! }
//! ```
//!
//! The `construct_runtime!` macro assembles the calls from all the included modules into a
//! single "super call". The name of this enum is also "Call", but let's refer to it as
//! `runtime::Call`. A `runtime::Call` looks something like this:
//!
//! ```
//! # mod module1 { pub type Call = (); }
//! # mod module2 { pub type Call = (); }
//! # mod module3 { pub type Call = (); }
//! enum Call {
//!    Module1(module1::Call),
//!    Module2(module2::Call),
//!    Module3(module3::Call),
//! }
//! ```
//!
//! This module allows members of the group called Master to "vote" on a `runtime::Call` (a
//! proposal) using cryptographic signatures. The votes, along with the proposed `runtime::Call`
//! are submitted in a single transaction. If enough valid votes endorse the proposal, the proposal
//! is run as root. If the running the proposal as root succeeds, a new round of voting is started.
//!
//! Each member of Master is idenitified by their dock DID.
//!
//! This module implement partial replay protection to prevent unauthorized resubmission of votes
//! from previous rounds.

// REVIEWER: the Membership type is capable of soundly representing
//           a superset of revoke::Policy::OneOf. Should we unify the
//           types? It would make the revoke module more flexible and
//           would be code re-use.
// ```
// enum Policy {
//     Vote(Membership),
// }
// ```

use crate::{
    did::{Did, DidSignature},
    StateChange,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use core::default::Default;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Dispatchable},
    ensure, Parameter,
};
use system::{ensure_root, ensure_signed};

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct Vote {
    /// The serialized Call to be run as root.
    // REVIEWER: The type of this call is erased becuase vote needs to go in StateChange
    //           Adding vote to StateChange requires Statechange to be generic over either
    //           master::Call or generic over T, where T: master::Trait .
    //           Turns out the coupling I introduced by requesting a StateChange enum has
    //           come back to bite me becuase a generic StateChange is a whole can of worms
    //           that spans multiple modules. Coupling modules, for example, Revoke to Master,
    //           which is innapropriate.
    //
    //           By erasing the type of Call we remove polkadotjs's ability to print "Vote" in
    //           a human comprehesible way.
    proposal: Vec<u8>,
    /// The round for which the vote is to be valid
    round_no: u64,
}

/// Proof of authorization by Master.
pub type PMAuth = BTreeMap<Did, DidSignature>;

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Membership {
    pub members: BTreeSet<Did>,
    pub vote_requirement: u64,
}

impl Default for Membership {
    fn default() -> Self {
        Membership {
            members: BTreeSet::new(),
            vote_requirement: 1,
        }
    }
}

pub trait Trait: system::Trait + crate::did::Trait
where
    <Self as system::Trait>::AccountId: Ord,
{
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The dispatchable that master may call as Root. It is possible to use another type here, but
    /// it's expectected that your runtime::Call will be used.
    type Call: Parameter + Dispatchable<Origin = Self::Origin>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Master {
        pub Members config(members): Membership;
        pub Round: u64;
    }
}

decl_error! {
    pub enum MasterError for Module<T: Trait> {
        /// The account used to submit this vote is not a member of Master.
        NotMember,
        /// This proposal does not yet have enough votes to be executed.
        InsufficientVotes,
        /// One of the signatures provided is invalid.
        /// Hint: Is everyone voting for the current round?
        BadSig,
    }
}

decl_event! {
    pub enum Event<T>
    where
        <T as Trait>::Call
    {
        /// A proposal succeeded and was executed. The dids listed are the members whose votes were
        /// used as proof of authorization. The hash of the proposal is provided.
        Executed(Vec<Did>, Box<Call>),
        /// The membership of Master has changed.
        UnderNewOwnership,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = MasterError<T>;

        fn deposit_event() = default;

        /// Execute a proposal that has received enough votes. The proposal is a serialized Call.
        /// This function can be freely called by anyone, even someone who is not a member of
        /// Master.
        ///
        /// After a sucessful execution, the current round of voted is cleared and round number is increased.
        #[weight = 0]
        pub fn execute(
            origin,
            proposal: Box<<T as Trait>::Call>,
            auth: PMAuth,
        ) -> DispatchResult {
            Module::<T>::execute_(origin, proposal, auth)
        }

        /// Root-only. Sets the members and vote requirement for master. Increases the round number
        /// and removes the votes for the prevous round.
        ///
        /// ```
        /// # use dock_testnet_runtime::master::Membership;
        /// # extern crate alloc;
        /// # use alloc::collections::BTreeSet;
        /// #
        /// // Setting the following membership will effectively dissolve the master account.
        /// Membership {
        ///     members: BTreeSet::new(),
        ///     vote_requirement: 1,
        /// };
        /// ```
        ///
        /// Setting the vote requirement to zero grants free and unrestricted root access to
        /// all accounts. It is not recomended to set the vote requirement to zero on a
        /// production chain.
        #[weight = 0]
        pub fn set_members(
            origin,
            membership: Membership
        ) -> DispatchResult {
            Module::<T>::set_members_(origin, membership)
        }
    }
}

impl<T: Trait> Module<T> {
    pub fn execute_(
        origin: T::Origin,
        proposal: Box<<T as Trait>::Call>,
        auth: PMAuth,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        let membership = Members::get();
        let payload = StateChange::MasterVote(Vote {
            proposal: proposal.encode(),
            round_no: Round::get(),
        })
        .encode();
        ensure!(
            auth.len() as u64 >= membership.vote_requirement,
            MasterError::<T>::InsufficientVotes,
        );
        ensure!(
            auth.keys().all(|k| membership.members.contains(k)),
            MasterError::<T>::NotMember,
        );
        for (did, sig) in auth.iter() {
            let valid = crate::did::Module::<T>::verify_sig_from_did(sig, &payload, did)?;
            ensure!(valid, MasterError::<T>::BadSig);
        }

        // check/execute
        proposal
            .clone()
            .dispatch(system::RawOrigin::Root.into())
            .map_err(|e| e.error)?;

        // execute
        Round::mutate(|round| {
            *round += 1;
        });

        // events
        Self::deposit_event(RawEvent::Executed(
            auth.keys().cloned().collect(),
            proposal.into(),
        ));

        Ok(())
    }

    pub fn set_members_(origin: T::Origin, membership: Membership) -> DispatchResult {
        ensure_root(origin)?;

        // execute
        Members::set(membership);
        Round::mutate(|round| {
            *round += 1;
        });

        // events
        Self::deposit_event(RawEvent::UnderNewOwnership);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_common::*;
    type MasterMod = crate::master::Module<Test>;
    use alloc::collections::BTreeMap;
    use sp_core::H256;

    /// set_members() may be called from within execute()
    /// that should cause round number to be incremented twice
    #[test]
    fn execute_set_members() {
        ext().execute_with(|| {
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let new_members = Membership {
                members: set(&[]),
                vote_requirement: 1,
            };
            let call = TestCall::Master(Call::set_members(new_members.clone()));
            assert_eq!(Round::get(), 0);
            MasterMod::execute(Origin::signed(0), Box::new(call), map(&[])).unwrap();
            assert_eq!(Members::get(), new_members);
            assert_eq!(Round::get(), 2);
        });
    }

    /// After a sucessful execution the round number is increased.
    #[test]
    fn round_inc() {
        ext().execute_with(|| {
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            assert_eq!(Round::get(), 0);
            MasterMod::execute(Origin::signed(0), Box::new(call), map(&[])).unwrap();
            assert_eq!(Round::get(), 1);
        });
    }

    /// Running a command that requires a non-root origin fails.
    #[test]
    fn non_root_impossible() {
        ext().execute_with(|| {
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let call = TestCall::System(system::Call::<Test>::remark(vec![]));
            let err = MasterMod::execute(Origin::signed(0), Box::new(call), map(&[])).unwrap_err();
            assert_eq!(err, DispatchError::BadOrigin);
        });
    }

    #[test]
    fn test_events() {
        ext().execute_with(|| {
            MasterMod::set_members(
                Origin::ROOT,
                Membership {
                    members: set(&[]),
                    vote_requirement: 1,
                },
            )
            .unwrap();
            assert_eq!(events(), vec![Event::<Test>::UnderNewOwnership]);
        });

        ext().execute_with(|| {
            let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            MasterMod::execute(Origin::signed(1), Box::new(call.clone()), map(&[])).unwrap();
            assert_eq!(
                events(),
                vec![Event::<Test>::Executed(vec![], Box::new(call))]
            );
        });

        ext().execute_with(|| {
            // let (dida, didak) = newdid();
            // let (didb, _didbk) = newdid();
            // let (didc, didck) = newdid();
            // let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            // Members::set(Membership {
            //     members: set(&[dida, didb, didc]),
            //     vote_requirement: 2,
            // });
            // MasterMod::execute(Origin::signed(1), Box::new(call.clone()), map(&[])).unwrap();
            // assert_eq!(
            //     events(),
            //     vec![Event::<Test>::Executed(vec![dida, didc], Box::new(call))]
            // );
        });

        ext().execute_with(|| {
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let call = TestCall::Master(Call::<Test>::set_members(Membership {
                members: set(&[]),
                vote_requirement: 0,
            }));
            MasterMod::execute(Origin::signed(0), Box::new(call.clone()), map(&[])).unwrap();
            assert_eq!(
                events(),
                vec![
                    Event::<Test>::UnderNewOwnership,
                    Event::<Test>::Executed(vec![], Box::new(call)),
                ]
            );
        });
    }

    #[test]
    #[ignore]
    fn no_members() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[]),
            //     vote_requirement: 1,
            // });
            // let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            // let err = MasterMod::execute(Origin::signed(0), Box::new(call)).unwrap_err();
            // assert_eq!(err, MasterError::<Test>::NotMember.into());
        });
    }

    #[test]
    #[ignore]
    fn valid_call() {
        ext().execute_with(|| {
            // let kv = (vec![4; 200], vec![5; 200]);
            // let call = TestCall::System(system::Call::<Test>::set_storage(vec![kv.clone()]));
            // Members::set(Membership {
            //     members: set(&[1, 2, 3]),
            //     vote_requirement: 2,
            // });

            // assert_eq!(sp_io::storage::get(&kv.0), None);
            // MasterMod::vote(Origin::signed(3), 0, hash(&call)).unwrap();
            // MasterMod::vote(Origin::signed(1), 0, hash(&call)).unwrap();
            // MasterMod::execute(Origin::signed(0), Box::new(call.clone())).unwrap();
            // assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec()));
        });
    }

    #[test]
    #[ignore]
    fn all_members_vote() {
        ext().execute_with(|| {
            // let kv = (vec![4; 200], vec![5; 200]);
            // let call = TestCall::System(system::Call::<Test>::set_storage(vec![kv.clone()]));
            // Members::set(Membership {
            //     members: set(&[1, 2, 3]),
            //     vote_requirement: 2,
            // });
            // MasterMod::vote(Origin::signed(1), 0, hash(&call)).unwrap();
            // MasterMod::vote(Origin::signed(2), 0, hash(&call)).unwrap();
            // MasterMod::vote(Origin::signed(3), 0, hash(&call)).unwrap();
            // MasterMod::execute(Origin::signed(0), Box::new(call.clone())).unwrap();
        });
    }

    #[test]
    #[ignore]
    fn two_successful_rounds_of_voting() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[1, 2, 3]),
            //     vote_requirement: 2,
            // });

            // {
            //     let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            //     MasterMod::vote(Origin::signed(3), 0, hash(&call)).unwrap();
            //     MasterMod::vote(Origin::signed(1), 0, hash(&call)).unwrap();
            //     MasterMod::execute(Origin::signed(0), Box::new(call.clone())).unwrap();
            // }

            // {
            //     let call = TestCall::System(system::Call::<Test>::set_storage(vec![]));
            //     MasterMod::vote(Origin::signed(3), 1, hash(&call)).unwrap();
            //     MasterMod::vote(Origin::signed(1), 1, hash(&call)).unwrap();
            //     MasterMod::execute(Origin::signed(0), Box::new(call.clone())).unwrap();
            // }
        });
    }

    #[test]
    #[ignore]
    fn revote() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[0]),
            //     vote_requirement: 1,
            // });
            // assert_eq!(Votes::<Test>::get(), map(&[]));
            // MasterMod::vote(Origin::signed(0), 0, H256([0; 32])).unwrap();
            // assert_eq!(Votes::<Test>::get(), map(&[(0u64, H256([0; 32]))]));
            // MasterMod::vote(Origin::signed(0), 0, H256([1; 32])).unwrap();
            // assert_eq!(Votes::<Test>::get(), map(&[(0u64, H256([1; 32]))]));
        });
    }

    #[test]
    #[ignore]
    fn err_bad_sig() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[1]),
            //     vote_requirement: 1,
            // });
            // let wrong_round = 1;
            // assert_ne!(wrong_round, Round::get());
            // let err = MasterMod::vote(Origin::signed(1), wrong_round, H256([0; 32])).unwrap_err();
            // assert_eq!(err, MasterError::<Test>::WrongRound.into());
        });
    }

    #[test]
    #[ignore]
    fn err_not_member() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[1]),
            //     vote_requirement: 1,
            // });
            // let wrong_voter = 0;
            // let err = MasterMod::vote(Origin::signed(wrong_voter), 0, H256([0; 32])).unwrap_err();
            // assert_eq!(err, MasterError::<Test>::NotMember.into());
        });
    }

    #[test]
    #[ignore]
    fn replay_protec() {
        ext().execute_with(|| {
            // Members::set(Membership {
            //     members: set(&[1]),
            //     vote_requirement: 1,
            // });
            // MasterMod::vote(Origin::signed(1), 0, H256([0; 32])).unwrap();
            // let err = MasterMod::vote(Origin::signed(1), 0, H256([0; 32])).unwrap_err();
            // assert_eq!(err, MasterError::<Test>::RepeatedVote.into());
        });
    }

    #[test]
    #[ignore]
    fn err_insufficient_votes() {
        ext().execute_with(|| {
            // let kv = (vec![4; 200], vec![5; 200]);
            // let call = TestCall::System(system::Call::<Test>::set_storage(vec![kv.clone()]));
            // Members::set(Membership {
            //     members: set(&[1, 2, 3]),
            //     vote_requirement: 2,
            // });
            // MasterMod::vote(Origin::signed(3), 0, hash(&call)).unwrap();
            // let err = MasterMod::execute(Origin::signed(0), Box::new(call.clone())).unwrap_err();
            // assert_eq!(err, MasterError::<Test>::InsufficientVotes.into());
        });
    }

    fn events() -> Vec<Event<Test>> {
        system::Module::<Test>::events()
            .iter()
            .map(|event_record| {
                let system::EventRecord::<TestEvent, sp_core::H256> {
                    phase,
                    event,
                    topics,
                } = event_record;
                assert_eq!(phase, &system::Phase::Initialization);
                assert_eq!(topics, &vec![]);
                match event {
                    TestEvent::Master(e) => e.clone(),
                    _ => panic!(),
                }
            })
            .collect()
    }

    fn map<K: Ord, V>(slice: &[(K, V)]) -> BTreeMap<K, V>
    where
        (K, V): Clone,
    {
        slice.iter().cloned().collect()
    }

    fn set<E: Clone + Ord>(slice: &[E]) -> BTreeSet<E> {
        slice.iter().cloned().collect()
    }
}
