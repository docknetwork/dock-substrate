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
//! # trait Config: frame_system::Config {}
//! decl_module! {
//!     pub struct Module<T: Config> for enum Call where origin: T::Origin {
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

use crate::revoke::PAuth;
use crate::util::WithNonce;
use crate::{did, did::Did, revoke::get_weight_for_pauth};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use core::default::Default;
use core::fmt::Debug;
use core::marker::PhantomData;

use frame_support::dispatch::PostDispatchInfo;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{
        DispatchError, DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo,
    },
    ensure,
    traits::{Get, UnfilteredDispatchable},
    weights::{GetDispatchInfo, Pays, RuntimeDbWeight, Weight},
    Parameter,
};
use frame_system::{self as system, ensure_root, ensure_signed};

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MasterVoteRaw<T> {
    /// The serialized Call to be run as root.
    proposal: Vec<u8>,
    /// The round for which the vote is to be valid
    round_no: u64,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _marker: PhantomData<T>,
}

crate::impl_action! {
    for (): MasterVoteRaw with 1 as len, () as target no_state_change
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Membership {
    pub members: BTreeSet<Did>,
    pub vote_requirement: u64,
}

pub type MasterVote<T> = WithNonce<T, MasterVoteRaw<T>>;

crate::impl_action_with_nonce! {
    for (): MasterVote with 1 as len, () as target
}

impl Default for Membership {
    fn default() -> Self {
        Membership {
            members: BTreeSet::new(),
            vote_requirement: 1,
        }
    }
}

// Minimum weight of Master's extrinsics. This is not based on any computation but only there to account for
// some in-memory operations
const MIN_WEIGHT: Weight = 10_000;

/// Minimum weight for master's extrinsics. Considers cost of signature verification and update to round no
fn get_min_weight_for_execute<T: frame_system::Config>(
    auth: &PAuth<T>,
    db_weights: RuntimeDbWeight,
) -> Weight {
    MIN_WEIGHT + get_weight_for_pauth(&auth, db_weights) + db_weights.reads_writes(1, 1)
}

pub trait Config: system::Config + crate::did::Config
where
    <Self as system::Config>::AccountId: Ord,
{
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;

    /// The dispatchable that master may call as Root. It is possible to use another type here, but
    /// it's expected that your runtime::Call will be used.
    /// Master's call should bypass any filter.
    type Call: Parameter + UnfilteredDispatchable<Origin = Self::Origin> + GetDispatchInfo;
}

decl_storage! {
    trait Store for Module<T: Config> as Master where T: Debug {
        pub Members: Membership;
        pub Round: u64;
    }
    add_extra_genesis {
        config(members): Membership;
        build(|slef: &Self| {
            debug_assert!(slef.members.vote_requirement != 0);
            debug_assert!(slef.members.vote_requirement <= slef.members.members.len() as u64);
            Members::set(slef.members.clone());
        })
    }
}

decl_error! {
    pub enum MasterError for Module<T: Config> where T: Debug {
        /// The account used to submit this vote is not a member of Master.
        NotMember,
        /// This proposal does not yet have enough votes to be executed.
        InsufficientVotes,
        /// One of the signatures provided is invalid.
        /// Hint: Is everyone voting for the current round?
        BadSig,
        /// A vote requirement of 0 would allow unresricted sudo access.
        ZeroVoteRequirement,
        /// There aren't enough members to satisfy that vote requirement.
        VoteRequirementTooHigh,
        IncorrectNonce,
    }
}

decl_event! {
    pub enum Event<T>
    where
        <T as Config>::Call
    {
        /// A proposal succeeded and was executed. The dids listed are the members whose votes were
        /// used as proof of authorization. The executed call is provided.
        Executed(Vec<Did>, Box<Call>),
        /// The membership of Master has changed.
        UnderNewOwnership,
        /// A proposal failed to execute
        ExecutionFailed(Vec<Did>, Box<Call>, DispatchError),
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        type Error = MasterError<T>;

        fn deposit_event() = default;

        /// Execute a proposal that has received enough votes. The proposal is a serialized Call.
        /// This function can be called by anyone, even someone who is not a member of Master.
        ///
        /// After a successful execution, the round number is increased.
        #[
            weight = (
             get_min_weight_for_execute(&auth, T::DbWeight::get()) + proposal.get_dispatch_info().weight,
             proposal.get_dispatch_info().class,
             proposal.get_dispatch_info().pays_fee,
            )
        ]
        pub fn execute(
            origin,
            proposal: Box<<T as Config>::Call>,
            auth: PAuth<T>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            // `execute_` will compute the weight
            Self::execute_(proposal, auth, None)
        }

        /// Does the same job as `execute` dispatchable but does not inherit the weight of the
        /// `Call` its wrapping but expects the caller to provide it
        #[
            weight = (
             get_min_weight_for_execute(&auth, T::DbWeight::get()) + _weight,
             proposal.get_dispatch_info().class,
             proposal.get_dispatch_info().pays_fee,
            )
        ]
        pub fn execute_unchecked_weight(
            origin,
            proposal: Box<<T as Config>::Call>,
            auth: PAuth<T>,
            _weight: Weight,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            let weight = get_min_weight_for_execute(&auth, T::DbWeight::get()) + _weight;

            // `execute_` won't compute the weight but use the given weight instead
            Self::execute_(proposal, auth, Some(weight))
        }

        /// Root-only. Sets the members and vote requirement for master. Increases the round number
        /// and removes the votes for the previous round.
        ///
        /// Since as a group members of master have root access, they will be able to call this
        /// function.
        ///
        /// A vote requirement of zero is not allowed and will result in an error.
        /// A vote requirement larger than the size of the member list is not allowed and will
        /// result in an error.
        #[weight = MIN_WEIGHT + T::DbWeight::get().reads_writes(1, 2)]
        pub fn set_members(
            origin,
            membership: Membership,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;

            Self::set_members_(membership)?;
            Ok(Pays::No.into())
        }
    }
}

impl<T: Config + Debug> Module<T> {
    /// Execute a call as Root origin after verifying signatures in `auth`. If `given_weight` is None,
    /// then it computes the weight by considering the cost of signature verification and cost of
    /// executing the call. If `given_weight` has a value then that is considered as weight.
    /// Note: The following can be misused to do recursive calls as the proposal can itself be call
    /// leading to `execute_` which will keep the cycle going. This can be prevented by incrementing
    /// the round no before dispatching the call in `proposal` and if the call throws error then
    /// decrementing the round no before returning the error.
    /// However, since this call is made by entities that not adversarial, the behavior is not dangerous
    /// in this case
    fn execute_(
        proposal: Box<<T as Config>::Call>,
        auth: PAuth<T>,
        given_weight: Option<Weight>,
    ) -> DispatchResultWithPostInfo {
        // check
        let membership = Members::get();
        ensure!(
            auth.auths.len() as u64 >= membership.vote_requirement,
            MasterError::<T>::InsufficientVotes,
        );
        ensure!(
            auth.auths.keys().all(|k| membership.members.contains(k)),
            MasterError::<T>::NotMember,
        );

        let new_payload = MasterVoteRaw {
            _marker: PhantomData,
            proposal: proposal.encode(),
            round_no: Round::get(),
        };

        let mut new_did_details = BTreeMap::new();

        // check each signature is valid over payload and signed by the claimed signer
        for (signer, (sig, nonce)) in &auth.auths {
            let nonce = *nonce;
            // Check if nonce is valid and increase it
            let mut did_detail = did::Module::<T>::onchain_did_details(&signer)?;
            did_detail
                .try_update(nonce)
                .map_err(|_| MasterError::<T>::IncorrectNonce)?;
            // Verify signature
            let valid = did::Module::<T>::verify_sig_from_auth_or_control_key(
                &WithNonce::new_with_nonce(new_payload.clone(), nonce),
                &sig,
            )?;
            ensure!(valid && (*signer == sig.did), MasterError::<T>::BadSig);
            new_did_details.insert(signer, did_detail);
        }

        // execute call and collect dispatch info to return
        let dispatch_result = proposal
            .clone()
            .dispatch_bypass_filter(system::RawOrigin::Root.into());

        // Update round (nonce)
        Round::mutate(|round| {
            *round += 1;
        });

        // The nonce of each DID must be updated
        for (signer, did_details) in new_did_details {
            did::Module::<T>::insert_did(*signer, did_details);
        }

        // Weight from dispatch's declaration. If dispatch does not return a weight in `PostDispatchInfo`,
        // then this weight is used.
        let dispatch_decl_weight = proposal.get_dispatch_info().weight;

        let authors = auth.auths.keys().cloned().collect();

        // If weight was not given in `given_weight`, look for weight of dispatch in `post_info`. If
        // `post_info` does not have weight, use weight from declaration. Also add minimum weight for execution
        let actual_weight = move |post_info: PostDispatchInfo| {
            given_weight.or_else(|| {
                Some(
                    post_info
                        .actual_weight
                        .unwrap_or_else(|| dispatch_decl_weight)
                        + get_min_weight_for_execute(&auth, T::DbWeight::get()),
                )
            })
        };

        // Log event for success or failure of execution
        match dispatch_result {
            Ok(post_dispatch_info) => {
                Self::deposit_event(RawEvent::Executed(authors, proposal));
                Ok(PostDispatchInfo {
                    actual_weight: actual_weight(post_dispatch_info),
                    pays_fee: post_dispatch_info.pays_fee,
                })
            }
            Err(e) => {
                Self::deposit_event(RawEvent::ExecutionFailed(authors, proposal, e.error));
                Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: actual_weight(e.post_info),
                        pays_fee: e.post_info.pays_fee,
                    },
                    error: e.error,
                })
            }
        }
    }

    fn set_members_(membership: Membership) -> DispatchResult {
        // check
        ensure!(
            membership.vote_requirement != 0,
            MasterError::<T>::ZeroVoteRequirement
        );
        ensure!(
            membership.vote_requirement <= membership.members.len() as u64,
            MasterError::<T>::VoteRequirementTooHigh
        );

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
    use codec::Encode;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
    use super::{
        Call as MasterCall, DispatchError, Event, MasterError, MasterVoteRaw, Members, Membership,
        PhantomData, Round,
    };
    use crate::revoke::tests::{check_nonce_increase, get_nonces, get_pauth};
    use crate::revoke::PAuth;
    use crate::test_common::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use frame_support::StorageValue;
    use frame_system as system;
    use sp_core::H256;

    // XXX: To check both `execute` and `execute_unchecked_weight`, we can simply test `execute_` but
    // thats less future proof in theory

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
                members: set(&[newdid().0]),
                vote_requirement: 1,
            };
            let call = Call::MasterMod(MasterCall::set_members(new_members.clone()));
            assert_eq!(Round::get(), 0);
            MasterMod::execute(Origin::signed(0), Box::new(call), PAuth { auths: map(&[]) })
                .unwrap();
            assert_eq!(Members::get(), new_members);
            assert_eq!(Round::get(), 2);
        });
    }

    /// After a successful execution the round number is increased.
    #[test]
    fn round_inc() {
        ext().execute_with(|| {
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            assert_eq!(Round::get(), 0);
            MasterMod::execute(
                Origin::signed(0),
                Box::new(call.clone()),
                PAuth { auths: map(&[]) },
            )
            .unwrap();
            assert_eq!(Round::get(), 1);
            MasterMod::execute_unchecked_weight(
                Origin::signed(0),
                Box::new(call),
                PAuth { auths: map(&[]) },
                1,
            )
            .unwrap();
            assert_eq!(Round::get(), 2);
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
            let call = Call::System(system::Call::<Test>::remark(vec![]));
            let err =
                MasterMod::execute(Origin::signed(0), Box::new(call), PAuth { auths: map(&[]) })
                    .unwrap_err();
            assert_eq!(err.error, DispatchError::BadOrigin);
        });
    }

    #[test]
    fn test_events() {
        ext().execute_with(|| {
            MasterMod::set_members(
                system::RawOrigin::Root.into(),
                Membership {
                    members: set(&[newdid().0]),
                    vote_requirement: 1,
                },
            )
            .unwrap();
            assert_eq!(master_events(), vec![Event::<Test>::UnderNewOwnership]);
        });

        ext().execute_with(|| {
            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            MasterMod::execute(
                Origin::signed(0),
                Box::new(call.clone()),
                PAuth { auths: map(&[]) },
            )
            .unwrap();
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

            Members::set(Membership {
                members: set(&[dida, didb, didc]),
                vote_requirement: 2,
            });

            run_to_block(15);

            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
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
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let call = Call::MasterMod(MasterCall::set_members(Membership {
                members: set(&[newdid().0]),
                vote_requirement: 1,
            }));
            MasterMod::execute(
                Origin::signed(0),
                Box::new(call.clone()),
                PAuth { auths: map(&[]) },
            )
            .unwrap();
            assert_eq!(
                master_events(),
                vec![
                    Event::<Test>::UnderNewOwnership,
                    Event::<Test>::Executed(vec![], Box::new(call)),
                ]
            );
        });

        ext().execute_with(|| {
            let call = Call::System(system::Call::<Test>::remark(vec![]));
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 0,
            });
            let res = MasterMod::execute(
                Origin::signed(0),
                Box::new(call.clone()),
                PAuth { auths: map(&[]) },
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
        });
    }

    #[test]
    fn no_members() {
        ext().execute_with(|| {
            let (dida, didak) = newdid();
            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
            };
            Members::set(Membership {
                members: set(&[]),
                vote_requirement: 1,
            });

            let pauth = get_pauth(&sc, &[(dida, &didak)]);

            let err = MasterMod::execute(Origin::signed(0), Box::new(call), pauth).unwrap_err();
            assert_eq!(err, MasterError::<Test>::NotMember.into());
        });
    }

    #[test]
    fn valid_call() {
        ext().execute_with(|| {
            let (dida, didak) = newdid();
            let (didb, _didbk) = newdid();
            let (didc, didck) = newdid();
            let kv = (vec![4; 200], vec![5; 200]);
            let call = Call::System(system::Call::<Test>::set_storage(vec![kv.clone()]));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
            };
            Members::set(Membership {
                members: set(&[dida, didb, didc]),
                vote_requirement: 2,
            });

            assert_eq!(sp_io::storage::get(&kv.0), None);

            let signers = [(dida, &didak), (didc, &didck)];

            let old_nonces = get_nonces(&signers);

            let pauth = get_pauth(&sc, &signers);

            MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();
            assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec()));
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
            let call = Call::System(system::Call::<Test>::set_storage(vec![kv.clone()]));

            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
            };
            Members::set(Membership {
                members: set(&[dida, didb, didc]),
                vote_requirement: 3,
            });

            let signers = [(dida, &didak), (didb, &didbk), (didc, &didck)];

            let old_nonces = get_nonces(&signers);

            let pauth = get_pauth(&sc, &signers);

            MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();
            assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec()));
            check_nonce_increase(old_nonces, &signers);
        });
    }

    #[test]
    fn two_successful_rounds_of_voting() {
        ext().execute_with(|| {
            let (dida, didak) = newdid();
            let (didb, didbk) = newdid();
            let (didc, didck) = newdid();
            Members::set(Membership {
                members: set(&[dida, didb, didc]),
                vote_requirement: 2,
            });

            {
                let kv = (vec![4; 200], vec![5; 200]);
                let call = Call::System(system::Call::<Test>::set_storage(vec![kv.clone()]));

                let sc = MasterVoteRaw {
                    _marker: PhantomData,
                    proposal: call.encode(),
                    round_no: 0,
                };

                let signers = [(dida, &didak), (didc, &didck)];

                let old_nonces = get_nonces(&signers);

                let pauth = get_pauth(&sc, &signers);

                MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();
                assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec()));
                check_nonce_increase(old_nonces, &signers);
            }

            {
                let kv = (vec![6; 200], vec![9; 200]);
                let call = Call::System(system::Call::<Test>::set_storage(vec![kv.clone()]));

                let sc = MasterVoteRaw {
                    _marker: PhantomData,
                    proposal: call.encode(),
                    round_no: 1,
                };

                let signers = [(dida, &didak), (didb, &didbk)];

                let old_nonces = get_nonces(&signers);

                let pauth = get_pauth(&sc, &signers);

                MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();
                assert_eq!(sp_io::storage::get(&kv.0), Some(kv.1.to_vec()));
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
            Members::set(Membership {
                members: set(&[dida, didb]),
                vote_requirement: 1,
            });
            let call = Box::new(Call::System(system::Call::<Test>::set_storage(vec![])));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: 0,
            };

            {
                // signing with wrong key
                let pauth = get_pauth(&sc, &[(didb, &didak)]);
                let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
                assert_eq!(err, MasterError::<Test>::BadSig.into());
            }

            {
                // signing with wrong key, not in member set
                let pauth = get_pauth(&sc, &[(didc, &didck)]);
                let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
                assert_eq!(err, MasterError::<Test>::NotMember.into());
            }

            {
                // wrong payload
                let sc = crate::revoke::RemoveRegistryRaw {
                    registry_id: RGA,
                    _marker: PhantomData,
                };
                let pauth = get_pauth(&sc, &[(dida, &didak)]);
                let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
                assert_eq!(err, MasterError::<Test>::BadSig.into());
            }
        });
    }

    #[test]
    fn err_not_member() {
        ext().execute_with(|| {
            let (dida, _didak) = newdid();
            let (didc, didck) = newdid();
            Members::set(Membership {
                members: set(&[dida]),
                vote_requirement: 1,
            });
            let call = Box::new(Call::System(system::Call::<Test>::set_storage(vec![])));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: 0,
            };
            let pauth = get_pauth(&sc, &[(didc, &didck)]);
            let err = MasterMod::execute(Origin::signed(0), call.clone(), pauth).unwrap_err();
            assert_eq!(err, MasterError::<Test>::NotMember.into());
        });
    }

    #[test]
    fn replay_protec() {
        ext().execute_with(|| {
            let (dida, didak) = newdid();
            Members::set(Membership {
                members: set(&[dida]),
                vote_requirement: 1,
            });
            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
            };
            let pauth = get_pauth(&sc, &[(dida, &didak)]);

            MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap();

            let pauth = get_pauth(&sc, &[(dida, &didak)]);
            let err =
                MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap_err();
            assert_eq!(err, MasterError::<Test>::BadSig.into());
        });
    }

    #[test]
    fn err_insufficient_votes() {
        ext().execute_with(|| {
            let (dida, didak) = newdid();
            let (didb, _didbk) = newdid();
            let call = Call::System(system::Call::<Test>::set_storage(vec![]));
            let sc = MasterVoteRaw {
                _marker: PhantomData,
                proposal: call.encode(),
                round_no: Round::get(),
            };
            Members::set(Membership {
                members: set(&[dida, didb]),
                vote_requirement: 2,
            });

            let pauth = get_pauth(&sc, &[(dida, &didak)]);
            let err =
                MasterMod::execute(Origin::signed(0), Box::new(call.clone()), pauth).unwrap_err();
            assert_eq!(err, MasterError::<Test>::InsufficientVotes.into());
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
                assert_eq!(err, MasterError::<Test>::ZeroVoteRequirement.into());
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
                assert_eq!(err, MasterError::<Test>::VoteRequirementTooHigh.into());
            }
        });
    }

    fn master_events() -> Vec<Event<Test>> {
        system::Module::<Test>::events()
            .iter()
            .filter_map(|event_record| {
                let system::EventRecord::<TestEvent, H256> {
                    phase,
                    event,
                    topics,
                } = event_record;
                assert_eq!(phase, &system::Phase::Initialization);
                match event {
                    TestEvent::Master(e) => Some(e.clone()),
                    _ => None,
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

    fn sorted<T: Ord>(mut inp: Vec<T>) -> Vec<T> {
        inp.sort();
        inp
    }
}
