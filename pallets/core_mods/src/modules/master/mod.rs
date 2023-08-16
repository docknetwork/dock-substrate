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

use crate::{common::DidSignatureWithNonce, did, did::Did, util::WithNonce};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use codec::{Decode, Encode};
use core::{default::Default, fmt::Debug, marker::PhantomData};
use sp_std::prelude::*;

use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{
        DispatchError, DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo,
        PostDispatchInfo,
    },
    ensure,
    traits::{Get, UnfilteredDispatchable},
    weights::{GetDispatchInfo, Pays, RuntimeDbWeight, Weight},
    Parameter,
};
use frame_system::{self as system, ensure_root, ensure_signed};

#[cfg(test)]
mod tests;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
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

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
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

pub type MasterVote<T> = WithNonce<T, MasterVoteRaw<T>>;

crate::impl_action_with_nonce! {
    for (): MasterVote with 1 as len, () as target
}

// Minimum weight of Master's extrinsics. This is not based on any computation but only there to account for
// some in-memory operations
const MIN_WEIGHT: Weight = Weight::from_ref_time(10_000);

/// Minimum weight for master's extrinsics. Considers cost of signature verification and update to round no
fn get_min_weight_for_execute<T: frame_system::Config>(
    auth: &[DidSignatureWithNonce<T>],
    db_weights: RuntimeDbWeight,
) -> Weight {
    MIN_WEIGHT
        + DidSignatureWithNonce::auth_weight(auth, db_weights)
        + db_weights.reads_writes(1, 1)
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
             get_min_weight_for_execute(auth, T::DbWeight::get()) + proposal.get_dispatch_info().weight,
             proposal.get_dispatch_info().class,
             proposal.get_dispatch_info().pays_fee,
            )
        ]
        pub fn execute(
            origin,
            proposal: Box<<T as Config>::Call>,
            auth: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            // `execute_` will compute the weight
            Self::execute_(proposal, auth, None)
        }

        /// Does the same job as `execute` dispatchable but does not inherit the weight of the
        /// `Call` its wrapping but expects the caller to provide it
        #[
            weight = (
             get_min_weight_for_execute(auth, T::DbWeight::get()) + *_weight,
             proposal.get_dispatch_info().class,
             proposal.get_dispatch_info().pays_fee,
            )
        ]
        pub fn execute_unchecked_weight(
            origin,
            proposal: Box<<T as Config>::Call>,
            auth: Vec<DidSignatureWithNonce<T>>,
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
        auth: Vec<DidSignatureWithNonce<T>>,
        given_weight: Option<Weight>,
    ) -> DispatchResultWithPostInfo {
        // check
        let new_payload = MasterVoteRaw {
            _marker: PhantomData,
            proposal: proposal.encode(),
            round_no: Round::get(),
        };

        let mut new_did_details = BTreeMap::new();
        // check each signature is valid over payload and signed by the claimed signer
        for a in auth.iter() {
            let signer = a.sig.did;
            let nonce = a.nonce;
            // Check if nonce is valid and increase it
            let mut did_detail = did::Pallet::<T>::onchain_did_details(&signer)?;
            did_detail
                .try_update(nonce)
                .map_err(|_| MasterError::<T>::IncorrectNonce)?;
            // Verify signature
            let valid = did::Pallet::<T>::verify_sig_from_auth_or_control_key(
                &WithNonce::new_with_nonce(new_payload.clone(), nonce),
                &a.sig,
            )?;
            ensure!(valid, MasterError::<T>::BadSig);

            new_did_details.insert(signer, did_detail);
        }

        let authors = new_did_details.keys().cloned().collect::<Vec<_>>();

        let membership = Members::get();
        ensure!(
            authors.len() as u64 >= membership.vote_requirement,
            MasterError::<T>::InsufficientVotes,
        );
        ensure!(
            authors.iter().all(|k| membership.members.contains(k)),
            MasterError::<T>::NotMember,
        );

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
            did::Pallet::<T>::insert_did_details(signer, did_details);
        }

        // Weight from dispatch's declaration. If dispatch does not return a weight in `PostDispatchInfo`,
        // then this weight is used.
        let dispatch_decl_weight = proposal.get_dispatch_info().weight;

        // If weight was not given in `given_weight`, look for weight of dispatch in `post_info`. If
        // `post_info` does not have weight, use weight from declaration. Also add minimum weight for execution
        let actual_weight = move |post_info: PostDispatchInfo| {
            given_weight.or_else(|| {
                Some(
                    post_info.actual_weight.unwrap_or(dispatch_decl_weight)
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
