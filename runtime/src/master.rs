//! Simulates a multisig root account. Members cast votes on a Call by commiting to a hash.
//! When a hash has enough votes, it can be executed by providing the preimage.
//! The preimage is a Dispatchable (a reified on-chain function call). When a vote
//! succeeds and its preimage is provided, the preimage is called with system::Origin::Root as the
//! origin.
//!
//! Your node_runtime::Call is an example of a Dispatchable.
//!
//! For simplicity, the hashing function used will be the same as what is used in the rest of your
//! runtime (the one configured in pallet_system::Trait).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode};
use core::default::Default;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Dispatchable},
    ensure, Parameter,
};
use sp_runtime::traits::Hash;
use system::{ensure_root, ensure_signed};

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Membership<AccountId: Ord> {
    pub members: BTreeSet<AccountId>,
    pub vote_requirement: u64,
}

impl<T: Ord> Default for Membership<T> {
    fn default() -> Self {
        Membership {
            members: BTreeSet::new(),
            vote_requirement: 1,
        }
    }
}

pub trait Trait: system::Trait
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
        pub Votes: BTreeMap<T::AccountId, <T as system::Trait>::Hash>;
        pub Members config(members): Membership<T::AccountId>;
        pub Round: u64;
    }
}

decl_error! {
    pub enum MasterError for Module<T: Trait> {
        /// Attempted to submit vote for a voting round that is not current. Hint: you can query the
        /// current round from chain state.
        WrongRound,
        /// The account used to submit this vote is not a member of Master.
        NotMember,
        /// This is already the active vote for this account. No need to submit it again this round.
        RepeatedVote,
        /// This proposal does not yet have enough votes to be executed.
        InsufficientVotes,
    }
}

decl_event! {
    pub enum Event<T>
    where
        <T as system::Trait>::AccountId,
        <T as system::Trait>::Hash
    {
        /// A member of master submitted a vote.
        /// The account id of the the voter and the hash of the proposal is provided.
        Vote(AccountId, Hash),
        /// A proposal succeeded and was executed. The hash of the proposal is provided.
        Executed(Hash),
        /// The membership of Master has changed.
        UnderNewOwnership,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = MasterError<T>;

        fn deposit_event() = default;

        /// Vote "yes" to some proposal.
        ///
        /// `current_round` is a protection against accidendally voting on a proposal after is has
        /// already been executed. Every time a proposal is executed the round number is increased
        /// by at least one and the votes for the current round are cleared.
        #[weight = 0]
        pub fn vote(
            origin,
            current_round: u64,
            proposal_hash: <T as system::Trait>::Hash,
        ) -> DispatchResult {
            Module::<T>::vote_(origin, current_round, proposal_hash)
        }

        /// Execute a proposal that has received enough votes. The proposal is a serialized Call.
        /// This function can be freely called by anyone, even someone who is not a member of
        /// Master.
        ///
        /// After a sucessful execution, the current round of voted is cleared and round number is increased.
        #[weight = 0]
        pub fn execute(
            origin,
            proposal: Box<<T as Trait>::Call>,
        ) -> DispatchResult {
            Module::<T>::execute_(origin, proposal)
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
        /// # let _: Membership<[u8; 32]> =
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
            membership: Membership<T::AccountId>
        ) -> DispatchResult {
            Module::<T>::set_members_(origin, membership)
        }
    }
}

impl<T: Trait> Module<T> {
    pub fn vote_(
        origin: T::Origin,
        current_round: u64,
        proposal_hash: <T as system::Trait>::Hash,
    ) -> DispatchResult {
        let who = ensure_signed(origin)?;

        // check
        let mut votes = Votes::<T>::get();
        ensure!(Round::get() == current_round, MasterError::<T>::WrongRound);
        ensure!(
            Members::<T>::get().members.contains(&who),
            MasterError::<T>::NotMember
        );
        ensure!(
            votes.get(&who) != Some(&proposal_hash),
            MasterError::<T>::RepeatedVote
        );

        // execute
        votes.insert(who.clone(), proposal_hash);
        Votes::<T>::set(votes);

        // events
        Self::deposit_event(RawEvent::Vote(who, proposal_hash));

        Ok(())
    }

    pub fn execute_(origin: T::Origin, proposal: Box<<T as Trait>::Call>) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        let votes = Votes::<T>::get();
        let members = Members::<T>::get();
        let proposal_hash = <T as system::Trait>::Hashing::hash_of(&proposal);
        let num_votes = votes.values().filter(|h| proposal_hash.eq(*h)).count() as u64;
        debug_assert!(votes.keys().all(|k| members.members.contains(k)));
        ensure!(
            num_votes >= members.vote_requirement,
            MasterError::<T>::InsufficientVotes
        );

        // execute/check
        proposal
            .dispatch(system::RawOrigin::Root.into())
            .map_err(|e| e.error)?;

        // execute
        Votes::<T>::set(BTreeMap::default());
        Round::mutate(|round| {
            *round += 1;
        });

        // events
        Self::deposit_event(RawEvent::Executed(proposal_hash));

        Ok(())
    }

    pub fn set_members_(origin: T::Origin, membership: Membership<T::AccountId>) -> DispatchResult {
        ensure_root(origin)?;

        // execute
        Members::<T>::set(membership);
        Votes::<T>::set(BTreeMap::default());
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
    /// set_members() may be called from within execute()
    /// that should cause round number to be incremented twice
    /// the Votes map will be set twice and that's expected
    #[test]
    #[ignore]
    fn execute_set_members() {
        todo!();
    }

    /// After a sucessful execution, the current round of voted is cleared and round number is increased.
    #[test]
    #[ignore]
    fn round_inc_votes_cleared() {
        todo!();
    }

    #[test]
    #[ignore]
    fn test_events() {
        todo!();
    }

    #[test]
    #[ignore]
    fn no_members() {
        todo!();
    }

    #[test]
    #[ignore]
    fn call_other_module() {}

    #[test]
    #[ignore]
    fn valid_call() {}
}
