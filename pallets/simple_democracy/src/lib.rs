//! This is a facade over Substrate's democracy pallet offering similar functionality with a few differences.
//! It also assumes that sending extrinsics to Substrate's democracy pallet are disallowed and this is configured in runtime/lib.rs
//! This pallet offers a "simple majority" governance, by mostly restricting certain features of Substrate's democracy pallet. Here only Council can vote but anyone can
//! propose by locking a fixed amount of tokens, `PublicProposalDeposit`. Similar to Substrate's governance pallet, both Council and
//! general public take turns proposing, and a proposal follows "propose" -> "referendum" -> "enact" sequence.
//! General public's proposals can be "seconded" by other token holder.
//! Technical committee can fast track proposal made by Council member.
//! A simple majority of Council members' votes (>50%) are needed to accept an ongoing referendum.
//! Council members can cancel a proposal made by the public.
//! Setting up of Council and Technical committee can be seen in the pallet's tests.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use frame_support::dispatch::{DispatchError, DispatchResult};
use frame_support::{
    decl_error, decl_event, decl_module, ensure,
    traits::{Currency, EnsureOrigin, Get, Imbalance, OnUnbalanced},
    weights::{constants::RocksDbWeight as DbWeight, DispatchClass, Weight},
    StorageMap, StorageValue,
};
use frame_system::{self as system, ensure_signed};
use pallet_democracy::{
    AccountVote, BalanceOf, Conviction, NegativeImbalanceOf, PreimageStatus, PropIndex,
    ReferendumIndex, ReferendumInfo, ReferendumInfoOf, ReferendumStatus, Tally, UnvoteScope, Vote,
    VoteThreshold, Voting, WeightInfo,
};
use sp_runtime::{traits::Zero, SaturatedConversion};

#[cfg(test)]
mod tests;

// Another way to achieve voting by Council is to have the council vote as simple majority on the proposal as the gov. call.
// The simple majority origin can be used to make the call.

/// Copied from Substrate democracy pallet's default weight but discouted the read and write of locks
fn vote_new(r: u32) -> Weight {
    (54159000 as Weight)
        .saturating_add((252000 as Weight).saturating_mul(r as Weight))
        .saturating_add(DbWeight::get().reads(2 as Weight))
        .saturating_add(DbWeight::get().writes(2 as Weight))
}

/// Copied from Substrate democracy pallet's default weight but discouted the read and write of locks
fn vote_existing(r: u32) -> Weight {
    (54145000 as Weight)
        .saturating_add((262000 as Weight).saturating_mul(r as Weight))
        .saturating_add(DbWeight::get().reads(2 as Weight))
        .saturating_add(DbWeight::get().writes(2 as Weight))
}

pub trait Trait: system::Trait + pallet_democracy::Trait + poa::Trait {
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
    /// Origin which can vote
    type VoterOrigin: EnsureOrigin<Self::Origin, Success = Self::AccountId>;
}

decl_event!(
    pub enum Event {
        CouncilMemberAdded,
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        OnlyDirectVotingAllowed,
        OnlyStandardVotingAllowed,
        NotVoter,
        NoPermission,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        // Several functions below are "proxy" to the forked democracy pallet's calls and have their docs
        // and weight largely copied from there

        /// Propose a sensitive action to be taken.
        ///
        /// The dispatch origin of this call must be _Signed_ and the sender must
        /// have funds to cover the deposit.
        ///
        /// - `proposal_hash`: The hash of the proposal preimage.
        /// - `value`: The amount of deposit (must be at least `MinimumDeposit`).
        ///
        /// Emits `Proposed`.
        ///
        /// # <weight>
        /// - Complexity: `O(1)`
        /// - Db reads: `PublicPropCount`, `PublicProps`
        /// - Db writes: `PublicPropCount`, `PublicProps`, `DepositOf`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::propose()]
        fn propose(origin, proposal_hash: T::Hash, #[compact] value: BalanceOf<T>) {
            <pallet_democracy::Module<T>>::propose(origin, proposal_hash, value)?;
        }

        /// Signals agreement with a particular proposal.
        ///
        /// The dispatch origin of this call must be _Signed_ and the sender
        /// must have funds to cover the deposit, equal to the original deposit.
        ///
        /// - `proposal`: The index of the proposal to second.
        /// - `seconds_upper_bound`: an upper bound on the current number of seconds on this
        ///   proposal. Extrinsic is weighted according to this value with no refund.
        ///
        /// # <weight>
        /// - Complexity: `O(S)` where S is the number of seconds a proposal already has.
        /// - Db reads: `DepositOf`
        /// - Db writes: `DepositOf`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::second(*seconds_upper_bound)]
        fn second(origin, #[compact] proposal: PropIndex, #[compact] seconds_upper_bound: u32) {
            <pallet_democracy::Module<T>>::second(origin, proposal, seconds_upper_bound)?;
        }

        /// Schedule a majority-carries referendum to be tabled next once it is legal to schedule
        /// an external referendum.
        ///
        /// The dispatch of this call must be `ExternalMajorityOrigin`.
        ///
        /// - `proposal_hash`: The preimage hash of the proposal.
        ///
        /// Unlike `external_propose`, blacklisting has no effect on this and it may replace a
        /// pre-scheduled `external_propose` call.
        ///
        /// # <weight>
        /// - Complexity: `O(1)`
        /// - Db write: `NextExternal`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::external_propose_majority()]
        fn council_propose(origin, proposal_hash: T::Hash) {
            <pallet_democracy::Module<T>>::external_propose_majority(origin, proposal_hash)?;
        }

        /// Schedule the currently externally-proposed majority-carries referendum to be tabled
        /// immediately. If there is no externally-proposed referendum currently, or if there is one
        /// but it is not a majority-carries referendum then it fails.
        ///
        /// The dispatch of this call must be `FastTrackOrigin`.
        ///
        /// - `proposal_hash`: The hash of the current external proposal.
        /// - `voting_period`: The period that is allowed for voting on this proposal. Increased to
        ///   `FastTrackVotingPeriod` if too low.
        /// - `delay`: The number of block after voting has ended in approval and this should be
        ///   enacted. This doesn't have a minimum amount.
        ///
        /// Emits `Started`.
        ///
        /// # <weight>
        /// - Complexity: `O(1)`
        /// - Db reads: `NextExternal`, `ReferendumCount`
        /// - Db writes: `NextExternal`, `ReferendumCount`, `ReferendumInfoOf`
        /// - Base Weight: 30.1 µs
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::fast_track()]
        fn fast_track(origin, proposal_hash: T::Hash, voting_period: T::BlockNumber, delay: T::BlockNumber) {
            <pallet_democracy::Module<T>>::fast_track(origin, proposal_hash, voting_period, delay)?;
        }

        /// Vote in a referendum. If `vote` is true, the vote is to enact the proposal;
        /// otherwise it is a vote to keep the status quo.
        ///
        /// The dispatch origin of this call must be _Signed_.
        ///
        /// - `ref_index`: The index of the referendum to vote for.
        /// - `vote`: True or false.
        ///
        /// # <weight>
        /// - Complexity: `O(R)` where R is the number of referendums the voter has voted on.
        ///   weight is charged as if maximum votes.
        /// - Db reads: `ReferendumInfoOf`, `VotingOf`
        /// - Db writes: `ReferendumInfoOf`, `VotingOf`
        /// # </weight>
        #[weight = vote_new(<T as pallet_democracy::Trait>::MaxVotes::get())
            .max(vote_existing(<T as pallet_democracy::Trait>::MaxVotes::get()))]
        fn vote(origin, #[compact] ref_index: ReferendumIndex, vote: bool) -> DispatchResult {
            let who = T::VoterOrigin::ensure_origin(origin)?;
            Self::try_vote(&who, ref_index, vote)
        }

        /// Remove a vote for a referendum.
        ///
        /// If:
        /// - the referendum was cancelled, or
        /// - the referendum is ongoing, or
        /// - the referendum has ended
        ///
        /// The dispatch origin of this call must be _Signed_, and the signer must have a vote
        /// registered for referendum `index`.
        ///
        /// - `index`: The index of referendum of the vote to be removed.
        ///
        /// # <weight>
        /// - `O(R + log R)` where R is the number of referenda that `target` has voted on.
        ///   Weight is calculated for the maximum number of vote.
        /// - Db reads: `ReferendumInfoOf`, `VotingOf`
        /// - Db writes: `ReferendumInfoOf`, `VotingOf`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::remove_vote(<T as pallet_democracy::Trait>::MaxVotes::get())]
        fn remove_vote(origin, #[compact] ref_index: ReferendumIndex) -> DispatchResult {
            let who = T::VoterOrigin::ensure_origin(origin)?;
            Self::try_remove_vote(&who, ref_index, UnvoteScope::Any)
        }

        /// Remove a vote for a referendum.
        ///
        /// If the `target` is equal to the signer, then this function is exactly equivalent to
        /// `remove_vote`. If not equal to the signer, then the vote must have expired,
        /// either because the referendum was cancelled or the voter lost the referendum
        ///
        /// The dispatch origin of this call must be _Signed_.
        ///
        /// - `target`: The account of the vote to be removed; this account must have voted for
        ///   referendum `index`.
        /// - `index`: The index of referendum of the vote to be removed.
        ///
        /// # <weight>
        /// - `O(R + log R)` where R is the number of referenda that `target` has voted on.
        ///   Weight is calculated for the maximum number of vote.
        /// - Db reads: `ReferendumInfoOf`, `VotingOf`
        /// - Db writes: `ReferendumInfoOf`, `VotingOf`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::remove_other_vote(<T as pallet_democracy::Trait>::MaxVotes::get())]
        fn remove_other_vote(origin, target: T::AccountId, ref_index: ReferendumIndex) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let scope = if target == who { UnvoteScope::Any } else { UnvoteScope::OnlyExpired };
            Self::try_remove_vote(&target, ref_index, scope)
        }

        /// Enact a proposal from a referendum. For now we just make the weight be the maximum.
        #[weight = T::MaximumBlockWeight::get()]
        fn enact_proposal(origin, proposal_hash: T::Hash, index: ReferendumIndex) -> DispatchResult {
            <pallet_democracy::Module<T>>::enact_proposal(origin, proposal_hash, index)
        }

        /// Register the preimage for an upcoming proposal. This doesn't require the proposal to be
        /// in the dispatch queue but does require a deposit, returned once enacted.
        ///
        /// The dispatch origin of this call must be _Signed_.
        ///
        /// - `encoded_proposal`: The preimage of a proposal.
        ///
        /// Emits `PreimageNoted`.
        ///
        /// # <weight>
        /// - Complexity: `O(E)` with E size of `encoded_proposal` (protected by a required deposit).
        /// - Db reads: `Preimages`
        /// - Db writes: `Preimages`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::note_preimage(encoded_proposal.len() as u32)]
        pub fn note_preimage(origin, encoded_proposal: Vec<u8>) {
            <pallet_democracy::Module<T>>::note_preimage(origin, encoded_proposal)?;
        }

        /// Same as `note_preimage` but origin is `OperationalPreimageOrigin`.
        #[weight = (<T as pallet_democracy::Trait>::WeightInfo::note_preimage(encoded_proposal.len() as u32), DispatchClass::Operational)]
        fn note_preimage_operational(origin, encoded_proposal: Vec<u8>) {
            <pallet_democracy::Module<T>>::note_preimage_operational(origin, encoded_proposal)?;
        }

        /// Remove an expired proposal preimage and collect the deposit.
        ///
        /// The dispatch origin of this call must be _Signed_.
        ///
        /// - `proposal_hash`: The preimage hash of a proposal.
        /// - `proposal_length_upper_bound`: an upper bound on length of the proposal.
        ///   Extrinsic is weighted according to this value with no refund.
        ///
        /// This will only work after `VotingPeriod` blocks from the time that the preimage was
        /// noted, if it's the same account doing it. If it's a different account, then it'll only
        /// work an additional `EnactmentPeriod` later.
        ///
        /// Emits `PreimageReaped`.
        ///
        /// # <weight>
        /// - Complexity: `O(D)` where D is length of proposal.
        /// - Db reads: `Preimages`, provider account data
        /// - Db writes: `Preimages` provider account data
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::reap_preimage(*proposal_len_upper_bound)]
        pub fn reap_preimage(origin, proposal_hash: T::Hash, #[compact] proposal_len_upper_bound: u32) {
            <pallet_democracy::Module<T>>::reap_preimage(origin, proposal_hash, proposal_len_upper_bound)?;
        }

        /// Remove a proposal.
        ///
        /// The dispatch origin of this call must be `CancelProposalOrigin`.
        ///
        /// - `prop_index`: The index of the proposal to cancel.
        ///
        /// Weight: `O(p)` where `p = PublicProps::<T>::decode_len()`
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::cancel_proposal(<T as pallet_democracy::Trait>::MaxProposals::get())]
        fn cancel_proposal(origin, #[compact] prop_index: PropIndex) {
            <pallet_democracy::Module<T>>::cancel_proposal(origin, prop_index)?;
        }

        /// Cancel a proposal queued for enactment.
        ///
        /// The dispatch origin of this call must be _Root_.
        ///
        /// - `which`: The index of the referendum to cancel.
        ///
        /// # <weight>
        /// - `O(D)` where `D` is the items in the dispatch queue. Weighted as `D = 10`.
        /// - Db reads: `scheduler lookup`, scheduler agenda`
        /// - Db writes: `scheduler lookup`, scheduler agenda`
        /// # </weight>
        #[weight = (<T as pallet_democracy::Trait>::WeightInfo::cancel_queued(10), DispatchClass::Operational)]
        fn cancel_queued(origin, which: ReferendumIndex) {
            <pallet_democracy::Module<T>>::cancel_queued(origin, which)?;
        }

        /// Remove a referendum.
        ///
        /// The dispatch origin of this call must be _Root_.
        ///
        /// - `ref_index`: The index of the referendum to cancel.
        ///
        /// # <weight>
        /// - Complexity: `O(1)`.
        /// - Db writes: `ReferendumInfoOf`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::cancel_referendum()]
        fn cancel_referendum(origin, #[compact] ref_index: ReferendumIndex) {
            <pallet_democracy::Module<T>>::cancel_referendum(origin, ref_index)?;
        }

        /// Clears all public proposals.
        ///
        /// The dispatch origin of this call must be _Root_.
        ///
        /// # <weight>
        /// - `O(1)`.
        /// - Db writes: `PublicProps`
        /// # </weight>
        #[weight = <T as pallet_democracy::Trait>::WeightInfo::clear_public_proposals()]
        fn clear_public_proposals(origin) {
            <pallet_democracy::Module<T>>::clear_public_proposals(origin)?;
        }
    }
}

impl<T: Trait> Module<T> {
    /// Almost similar to forked democracy pallet's `try_vote` with the difference that vote balances are disregarded and split voting is not allowed
    fn try_vote(who: &T::AccountId, ref_index: ReferendumIndex, vote: bool) -> DispatchResult {
        let vote = Self::bool_vote_to_account_vote(vote);
        let mut status = <pallet_democracy::Module<T>>::referendum_status(ref_index)?;
        <pallet_democracy::VotingOf<T>>::try_mutate(who, |voting| -> DispatchResult {
            if let Voting::Direct { ref mut votes, .. } = voting {
                match votes.binary_search_by_key(&ref_index, |i| i.0) {
                    Ok(i) => {
                        Self::remove_from_tally(votes[i].1.clone(), &mut status.tally)?;
                        votes[i].1 = vote;
                    }
                    Err(i) => {
                        // Don't worry about exceeding max votes
                        votes.insert(i, (ref_index, vote));
                    }
                }
                Self::add_to_tally(vote.clone(), &mut status.tally)?;
                Ok(())
            } else {
                Err(Error::<T>::OnlyDirectVotingAllowed.into())
            }
        })?;
        <pallet_democracy::ReferendumInfoOf<T>>::insert(ref_index, ReferendumInfo::Ongoing(status));
        Ok(())
    }

    /// Almost similar to forked democracy pallet's `try_remove_vote` with the difference that vote balances are disregarded and split voting is not allowed
    fn try_remove_vote(
        who: &T::AccountId,
        ref_index: ReferendumIndex,
        scope: UnvoteScope,
    ) -> DispatchResult {
        let info = <pallet_democracy::ReferendumInfoOf<T>>::get(ref_index);
        <pallet_democracy::VotingOf<T>>::try_mutate(who, |voting| -> DispatchResult {
            if let Voting::Direct { ref mut votes, .. } = voting {
                let i = votes
                    .binary_search_by_key(&ref_index, |i| i.0)
                    .map_err(|_| Error::<T>::NotVoter)?;
                match info {
                    Some(ReferendumInfo::Ongoing(mut status)) => {
                        ensure!(matches!(scope, UnvoteScope::Any), Error::<T>::NoPermission);
                        Self::remove_from_tally(votes[i].1.clone(), &mut status.tally)?;
                        ReferendumInfoOf::<T>::insert(ref_index, ReferendumInfo::Ongoing(status));
                    }
                    _ => {} // Referendum was expired or cancelled.
                }
                votes.remove(i);
                Ok(())
            } else {
                Err(Error::<T>::OnlyDirectVotingAllowed.into())
            }
        })?;
        Ok(())
    }

    /// Remove vote from tally
    fn remove_from_tally(
        vote: AccountVote<BalanceOf<T>>,
        tally: &mut Tally<BalanceOf<T>>,
    ) -> DispatchResult {
        if let AccountVote::Standard { vote, .. } = vote {
            match vote.aye {
                true => tally.ayes -= 1u32.saturated_into(),
                false => tally.nays -= 1u32.saturated_into(),
            }
            Ok(())
        } else {
            Err(Error::<T>::OnlyStandardVotingAllowed.into())
        }
    }

    /// Add vote to tally
    fn add_to_tally(
        vote: AccountVote<BalanceOf<T>>,
        tally: &mut Tally<BalanceOf<T>>,
    ) -> DispatchResult {
        if let AccountVote::Standard { vote, .. } = vote {
            match vote.aye {
                true => tally.ayes += 1u32.saturated_into(),
                false => tally.nays += 1u32.saturated_into(),
            }
            Ok(())
        } else {
            Err(Error::<T>::OnlyStandardVotingAllowed.into())
        }
    }

    /// Take a vote as a boolean and convert to `AccountVote` as that's whats needed by the forked pallet
    fn bool_vote_to_account_vote(vote: bool) -> AccountVote<BalanceOf<T>> {
        AccountVote::Standard {
            vote: Vote {
                aye: vote,
                conviction: Conviction::None,
            },
            balance: BalanceOf::<T>::zero(),
        }
    }

    // Following are proxys/wrappers to forked democracy pallet's storage. Consider exposing them as RPC for convenience

    /// Next proposal from council
    pub fn next_external() -> Option<(T::Hash, VoteThreshold)> {
        <pallet_democracy::NextExternal<T>>::get()
    }

    /// Number of public proposals made so far
    pub fn public_prop_count() -> PropIndex {
        <pallet_democracy::PublicPropCount>::get()
    }

    /// List of public proposals
    pub fn public_props() -> Vec<(PropIndex, T::Hash, T::AccountId)> {
        <pallet_democracy::PublicProps<T>>::get()
    }

    /// Number of referenda made so far
    pub fn referendum_count() -> ReferendumIndex {
        <pallet_democracy::ReferendumCount>::get()
    }

    /// Status of a particular referendum
    pub fn referendum_status(
        ref_index: ReferendumIndex,
    ) -> Result<ReferendumStatus<T::BlockNumber, T::Hash, BalanceOf<T>>, DispatchError> {
        <pallet_democracy::Module<T>>::referendum_status(ref_index)
    }

    /// Info of a particular referendum
    pub fn referendum_info_of(
        idx: ReferendumIndex,
    ) -> Option<ReferendumInfo<T::BlockNumber, T::Hash, BalanceOf<T>>> {
        <pallet_democracy::ReferendumInfoOf<T>>::get(idx)
    }

    /// Get preimage of a proposal hash
    pub fn get_preimage(
        image: T::Hash,
    ) -> Option<PreimageStatus<T::AccountId, BalanceOf<T>, T::BlockNumber>> {
        <pallet_democracy::Preimages<T>>::get(image)
    }

    /// Get all deposits of a public proposal
    pub fn deposit_of(prop_index: PropIndex) -> Option<(Vec<T::AccountId>, BalanceOf<T>)> {
        <pallet_democracy::DepositOf<T>>::get(prop_index)
    }
}

/// Transfer slashes to Treasury account defined in the PoA module
impl<T: Trait> OnUnbalanced<NegativeImbalanceOf<T>> for Module<T> {
    fn on_nonzero_unbalanced(amount: NegativeImbalanceOf<T>) {
        let slashed = amount.peek();
        // An alternative could be to not make this pallet depend on the PoA pallet but make sure that
        // same constant `TREASURY_ID` is used to generate treasury account.
        let treasury_account = <poa::Module<T>>::treasury_account();
        <T as pallet_democracy::Trait>::Currency::deposit_creating(&treasury_account, slashed);
    }
}
