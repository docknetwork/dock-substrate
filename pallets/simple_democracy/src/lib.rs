//! This is a facade over Substrate's democracy pallet

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use frame_support::dispatch::{DispatchError, DispatchResult};
use frame_support::{
    decl_error, decl_event, decl_module, ensure,
    traits::{Currency, EnsureOrigin, Get, Imbalance, OnUnbalanced},
    weights::{DispatchClass, Weight},
    StorageMap, StorageValue,
};
use frame_system::{self as system, ensure_signed};
use pallet_democracy::{
    AccountVote, BalanceOf, NegativeImbalanceOf, PreimageStatus, PropIndex, ReferendumIndex,
    ReferendumInfo, ReferendumInfoOf, ReferendumStatus, Tally, UnvoteScope, VoteThreshold, Voting,
};
use sp_runtime::SaturatedConversion;

#[cfg(test)]
mod tests;

// Another way to achieve voting by Council is to have the council vote as simple majority on the proposal as the gov. call.
// The simple majority origin can be used to make the call.

pub trait Trait: system::Trait + pallet_democracy::Trait + poa::Trait {
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
    type PublicProposalDeposit: Get<u64>;
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

        /// Almost similar to forked democracy pallet's `propose` with the difference being that the
        /// deposit cannot be chosen by user but is fixed in `PublicProposalDeposit`
        // TODO: Fix weight
        #[weight = 0]
        fn propose(origin, proposal_hash: T::Hash) {
            let deposit = T::PublicProposalDeposit::get();
            <pallet_democracy::Module<T>>::propose(origin, proposal_hash, deposit.saturated_into())?;
        }

        /// Proxy function to forked democracy pallet's `second`
        // TODO: Fix weight
        #[weight = 0]
        fn second(origin, #[compact] proposal: PropIndex, #[compact] seconds_upper_bound: u32) {
            <pallet_democracy::Module<T>>::second(origin, proposal, seconds_upper_bound)?;
        }

        /// Proxy function to forked democracy pallet's `external_propose_majority`
        // TODO: Fix weight
        #[weight = 0]
        fn council_propose(origin, proposal_hash: T::Hash) {
            <pallet_democracy::Module<T>>::external_propose_majority(origin, proposal_hash)?;
        }

        // TODO: Fix weight
        #[weight = 0]
        fn fast_track(origin, proposal_hash: T::Hash, voting_period: T::BlockNumber, delay: T::BlockNumber) {
            <pallet_democracy::Module<T>>::fast_track(origin, proposal_hash, voting_period, delay)?;
        }

        /// Almost similar to forked democracy pallet's `vote` with the difference that vote balances
        /// are disregarded and split voting is not allowed
        // TODO: Fix weight
        #[weight = 0]
        fn vote(origin, #[compact] ref_index: ReferendumIndex, vote: AccountVote<BalanceOf<T>>) -> DispatchResult {
            let who = T::VoterOrigin::ensure_origin(origin)?;
            Self::try_vote(&who, ref_index, vote)
        }

        /// Almost similar to forked democracy pallet's `remove_vote` with the difference that vote
        /// balances are disregarded and split voting is not allowed
        // TODO: Fix weight
        #[weight = 0]
        fn remove_vote(origin, #[compact] ref_index: ReferendumIndex) -> DispatchResult {
            let who = T::VoterOrigin::ensure_origin(origin)?;
            Self::try_remove_vote(&who, ref_index, UnvoteScope::Any)
        }

        /// Almost similar to forked democracy pallet's `remove_other_vote` with the difference that
        /// vote balances are disregarded and split voting is not allowed
        // TODO: Fix weight
        #[weight = 0]
        fn remove_other_vote(origin, target: T::AccountId, ref_index: ReferendumIndex) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let scope = if target == who { UnvoteScope::Any } else { UnvoteScope::OnlyExpired };
            Self::try_remove_vote(&target, ref_index, scope)
        }

        /// Proxy function to forked democracy pallet's `enact_proposal`
        #[weight = T::MaximumBlockWeight::get()]
        fn enact_proposal(origin, proposal_hash: T::Hash, index: ReferendumIndex) -> DispatchResult {
            <pallet_democracy::Module<T>>::enact_proposal(origin, proposal_hash, index)
        }

        /// Proxy function to forked democracy pallet's `note_preimage`
        // TODO: Fix weight
        #[weight = 0]
        pub fn note_preimage(origin, encoded_proposal: Vec<u8>) {
            <pallet_democracy::Module<T>>::note_preimage(origin, encoded_proposal)?;
        }

        /// Proxy function to forked democracy pallet's `note_preimage_operational`
        // TODO: Fix weight
        #[weight = (0, DispatchClass::Operational)]
        fn note_preimage_operational(origin, encoded_proposal: Vec<u8>) {
            <pallet_democracy::Module<T>>::note_preimage_operational(origin, encoded_proposal)?;
        }

        /// Proxy function to forked democracy pallet's `reap_preimage`
        // TODO: Fix weight
        #[weight = 0]
        pub fn reap_preimage(origin, proposal_hash: T::Hash, #[compact] proposal_len_upper_bound: u32) {
            <pallet_democracy::Module<T>>::reap_preimage(origin, proposal_hash, proposal_len_upper_bound)?;
        }

        /// Proxy function to forked democracy pallet's `cancel_proposal`
        // TODO: Fix weight
        #[weight = 0]
        fn cancel_proposal(origin, #[compact] prop_index: PropIndex) {
            <pallet_democracy::Module<T>>::cancel_proposal(origin, prop_index)?;
        }

        /// Proxy function to forked democracy pallet's `cancel_queued`
        // TODO: Fix weight
        #[weight = (0, DispatchClass::Operational)]
        fn cancel_queued(origin, which: ReferendumIndex) {
            <pallet_democracy::Module<T>>::cancel_queued(origin, which)?;
        }

        /// Proxy function to forked democracy pallet's `cancel_referendum`
        // TODO: Fix weight
        #[weight = 0]
        fn cancel_referendum(origin, #[compact] ref_index: ReferendumIndex) {
            <pallet_democracy::Module<T>>::cancel_referendum(origin, ref_index)?;
        }

        /// Proxy function to forked democracy pallet's `clear_public_proposals`
        // TODO: Fix weight
        #[weight = 0]
        fn clear_public_proposals(origin) {
            <pallet_democracy::Module<T>>::clear_public_proposals(origin)?;
        }

        /// Proxy function to forked democracy pallet's `on_initialize`
        // TODO: Set weight
        fn on_initialize(n: T::BlockNumber) -> Weight {
            <pallet_democracy::Module<T>>::on_initialize(n)
        }
    }
}

impl<T: Trait> Module<T> {
    /// Almost similar to forked democracy pallet's `try_vote` with the difference that vote balances are disregarded and split voting is not allowed
    fn try_vote(
        who: &T::AccountId,
        ref_index: ReferendumIndex,
        vote: AccountVote<BalanceOf<T>>,
    ) -> DispatchResult {
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
                true => tally.ayes += 1.saturated_into(),
                false => tally.nays += 1.saturated_into(),
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
                true => {
                    tally.ayes += 1.saturated_into();
                }
                false => tally.nays += 1.saturated_into(),
            }
            Ok(())
        } else {
            Err(Error::<T>::OnlyStandardVotingAllowed.into())
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
