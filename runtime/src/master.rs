//! Simulates a multisig sudo account. Members cast votes on a sudo call by commiting to a hash.
//! When a hash has enough votes, it can be executed by providing the preimage.
//! The preimage is a Dispatchable (a reified on-chain function call). When a vote
//! succeeds and its preimage is provided, the preimage is called with system::Origin::Root as the
//! origin.
//!
//! Your node_runtime::Call is an example of a Dispatchable.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use blake2::Digest;
use codec::{Decode, Encode};
use core::default::Default;
use frame_support::{
    decl_module, decl_storage,
    dispatch::{DispatchResult, Dispatchable},
    ensure, Parameter,
};
use system::{ensure_root, ensure_signed};

/// The output from hashing something with blake2s
pub type Blake2sHash = [u8; 32];

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
            vote_requirement: u64::max_value(),
        }
    }
}

pub trait Trait: system::Trait + sudo::Trait
where
    <Self as system::Trait>::AccountId: Ord,
{
    /// The dispatchable that master may call as Root. It is possible to use another type here, but
    /// its expectected that your runtime::Call will be used.
    type Call: Parameter + Dispatchable<Origin = Self::Origin>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Master {
        Votes: BTreeMap<T::AccountId, Blake2sHash>;
        Members: Membership<T::AccountId>;
        Round: u64;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        /// Vote "yes" to some proposal.
        #[weight = 0]
        pub fn vote(
            origin,
            current_round: u64,
            proposal_hash: Blake2sHash,
        ) -> DispatchResult {
            Module::<T>::vote_(origin, current_round, proposal_hash)
        }

        /// Execute a proposal that has received enough votes.
        /// The preimage is a serialized runtime Call
        ///
        /// This can be called by anyone, even someone who is not a member of Master.
        #[weight = 0]
        pub fn execute(
            origin,
            proposal_preimage: Box<<T as Trait>::Call>,
        ) -> DispatchResult {
            Module::<T>::execute_(origin, proposal_preimage)
        }

        /// A sudo-only call to set the members and vote requirement for master.
        ///
        /// This function does not check the membership of a set; rather, it sets the members of the collective.
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
        proposal_hash: Blake2sHash,
    ) -> DispatchResult {
        let who = ensure_signed(origin)?;
        let mut votes = Votes::<T>::get();
        let members = Members::<T>::get();
        let round = Round::get();
        ensure!(round == current_round, "");
        ensure!(members.members.contains(&who), "");
        ensure!(votes.get(&who) != Some(&proposal_hash), "");
        votes.insert(who, proposal_hash);
        Votes::<T>::set(votes);
        Ok(())
    }

    pub fn execute_(
        origin: T::Origin,
        proposal_preimage: Box<<T as Trait>::Call>,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        let votes = Votes::<T>::get();
        let members = Members::<T>::get();
        let round = Round::get();
        let proposal_hash: Blake2sHash = proposal_preimage.as_ref().using_encoded(blake2s_hash);
        let num_votes = votes.values().filter(|h| proposal_hash.eq(*h)).count() as u64;
        ensure!(num_votes >= members.vote_requirement, "");
        proposal_preimage
            .dispatch(system::RawOrigin::Root.into())
            .map_err(|e| e.error)?;
        Votes::<T>::set(BTreeMap::default());
        Round::set(round + 1);
        Ok(())
    }

    pub fn set_members_(origin: T::Origin, membership: Membership<T::AccountId>) -> DispatchResult {
        ensure_root(origin)?;
        ensure!(membership.vote_requirement != 0, "");
        Members::<T>::set(membership);
        Round::set(Round::get() + 1);
        Votes::<T>::set(BTreeMap::default());
        Ok(())
    }
}

fn blake2s_hash(inp: &[u8]) -> [u8; 32] {
    blake2::Blake2s::new().chain(inp).finalize().into()
}
