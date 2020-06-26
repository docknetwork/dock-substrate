//! Simulates a multisig sudo account. Members cast votes on a sudo call by commiting to a hash.
//! When a hash has enough votes, it can be executed by providing the preimage which is a call
//! to the sudo module.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode};
use core::default::Default;
use frame_support::{decl_module, decl_storage, dispatch::DispatchResult, ensure};
use system::{ensure_root, ensure_signed};

/// The output from hashing something with blake2s
pub type Blake2sHash = sp_core::H256;

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Membership<AccountId> {
    pub members: BTreeSet<AccountId>,
    pub vote_requirement: u64,
}

impl Default for Membership {
    fn default() -> Self {
        Membership {
            members: BTreeSet::new(),
            vote_requirement: u64::max_value(),
        }
    }
}

pub trait Trait: system::Trait + sudo::Trait {}

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
        pub fn execute(
            origin,
            proposal_preimage: Box<<T as system::Trait>::Call>,
        ) -> DispatchResult {
            Module::<T>::execute_(origin, proposal_preimage)
        }

        /// A sudo-only call to set the members and vote requirement for master.
        pub fn set_membership(origin, membership: Membership<T::AccountId>) -> DispatchResult {
            Module::<T>::set_membership_(origin, proposal_preimage)
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
        let mut votes = Votes::get();
        let members = Members::get();
        let round = Round::get();
        ensure!(round == current_round, "");
        ensure!(members.members.contains(&who), "");
        ensure!(votes.get(&who) != Some(&proposal_hash), "");
        votes.insert(who, proposal_hash);
        Votes::set(votes);
        Ok(())
    }

    pub fn execute_(
        origin: T::Origin,
        proposal_preimage: Box<<T as system::Trait>::Call>,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        let votes = Votes::get();
        let members = Members::get();
        let round = Round::get();
        let proposal_hash = proposal_preimage.using_encoded(sp_core::Blake2Hasher::hash);
        let num_votes = votes.values().filter(|h| h.eq(proposal_hash)).count() as u64;
        ensure!(num_votes >= members.vote_requirement, "");
        proposal_preimage.dispatch(system::RawOrigin::Root)?;
        Votes::set(BTreeMap::default());
        Round::set(round + 1);
        Ok(())
    }

    pub fn set_membership_(
        origin: T::Origin,
        membership: Membership<T::AccountId>,
    ) -> DispatchResult {
        ensure_root(origin)?;
        ensure!(membership.vote_requirement != 0, "");
        Members::set(membership);
        Round::set(Round::get() + 1);
        Votes::set(BTreeMap::default());
        Ok(())
    }
}
