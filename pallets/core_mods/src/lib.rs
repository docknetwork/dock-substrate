#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use codec::{Decode, Encode};
use sp_std::borrow::Cow;

/// Any state change that needs to be signed is first wrapped in this enum and then its serialized.
/// This is done to make it unambiguous which command was intended as the SCALE codec's
/// not self describing.
/// Never change the order of variants in this enum
#[derive(Encode, Decode)]
pub enum StateChange<'a, T: frame_system::Config> {
    AddKeys(Cow<'a, did::AddKeys<T>>),
    AddControllers(Cow<'a, did::AddControllers<T>>),
    RemoveKeys(Cow<'a, did::RemoveKeys<T>>),
    RemoveControllers(Cow<'a, did::RemoveControllers<T>>),
    AddServiceEndpoint(Cow<'a, did::AddServiceEndpoint<T>>),
    RemoveServiceEndpoint(Cow<'a, did::RemoveServiceEndpoint<T>>),
    DidRemoval(Cow<'a, did::DidRemoval<T>>),
    Revoke(Cow<'a, revoke::Revoke<T>>),
    UnRevoke(Cow<'a, revoke::UnRevoke<T>>),
    RemoveRegistry(Cow<'a, revoke::RemoveRegistry<T>>),
    AddBlob(Cow<'a, blob::AddBlob<T>>),
    MasterVote(Cow<'a, master::MasterVote<T>>),
    SetAttestationClaim(Cow<'a, attest::SetAttestationClaim<T>>),
    AddBBSPlusParams(Cow<'a, bbs_plus::AddBBSPlusParams<T>>),
    AddBBSPlusPublicKey(Cow<'a, bbs_plus::AddBBSPlusPublicKey<T>>),
    RemoveBBSPlusParams(Cow<'a, bbs_plus::RemoveBBSPlusParams<T>>),
    RemoveBBSPlusPublicKey(Cow<'a, bbs_plus::RemoveBBSPlusPublicKey<T>>),
    AddAccumulatorParams(Cow<'a, accumulator::AddAccumulatorParams<T>>),
    AddAccumulatorPublicKey(Cow<'a, accumulator::AddAccumulatorPublicKey<T>>),
    RemoveAccumulatorParams(Cow<'a, accumulator::RemoveAccumulatorParams<T>>),
    RemoveAccumulatorPublicKey(Cow<'a, accumulator::RemoveAccumulatorPublicKey<T>>),
    AddAccumulator(Cow<'a, accumulator::AddAccumulator<T>>),
    UpdateAccumulator(Cow<'a, accumulator::UpdateAccumulator<T>>),
    RemoveAccumulator(Cow<'a, accumulator::RemoveAccumulator<T>>),
}

/// Describes an action which can be performed on some `Target`
pub trait Action<T: frame_system::Config> {
    /// Action target.
    type Target;

    /// Returns underlying action target.
    fn target(&self) -> Self::Target;

    /// Returns action unit length.
    fn len(&self) -> u32;

    /// Returns `true` if the action unit count is equal to zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts the given action to the state change.
    fn to_state_change(&self) -> StateChange<'_, T>;

    /// Converts the given action to the state change.
    fn into_state_change(self) -> StateChange<'static, T>;
}

/// Describes an action with nonce which can be performed on some `Target`
pub trait ActionWithNonce<T: frame_system::Config>: Action<T> {
    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;
}

pub mod accumulator;
pub mod anchor;
pub mod attest;
pub mod bbs_plus;
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_utils;
pub mod blob;
pub mod did;
pub mod keys_and_sigs;
pub mod master;
pub mod revoke;
pub mod runtime_api;
pub mod types;
pub mod util;

#[cfg(test)]
mod test_common;
