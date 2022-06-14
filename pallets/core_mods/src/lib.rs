#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

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
    // Revoke(revoke::Revoke),
    // UnRevoke(revoke::UnRevoke),
    // RemoveRegistry(revoke::RemoveRegistry),
    // Blob(blob::Blob),
    // MasterVote(master::Payload),
    // Attestation((did::Did, attest::Attestation)),
    // AddBBSPlusParams(bbs_plus::BbsPlusParameters),
    // AddBBSPlusPublicKey(bbs_plus::BbsPlusPublicKey),
    // RemoveBBSPlusParams(bbs_plus::ParametersStorageKey),
    // RemoveBBSPlusPublicKey(bbs_plus::PublicKeyStorageKey),
    // AddAccumulatorParams(accumulator::AccumulatorParameters),
    // AddAccumulatorPublicKey(accumulator::AccumulatorPublicKey),
    // RemoveAccumulatorParams(accumulator::ParametersStorageKey),
    // RemoveAccumulatorPublicKey(accumulator::PublicKeyStorageKey),
    // AddAccumulator(accumulator::AddAccumulator),
    // UpdateAccumulator(accumulator::AccumulatorUpdate),
    // RemoveAccumulator(accumulator::RemoveAccumulator),
}

/// Describes an action which can be performed on some `Target`
pub trait Action<T: frame_system::Config> {
    /// Action target.
    type Target;

    /// Returns underlying action target.
    fn target(&self) -> Self::Target;

    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;

    /// Returns action unit length.
    fn len(&self) -> u32;

    /// Returns `true` if the ction unit count is equal to zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts the given action to the state change.
    fn to_state_change(&self) -> StateChange<'_, T>;
}

// pub mod accumulator;
pub mod anchor;
// pub mod attest;
// pub mod bbs_plus;
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_utils;
// pub mod blob;
pub mod did;
pub mod keys_and_sigs;
// pub mod master;
// pub mod revoke;
pub mod runtime_api;
pub mod types;
pub mod util;

#[cfg(test)]
mod test_common;
