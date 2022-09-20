#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use codec::{Decode, Encode};

def_state_change! {
    /// Any state change that needs to be signed is first wrapped in this enum and then its serialized.
    /// This is done to make it unambiguous which command was intended as the SCALE codec's
    /// not self describing. The enum variants are supposed to take care of replay protection by having a
    /// nonce or something else. A better approach would have been to make `StateChange` aware of nonce or nonces.
    /// There can be multiple nonces attached with a payload a multiple DIDs may take part in an action and they
    /// will have their own nonce. However this change will be a major disruption for now.
    /// Never change the order of variants in this enum
    StateChange:
        did::AddKeys,
        did::AddControllers,
        did::RemoveKeys,
        did::RemoveControllers,
        did::AddServiceEndpoint,
        did::RemoveServiceEndpoint,
        did::DidRemoval,
        revoke::Revoke,
        revoke::UnRevoke,
        revoke::RemoveRegistry,
        blob::AddBlob,
        master::MasterVote,
        attest::SetAttestationClaim,
        bbs_plus::AddBBSPlusParams,
        bbs_plus::AddBBSPlusPublicKey,
        bbs_plus::RemoveBBSPlusParams,
        bbs_plus::RemoveBBSPlusPublicKey,
        accumulator::AddAccumulatorParams,
        accumulator::AddAccumulatorPublicKey,
        accumulator::RemoveAccumulatorParams,
        accumulator::RemoveAccumulatorPublicKey,
        accumulator::AddAccumulator,
        accumulator::UpdateAccumulator,
        accumulator::RemoveAccumulator
}

/// Converts the given entity to the state change.
pub trait ToStateChange<T: frame_system::Config> {
    /// Converts the given entity to the state change.
    fn to_state_change(&self) -> StateChange<'_, T>;

    /// Transforms given entity into `StateChange`.
    fn into_state_change(self) -> StateChange<'static, T>;
}

/// Describes an action which can be performed on some `Target`.
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
}

/// Describes an action with nonce which can be performed on some `Target`
pub trait ActionWithNonce<T: frame_system::Config>: Action<T> {
    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;
}

/// Defines version of the storage being used.
#[derive(Encode, Decode, scale_info::TypeInfo, Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageVersion {
    /// The old version which supports only a single key for DID.
    SingleKey,
    /// Multi-key DID.
    MultiKey,
}

impl Default for StorageVersion {
    fn default() -> Self {
        Self::MultiKey
    }
}

pub mod keys_and_sigs;
mod migrations;
mod modules;
pub mod runtime_api;
pub mod types;
pub mod util;

pub use modules::{accumulator, anchor, attest, bbs_plus, blob, did, master, revoke};

// #[cfg(test)]
// mod storage_reader_tests;
#[cfg(test)]
mod test_common;
