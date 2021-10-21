#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use codec::{Decode, Encode};

/// Any state change that needs to be signed is first wrapped in this enum and then its serialized.
/// This is done to make it unambiguous which command was intended as the SCALE codec's
/// not self describing.
/// Never change the order of variants in this enum
#[derive(Encode, Decode)]
pub enum StateChange {
    KeyUpdate(did::KeyUpdate),
    DIDRemoval(did::DidRemoval),
    Revoke(revoke::Revoke),
    UnRevoke(revoke::UnRevoke),
    RemoveRegistry(revoke::RemoveRegistry),
    Blob(blob::Blob),
    MasterVote(master::Payload),
    Attestation((did::Did, attest::Attestation)),
    AddBBSPlusParams(bbs_plus::BBSPlusParameters),
    AddBBSPlusPublicKey(bbs_plus::BbsPlusPublicKey),
    RemoveBBSPlusParams(bbs_plus::ParametersStorageKey),
    RemoveBBSPlusPublicKey(bbs_plus::PublicKeyStorageKey),
}

// This should be same as the type defined in runtime/src/lib.rs. Less than ideal shortcut as this module shouldn't
// be aware of runtime. A better approach would be to make modules typed.
pub type BlockNumber = u32;

pub mod anchor;
pub mod attest;
pub mod bbs_plus;
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_utils;
pub mod blob;
pub mod did;
pub mod master;
pub mod revoke;
pub mod runtime_api;

#[cfg(test)]
mod test_common;
