#![allow(unused_lifetimes)]
use super::TypesAndLimits;

crate::def_state_change! {
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
        offchain_signatures::AddOffchainSignatureParams,
        offchain_signatures::AddOffchainSignaturePublicKey,
        offchain_signatures::RemoveOffchainSignatureParams,
        offchain_signatures::RemoveOffchainSignaturePublicKey,
        accumulator::AddAccumulatorParams,
        accumulator::AddAccumulatorPublicKey,
        accumulator::RemoveAccumulatorParams,
        accumulator::RemoveAccumulatorPublicKey,
        accumulator::AddAccumulator,
        accumulator::UpdateAccumulator,
        accumulator::RemoveAccumulator,
        status_list_credential::UpdateStatusListCredential,
        status_list_credential::RemoveStatusListCredential
}

/// Converts the given entity to the state change.
pub trait ToStateChange<T: TypesAndLimits> {
    /// Converts the given entity to the state change.
    fn to_state_change(&self) -> StateChange<'_, T>;
}
