//! This module allows DIDs to publically attests to arbirary (and arbitrarily large) RDF
//! claimgraphs. These attestations are not stored on-chain; rather, the attester chooses a storage
//! method by specifying an Iri.

use crate::{
    did::{self, Did, DidSignature},
    keys_and_sigs::SigValue,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_std::vec::Vec;
use weights::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

pub type Iri = Vec<u8>;

/// Attester is a DID giving an attestation to arbitrary (and arbitrarily large) RDF claimgraphs.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Attester(pub Did);

crate::impl_wrapper!(Attester, Did, for rand use Did(rand::random()), with tests as attester_tests);

pub trait Config: system::Config + did::Config {
    /// The cost charged by the network to store a single byte in chain-state for the life of the
    /// chain.
    type StorageWeight: Get<Weight>;
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attestation {
    #[codec(compact)]
    pub priority: u64,
    pub iri: Option<Iri>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetAttestationClaim<T: frame_system::Config> {
    pub attest: Attestation,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! { for (): SetAttestationClaim with 1 as len, () as target }

decl_error! {
    /// Error for the attest module.
    pub enum Error for Module<T: Config> where T: Debug {
        /// The Attestation was not posted because its priority was less than or equal to that of
        /// an attestation previously posted by the same entity.
        ///
        /// Note, the default value for an attestation is the null claim (claiming nothing), with
        /// a priority of 0. To override this initial value, a priority of 1 or greater is required.
        /// Check to see that the provided priority is not zero as that could be the cause of this
        /// error.
        PriorityTooLow,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Attest where T: Debug {
        // The priority value provides replay protection and also gives attestations a partial
        // ordering. Signatures with lesser or equal priority to those previously posted by the same
        // entity are not accepted by the chain.
        //
        // Notice that priority is not a block-number. This is intentional as it yields some desired
        // properties and allows some potential use-cases:
        //   - When publishing consecutive attestations, the attester need not care at which block a
        //     a previous attestation was included. This means attestations can be made over a
        //     mono-directional channel.
        //   - Timestamps may be used as priority when available.
        //   - A timeline of future attestations may be constructed by encrypting multiple
        //     signatures, each with the output of a verifiable delay function. A "final"
        //     attestation may be selected by assigning it the highest priority in the batch.
        //     The "final" attestation will be acceptable by the runtime regardless of whether its
        //     predecessors were submitted.
        //
        // An attestation on chain with iri set to None is semantically meaningless. Setting the
        // iri to None is equivalent to attesting to the empty claimgraph.
        //
        // When Attestations::get(did).iri == Some(dat) and dat is a valid utf-8 Iri:
        // `[did dock:attestsDocumentContents dat]`.
        Attestations: map hasher(blake2_128_concat) Attester => Attestation;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        #[weight = SubstrateWeight::<T>::set_claim(&attests, &signature)]
        fn set_claim(
            origin,
            attests: SetAttestationClaim<T>,
            signature: DidSignature<Attester>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(Self::set_claim_, attests, signature)
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn set_claim_(
        SetAttestationClaim { attest, .. }: SetAttestationClaim<T>,
        attester: Attester,
    ) -> DispatchResult {
        let prev = Attestations::get(attester);
        ensure!(prev.priority < attest.priority, Error::<T>::PriorityTooLow);

        // execute
        Attestations::insert(&attester, &attest);

        Ok(())
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn set_claim(
        SetAttestationClaim { attest, .. }: &SetAttestationClaim<T>,
        DidSignature { sig, .. }: &DidSignature<Attester>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::set_claim_sr25519,
            SigValue::Ed25519(_) => Self::set_claim_ed25519,
            SigValue::Secp256k1(_) => Self::set_claim_secp256k1,
        })(attest.iri.as_ref().map_or(0, |v| v.len()) as u32)
    }
}
