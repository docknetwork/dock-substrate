//! This module allows DIDs to publically attests to arbirary (and arbitrarily large) RDF
//! claimgraphs. These attestations are not stored on-chain; rather, the attester chooses a storage
//! method by specifying an Iri.

use crate::did::{self, Did, DidSignature};
use crate::StateChange;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};

pub type Iri = Vec<u8>;

pub trait Trait: system::Trait + did::Trait {
    /// The cost charged by the network to store a single byte in chain-state for the life of the
    /// chain.
    type StorageWeight: Get<Weight>;
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attestation {
    #[codec(compact)]
    priority: u64,
    iri: Option<Iri>,
}

decl_error! {
    /// Error for the attest module.
    pub enum Error for Module<T: Trait> {
        /// The Attestation was not posted because its priority was less than or equal to that of
        /// an attestation previously posted by the same entity.
        ///
        /// Note, the default value for an attestation is the null claim (claiming nothing), with
        /// a priority of 0. To override this initial value, a priority of 1 or greater is required.
        /// Check to see that the provided priority is not zero as that could be the cause of this
        /// error.
        PriorityTooLow,
        /// Signature verification failed while adding blob
        InvalidSig
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Blob {
        // The priority value provides replay protection and also gives attestations a paritial
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
        //     attestation may be selected by assigning it the higest prority in the batch.
        //     The "final" attestation will be acceptable by the runtime regardless of whether its
        //     predecessors were submitted.
        //
        // An attestation on chain with iri set to None is sematically meaningless. Setting the
        // iri to None is equivalent to attesting to the empty claimgraph.
        //
        // When Attestations::get(did).iri == Some(dat) and dat is a valid utf-8 Iri:
        // `[did dock:attestsDocumentContents dat]`.
        Attestations: map hasher(blake2_128_concat) Did => Attestation;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        #[weight = {
            T::DbWeight::get().reads_writes(2, 1)
                + signature.weight()
                + attests
                    .iri
                    .as_ref()
                    .map(|iri| iri.len())
                    .unwrap_or_default() as Weight
                    * T::StorageWeight::get()
        }]
        fn set_claim(
            origin,
            attester: Did,
            attests: Attestation,
            signature: DidSignature,
        ) -> DispatchResult {
            Module::<T>::set_claim_(origin, attester, attests, signature)
        }
    }
}

impl<T: Trait> Module<T> {
    fn set_claim_(
        origin: <T as system::Trait>::Origin,
        attester: Did,
        attests: Attestation,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        let payload = StateChange::Attestation((attester, attests.clone())).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &attester)?;
        ensure!(valid, Error::<T>::InvalidSig);
        let prev = Attestations::get(&attester);
        ensure!(prev.priority < attests.priority, Error::<T>::PriorityTooLow);

        // execute
        Attestations::insert(&attester, &attests);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    /// Trigger the PriorityTooLow error
    #[test]
    fn priority_too_low() {
        unimplemented!()
    }

    /// assert sizes of encoded Attestation
    #[test]
    fn encoded_attestation_size() {
        unimplemented!()
    }

    /// Trigger the InvalidSig error by tweaking a value in the plaintext after signing
    #[test]
    fn invalid_sig() {
        unimplemented!()
    }

    /// Attestations with equal priority are mutually exlusive
    #[test]
    fn priority_face_off() {
        unimplemented!()
    }

    /// After attempting a set of attestations the one with highest priority is the one that ends up
    /// in chain state.
    #[test]
    fn priority_battle_royale() {
        unimplemented!()
    }

    /// An attestation with priority set to the highest value is final.
    /// It does not trigger a panic by integer overflow.
    #[test]
    fn max_priority_is_final() {
        unimplemented!()
    }
}
