//! This module allows DIDs to publically attests to arbirary (and arbitrarily large) RDF
//! claimgraphs. These attestations are not stored on-chain; rather, the attester chooses a storage
//! method by specifying an Iri.

// TODO: Nonce is not nonce becuase it's ok to use it more than once.
//       Rename it to somthing like "priority".

use crate as dock;
use crate::did::{self, Did, DidSignature};
use alloc::vec::Vec;
use codec::Compact;
use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};

pub type Iri = Vec<u8>;

pub trait Trait: system::Trait + did::Trait {}

decl_error! {
    /// Error for the attest module.
    pub enum Error for Module<T: Trait> {
        /// There is no such DID registered
        DidDoesNotExist,
        /// Signature verification failed while adding blob
        InvalidSig
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Blob {
        // The nonce value provides replay protection, and also gives attestations a paritial
        // ordering. Signatures with lesser or equal nonces to those previously posted by the same
        // entity are not accepted by the chain.
        //
        // Notice that nonce is not a block-number. This is intentional as it yields some desired
        // properties and potential use-cases:
        //   - When publishing consecutive attestations, the attester need not care at which block a
        //     a previous attestation was included. This means attestations can be made over a
        //     mono-directional channel.
        //   - Timestamps may be used as nonces when available.
        //   - A timeline of future attestations may be constructed by encrypting multiple
        //     signatures, each with the output of it's own verifiable delay function. A "final"
        //     attestation may be selected by assigning it the higest nonce. The "final" attestation
        //     will be acceptable by the runtime regardless of whether its predecessors were
        //     submitted.
        //
        // A claim with the Iri set to None is sematically meaningless. Setting the Iri to None
        // is equivalent to attesting to the empty claimgraph.
        //
        // While Attests::get(Did) is (_, Some(iri)), `[did dock:attestsDocumentContents iri]`.
        Attests: map hasher(blake2_128_concat) Did => (
            /* nonce */ Compact<u64>,
            /* url to claim */ Option<Iri>,
        );
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        #[weight = T::DbWeight::get().reads_writes(unimplemented!(), unimplemented!())
          + signature.weight()
          + (1_100 * iri.map(|uri| uri.len()).unwrap_or_default()) as Weight]
        fn set_claim(
            origin,
            claimer: Did,
            nonce: T::BlockNumber,
            iri: Option<Iri>,
            signature: DidSignature
        ) -> DispatchResult {
            unimplemented!()
        }
    }
}

impl<T: Trait> Module<T> {
    fn set_claim_(
        origin: <T as system::Trait>::Origin,
        claimer: Did,
        claim: Option<Iri>,
        effective: T::BlockNumber,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check

        // execute

        unimplemented!()
    }
}
