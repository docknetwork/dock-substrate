//! This module allows DIDs to publically attests to arbirary (and arbitrarily large) RDF
//! claimgraphs. These attestations are not stored on-chain; rather, the attester chooses a storage
//! method by specifying an Iri.

use crate::{
    common::{signatures::ForSigType, Limits, TypesAndLimits},
    did::{
        self, AuthorizeAction, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature,
        SignedActionWithNonce,
    },
    util::BoundedBytes,
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::DispatchResult, ensure, weights::Weight, CloneNoBound, DebugNoBound, DefaultNoBound,
    EqNoBound, PartialEqNoBound,
};
use frame_system::ensure_signed;
use sp_std::{fmt::Debug, prelude::*};
use weights::*;

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

pub type Iri<T> = BoundedBytes<<T as Limits>::MaxIriSize>;

/// Attester is a DID giving an attestation to arbitrary (and arbitrarily large) RDF claimgraphs.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Attester(pub DidOrDidMethodKey);

impl AuthorizeAction<(), DidKey> for Attester {}
impl AuthorizeAction<(), DidMethodKey> for Attester {}

crate::impl_wrapper!(Attester(DidOrDidMethodKey));

#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    DebugNoBound,
    DefaultNoBound,
    EqNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct Attestation<T: Limits> {
    #[codec(compact)]
    pub priority: u64,
    pub iri: Option<Iri<T>>,
}

#[derive(
    Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound, Default,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct SetAttestationClaim<T: TypesAndLimits> {
    pub attest: Attestation<T>,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! { for (): SetAttestationClaim with 1 as len, () as target }

#[frame_support::pallet]
pub mod pallet {
    use crate::did::DidOrDidMethodKeySignature;

    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {}

    /// Error for the attest module.
    #[pallet::error]
    pub enum Error<T> {
        /// The Attestation was not posted because its priority was less than or equal to that of
        /// an attestation previously posted by the same entity.
        ///
        /// Note, the default value for an attestation is the null claim (claiming nothing), with
        /// a priority of 0. To override this initial value, a priority of 1 or greater is required.
        /// Check to see that the provided priority is not zero as that could be the cause of this
        /// error.
        PriorityTooLow,
    }

    /// The priority value provides replay protection and also gives attestations a partial
    /// ordering. Signatures with lesser or equal priority to those previously posted by the same
    /// entity are not accepted by the chain.
    ///
    /// Notice that priority is not a block-number. This is intentional as it yields some desired
    /// properties and allows some potential use-cases:
    ///   - When publishing consecutive attestations, the attester need not care at which block a
    ///     a previous attestation was included. This means attestations can be made over a
    ///     mono-directional channel.
    ///   - Timestamps may be used as priority when available.
    ///   - A timeline of future attestations may be constructed by encrypting multiple
    ///     signatures, each with the output of a verifiable delay function. A "final"
    ///     attestation may be selected by assigning it the highest priority in the batch.
    ///     The "final" attestation will be acceptable by the runtime regardless of whether its
    ///     predecessors were submitted.
    ///
    /// An attestation on chain with iri set to None is semantically meaningless. Setting the
    /// iri to None is equivalent to attesting to the empty claimgraph.
    ///
    /// When Attestations::get(did).iri == Some(dat) and dat is a valid utf-8 Iri:
    /// `[did dock:attestsDocumentContents dat]`.
    #[pallet::storage]
    #[pallet::getter(fn attestation)]
    pub type Attestations<T: Config> =
        StorageMap<_, Blake2_128Concat, Attester, Attestation<T>, ValueQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(SubstrateWeight::<T>::set_claim(attests, signature))]
        pub fn set_claim(
            origin: OriginFor<T>,
            attests: SetAttestationClaim<T>,
            signature: DidOrDidMethodKeySignature<Attester>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            SignedActionWithNonce::new(attests, signature).execute(Self::set_claim_)
        }
    }

    impl<T: Config> Pallet<T> {
        fn set_claim_(
            SetAttestationClaim { attest, .. }: SetAttestationClaim<T>,
            attester: Attester,
        ) -> DispatchResult {
            let prev = Attestations::<T>::get(attester);
            ensure!(prev.priority < attest.priority, Error::<T>::PriorityTooLow);

            // execute
            Attestations::insert(attester, &attest);

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            use did::Did;
            use frame_support::storage_alias;

            let mut reads_writes = 0;

            let attestations: Vec<_> = {
                #[storage_alias]
                pub type Attestations<T: Config> =
                    StorageMap<Pallet<T>, Blake2_128Concat, Did, Attestation<T>, ValueQuery>;

                Attestations::<T>::drain()
                    .map(|(did, attest): (Did, _)| (Attester(did.into()), attest))
                    .collect()
            };

            reads_writes += attestations.len() as u64;
            for (did, attest) in attestations {
                Attestations::<T>::insert(did, attest);
            }

            T::DbWeight::get().reads_writes(reads_writes, reads_writes)
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn set_claim(
        SetAttestationClaim { attest, .. }: &SetAttestationClaim<T>,
        sig: &DidOrDidMethodKeySignature<Attester>,
    ) -> Weight {
        let len = attest.iri.as_ref().map_or(0, |v| v.len()) as u32;

        sig.weight_for_sig_type::<T>(
            || Self::set_claim_sr25519(len),
            || Self::set_claim_ed25519(len),
            || Self::set_claim_secp256k1(len),
        )
    }
}
