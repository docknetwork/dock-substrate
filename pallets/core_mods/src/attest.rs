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

pub trait Trait: system::Config + did::Trait {
    /// The cost charged by the network to store a single byte in chain-state for the life of the
    /// chain.
    type StorageWeight: Get<Weight>;
}

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attestation {
    #[codec(compact)]
    priority: u64,
    pub iri: Option<Iri>,
}
impl Attestation {
    /// Create new Attestation
    pub fn new(priority: u64, iri: Option<Iri>) -> Self {
        Attestation { priority, iri }
    }
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
        origin: <T as system::Config>::Origin,
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
    use super::*;
    use crate::test_common::*;
    use sp_core::sr25519;

    type Mod = crate::attest::Module<Test>;
    type Er = crate::attest::Error<Test>;

    /// Trigger the PriorityTooLow error by submitting a priority 0 attestation.
    #[test]
    fn priority_too_low() {
        ext().execute_with(|| {
            let (did, kp) = newdid();
            let att = Attestation {
                priority: 0,
                iri: None,
            };
            let err = Mod::set_claim(
                Origin::signed(0),
                did,
                att.clone(),
                sign(&StateChange::Attestation((did, att)), &kp),
            )
            .unwrap_err();
            assert_eq!(err, Er::PriorityTooLow.into());
        });
    }

    /// assert sizes of encoded Attestation
    #[test]
    fn encoded_attestation_size() {
        ext().execute_with(|| {
            for (priority, iri, expected_size) in [
                (0, None, 1 + 1),
                (63, None, 1 + 1),
                (64, None, 2 + 1),
                (256, None, 2 + 1),
                (0, Some(vec![]), 1 + 2),
                (0, Some(vec![0]), 1 + 3),
                (0, Some(vec![0; 63]), 1 + 63 + 2),
                (0, Some(vec![0; 64]), 1 + 64 + 3),
                (0, Some(vec![0; 256]), 1 + 256 + 3),
                (63, Some(vec![0; 256]), 1 + 256 + 3),
                (64, Some(vec![0; 256]), 2 + 256 + 3),
            ]
            .iter()
            .cloned()
            {
                assert_eq!(Attestation { priority, iri }.encode().len(), expected_size);
            }
        });
    }

    /// Trigger the InvalidSig error by tweaking a value in the plaintext after signing
    #[test]
    fn invalid_sig_a() {
        ext().execute_with(|| {
            let (dida, kpa) = newdid();
            let mut att = Attestation {
                priority: 1,
                iri: None,
            };
            let sig = sign(&StateChange::Attestation((dida, att.clone())), &kpa);
            att.priority += 1;
            let err = Mod::set_claim(Origin::signed(0), dida, att, sig).unwrap_err();
            assert_eq!(err, Er::InvalidSig.into());
        });
    }

    /// Trigger the InvalidSig error using a different did for signing
    #[test]
    fn invalid_sig_b() {
        ext().execute_with(|| {
            let (dida, _kpa) = newdid();
            let (_didb, kpb) = newdid();
            let att = Attestation {
                priority: 1,
                iri: None,
            };
            let err = Mod::set_claim(
                Origin::signed(0),
                dida,
                att.clone(),
                sign(&StateChange::Attestation((dida, att)), &kpb),
            )
            .unwrap_err();
            assert_eq!(err, Er::InvalidSig.into());
        });
    }

    /// Attestations with equal priority are mutually exlusive
    #[test]
    fn priority_face_off() {
        ext().execute_with(|| {
            let (did, kp) = newdid();

            // same iri
            set_claim(
                &did,
                &Attestation {
                    priority: 1,
                    iri: None,
                },
                &kp,
            )
            .unwrap();
            assert_eq!(
                set_claim(
                    &did,
                    &Attestation {
                        priority: 1,
                        iri: None,
                    },
                    &kp,
                )
                .unwrap_err(),
                Er::PriorityTooLow.into()
            );

            // different iris
            set_claim(
                &did,
                &Attestation {
                    priority: 2,
                    iri: Some(vec![0]),
                },
                &kp,
            )
            .unwrap();
            assert_eq!(
                set_claim(
                    &did,
                    &Attestation {
                        priority: 2,
                        iri: Some(vec![0, 2, 3]),
                    },
                    &kp,
                )
                .unwrap_err(),
                Er::PriorityTooLow.into()
            );
        });
    }

    /// After attempting a set of attestations the one with highest priority is the one that ends up
    /// in chain state.
    #[test]
    fn priority_battle_royale() {
        ext().execute_with(|| {
            let (did, kp) = newdid();
            let prios: Vec<u64> = (0..200).map(|_| rand::random::<u64>()).collect();
            for priority in &prios {
                let _ = set_claim(
                    &did,
                    &Attestation {
                        priority: *priority,
                        iri: None,
                    },
                    &kp,
                );
            }
            assert_eq!(
                Attestations::get(did).priority,
                prios.iter().max().unwrap().clone()
            );
        });
    }

    /// An attestation with priority set to the highest value is final.
    /// It does not trigger a panic by integer overflow.
    #[test]
    fn max_priority_is_final() {
        ext().execute_with(|| {
            let (did, kp) = newdid();
            set_claim(
                &did,
                &Attestation {
                    priority: u64::max_value(),
                    iri: None,
                },
                &kp,
            )
            .unwrap();
            let err = set_claim(
                &did,
                &Attestation {
                    priority: u64::max_value(),
                    iri: None,
                },
                &kp,
            )
            .unwrap_err();
            assert_eq!(err, Er::PriorityTooLow.into());
        });
    }

    /// Set an attestation that is not None
    #[test]
    fn set_some_attestation() {
        ext().execute_with(|| {
            let (did, kp) = newdid();
            assert_eq!(
                Attestations::get(did),
                Attestation {
                    priority: 0,
                    iri: None,
                }
            );
            set_claim(
                &did,
                &Attestation {
                    priority: 1,
                    iri: Some(vec![0, 1, 2]),
                },
                &kp,
            )
            .unwrap();
            assert_eq!(
                Attestations::get(did),
                Attestation {
                    priority: 1,
                    iri: Some(vec![0, 1, 2]),
                }
            );
        });
    }

    /// Skip a priority value.
    #[test]
    fn skip_prio() {
        ext().execute_with(|| {
            let (did, kp) = newdid();
            for priority in &[1, 2, 4] {
                set_claim(
                    &did,
                    &Attestation {
                        priority: *priority,
                        iri: None,
                    },
                    &kp,
                )
                .unwrap();
            }
        });
    }

    /// helper
    fn set_claim(claimer: &did::Did, att: &Attestation, kp: &sr25519::Pair) -> DispatchResult {
        Mod::set_claim(
            Origin::signed(0),
            claimer.clone(),
            att.clone(),
            sign(
                &StateChange::Attestation((claimer.clone(), att.clone())),
                kp,
            ),
        )
    }
}
