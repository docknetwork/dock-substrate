//! This module allows DIDs to publically attests to arbirary (and arbitrarily large) RDF
//! claimgraphs. These attestations are not stored on-chain; rather, the attester chooses a storage
//! method by specifying an Iri.

use crate::did::{self, Did, DidSignature};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_std::vec::Vec;

pub type Iri = Vec<u8>;

/// Attester is a DID giving an attestation to arbitrary (and arbitrarily large) RDF claimgraphs.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Attester(pub Did);

crate::impl_wrapper!(Attester, Did, for test use tests with rand Did(rand::random()));

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
        #[weight = {
            T::DbWeight::get().reads_writes(2, 1)
                + signature.weight()
                + attests
                    .attest
                    .iri
                    .as_ref()
                    .map(|iri| iri.len())
                    .unwrap_or_default() as Weight
                    * T::StorageWeight::get()
        }]
        fn set_claim(
            origin,
            attests: SetAttestationClaim<T>,
            signature: DidSignature<Attester>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(attests, signature, Self::set_claim_)
            // Self::set_claim_(attests, signature.did)
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_common::*;
    use sp_core::sr25519;

    type Er = crate::attest::Error<Test>;

    /// Trigger the PriorityTooLow error by submitting a priority 0 attestation.
    #[test]
    fn priority_too_low() {
        ext().execute_with(|| {
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);
            let att = Attestation {
                priority: 0,
                iri: None,
            };
            let err = AttestMod::set_claim(
                Origin::signed(0),
                SetAttestationClaim {
                    attest: att.clone(),
                    nonce: 10 + 1,
                },
                did_sig::<Test, _, _>(
                    &SetAttestationClaim {
                        attest: att,
                        nonce: 10 + 1,
                    },
                    &kp,
                    did,
                    1,
                ),
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

    /// Trigger the InvalidSignature error by tweaking a value in the plaintext after signing
    #[test]
    fn invalid_sig_a() {
        ext().execute_with(|| {
            run_to_block(10);

            let (dida, kpa) = newdid();
            let mut att = Attestation {
                priority: 1,
                iri: None,
            };
            let sig = did_sig::<Test, _, _>(
                &SetAttestationClaim {
                    attest: att.clone(),
                    nonce: 10 + 1,
                },
                &kpa,
                Attester(dida),
                1,
            );
            // Modify payload so sig doesn't match
            att.priority += 1;
            let err = AttestMod::set_claim(
                Origin::signed(0),
                SetAttestationClaim {
                    attest: att.clone(),
                    nonce: 10 + 2,
                },
                sig,
            )
            .unwrap_err();
            assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
        });
    }

    /// Trigger the InvalidSignature error using a different did for signing
    #[test]
    fn invalid_sig_b() {
        ext().execute_with(|| {
            run_to_block(10);

            let (dida, _kpa) = newdid();
            let (_didb, kpb) = newdid();
            let att = Attestation {
                priority: 1,
                iri: None,
            };
            let err = AttestMod::set_claim(
                Origin::signed(0),
                SetAttestationClaim {
                    attest: att.clone(),
                    nonce: 10 + 1,
                },
                did_sig::<Test, _, _>(
                    &SetAttestationClaim {
                        attest: att,
                        nonce: 10 + 1,
                    },
                    &kpb,
                    Attester(dida),
                    1,
                ),
            )
            .unwrap_err();
            assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
        });
    }

    /// Attestations with equal priority are mutually exlusive
    #[test]
    fn priority_face_off() {
        ext().execute_with(|| {
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);

            // same iri
            set_claim(
                &did,
                &Attestation {
                    priority: 1,
                    iri: None,
                },
                &kp,
                10 + 1,
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
                    11 + 1
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
                11 + 1,
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
                    12 + 1
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
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);
            let prios: Vec<u64> = (0..200).map(|_| rand::random::<u64>()).collect();
            let mut nonce = 10 + 1;
            for priority in &prios {
                let _ = set_claim(
                    &did,
                    &Attestation {
                        priority: *priority,
                        iri: None,
                    },
                    &kp,
                    nonce,
                )
                .and_then(|_| {
                    nonce += 1;
                    Ok(())
                });
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
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);
            set_claim(
                &did,
                &Attestation {
                    priority: u64::max_value(),
                    iri: None,
                },
                &kp,
                10 + 1,
            )
            .unwrap();
            let err = set_claim(
                &did,
                &Attestation {
                    priority: u64::max_value(),
                    iri: None,
                },
                &kp,
                11 + 1,
            )
            .unwrap_err();
            assert_eq!(err, Er::PriorityTooLow.into());
        });
    }

    /// Set an attestation that is not None
    #[test]
    fn set_some_attestation() {
        ext().execute_with(|| {
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);
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
                10 + 1,
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
            run_to_block(10);

            let (did, kp) = newdid();
            let did = Attester(did);
            for (i, priority) in [1, 2, 4].iter().enumerate() {
                set_claim(
                    &did,
                    &Attestation {
                        priority: *priority,
                        iri: None,
                    },
                    &kp,
                    10 + 1 + i as u64,
                )
                .unwrap();
            }
        });
    }

    /// helper
    fn set_claim(
        claimer: &Attester,
        att: &Attestation,
        kp: &sr25519::Pair,
        nonce: u64,
    ) -> DispatchResult {
        AttestMod::set_claim(
            Origin::signed(0),
            SetAttestationClaim {
                attest: att.clone(),
                nonce,
            },
            did_sig::<Test, _, _>(
                &SetAttestationClaim {
                    attest: att.clone(),
                    nonce,
                },
                kp,
                claimer.clone(),
                1,
            ),
        )
    }
}
