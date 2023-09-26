use super::*;
use crate::tests::common::*;
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
            (0, Some(vec![].try_into().unwrap()), 1 + 2),
            (0, Some(vec![0].try_into().unwrap()), 1 + 3),
            (0, Some(vec![0; 63].try_into().unwrap()), 1 + 63 + 2),
            (0, Some(vec![0; 64].try_into().unwrap()), 1 + 64 + 3),
            (0, Some(vec![0; 256].try_into().unwrap()), 1 + 256 + 3),
            (63, Some(vec![0; 256].try_into().unwrap()), 1 + 256 + 3),
            (64, Some(vec![0; 256].try_into().unwrap()), 2 + 256 + 3),
        ]
        .iter()
        .cloned()
        {
            assert_eq!(
                Attestation::<Test> { priority, iri }.encode().len(),
                expected_size
            );
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
                attest: att,
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
        check_nonce(&did, 10);

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
        check_nonce(&did, 10 + 1);
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
                iri: Some(vec![0].try_into().unwrap()),
            },
            &kp,
            11 + 1,
        )
        .unwrap();
        check_nonce(&did, 11 + 1);

        assert_eq!(
            set_claim(
                &did,
                &Attestation {
                    priority: 2,
                    iri: Some(vec![0, 2, 3].try_into().unwrap()),
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
            check_nonce(&did, nonce - 1);

            let _ = set_claim(
                &did,
                &Attestation {
                    priority: *priority,
                    iri: None,
                },
                &kp,
                nonce,
            )
            .map(|_| {
                check_nonce(&did, nonce);
                nonce += 1;
            });
        }
        assert_eq!(
            Attestations::<Test>::get(did).priority,
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
        check_nonce(&did, 10);

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
        check_nonce(&did, 10 + 1);
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
            Attestations::<Test>::get(did),
            Attestation {
                priority: 0,
                iri: None,
            }
        );
        check_nonce(&did, 10);
        set_claim(
            &did,
            &Attestation {
                priority: 1,
                iri: Some(vec![0, 1, 2].try_into().unwrap()),
            },
            &kp,
            10 + 1,
        )
        .unwrap();
        check_nonce(&did, 10 + 1);
        assert_eq!(
            Attestations::<Test>::get(did),
            Attestation {
                priority: 1,
                iri: Some(vec![0, 1, 2].try_into().unwrap()),
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
            let nonce = 10 + 1 + i as u64;
            check_nonce(&did, nonce - 1);
            set_claim(
                &did,
                &Attestation {
                    priority: *priority,
                    iri: None,
                },
                &kp,
                nonce,
            )
            .unwrap();
            check_nonce(&did, nonce);
        }
    });
}

/// helper
fn set_claim(
    claimer: &Attester,
    att: &Attestation<Test>,
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
            *claimer,
            1,
        ),
    )
}
