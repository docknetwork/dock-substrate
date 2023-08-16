use super::*;
use crate::{
    common::{Policy, PolicyValidationError, ToStateChange},
    did::Did,
    tests::common::*,
    util::{Action, WithNonce},
};
use alloc::collections::BTreeMap;
use core::{iter::empty, marker::PhantomData};
use frame_support::{assert_noop, assert_ok};
use sp_core::sr25519;
use sp_runtime::DispatchError;

type Mod = super::Pallet<Test>;

pub fn get_pauth<A: Action<Test> + Clone>(
    action: &A,
    signers: &[(Did, &sr25519::Pair)],
) -> Vec<DidSignatureWithNonce<Test>>
where
    WithNonce<Test, A>: ToStateChange<Test>,
{
    signers
        .iter()
        .map(|(did, kp)| {
            let did_detail = DIDModule::onchain_did_details(&did).unwrap();
            let next_nonce = did_detail.next_nonce().unwrap();
            let action_with_nonce =
                WithNonce::<Test, _>::new_with_nonce(action.clone(), next_nonce);
            let state_change = action_with_nonce.to_state_change().encode();
            let sig = did_sig_on_bytes::<Test, _>(&state_change, &kp, did.clone(), 1);

            DidSignatureWithNonce {
                sig,
                nonce: next_nonce,
            }
        })
        .collect()
}

pub fn get_nonces(signers: &[(Did, &sr25519::Pair)]) -> BTreeMap<Did, u64> {
    let mut nonces = BTreeMap::new();
    for (d, _) in signers {
        let did_detail = DIDModule::onchain_did_details(d).unwrap();
        nonces.insert(*d, did_detail.nonce);
    }
    nonces
}

pub fn check_nonce_increase(old_nonces: BTreeMap<Did, u64>, signers: &[(Did, &sr25519::Pair)]) {
    let new_nonces = get_nonces(&signers);
    assert_eq!(new_nonces.len(), old_nonces.len());
    for (d, new_nonce) in new_nonces {
        assert_eq!(old_nonces.get(&d).unwrap() + 1, new_nonce);
    }
}

/// Checks auth mechanics for the `StatusListCredential` module.
#[test]
fn ensure_auth() {
    ext().execute_with(|| {
        run_to_block(10);

        let (a, b, c): (Did, Did, Did) = (Did(random()), Did(random()), Did(random()));
        let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));

        let cases: [(u32, Policy, &[(Did, &sr25519::Pair)], bool); 11] = [
            (line!(), Policy::one_of(&[a]), &[(a, &kpa)], true),
            (line!(), Policy::one_of(&[a, b]), &[(a, &kpa)], true),
            (line!(), Policy::one_of(&[a, b]), &[(b, &kpb)], true),
            (line!(), Policy::one_of(&[a]), &[], false), // provide no signatures
            (line!(), Policy::one_of(&[a]), &[(b, &kpb)], false), // wrong account; wrong key
            (line!(), Policy::one_of(&[a]), &[(a, &kpb)], false), // correct account; wrong key
            (line!(), Policy::one_of(&[a]), &[(a, &kpb)], false), // wrong account; correct key
            (line!(), Policy::one_of(&[a, b]), &[(c, &kpc)], false), // account not a controller
            (
                line!(),
                Policy::one_of(&[a, b]),
                &[(a, &kpa), (b, &kpb)],
                false,
            ), // two signers
            (line!(), Policy::one_of(&[a]), &[], false), // one controller; no sigs
            (line!(), Policy::one_of(&[a, b]), &[], false), // two controllers; no sigs
        ];
        for (i, (line_no, policy, signers, expect_success)) in cases.into_iter().enumerate() {
            eprintln!("running case from line {}", line_no);
            let id = StatusListCredentialId(rand::random());

            Mod::create_(
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::RevocationList2020Credential(
                        (0..10).map(|v| v as u8).collect(),
                    ),
                    policy: policy.clone(),
                },
            )
            .unwrap();

            let command = UpdateStatusListCredentialRaw {
                /// Unique identifier of the StatusListCredential
                id,
                /// StatusListCredential itself
                credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect(),
                ),
                _marker: PhantomData,
            };
            let old_nonces = get_nonces(signers);
            let proof = get_pauth(&command, &signers[..]);
            let res = Mod::try_exec_action_over_status_list_credential(
                |_, _| Ok::<_, DispatchError>(()),
                command.clone(),
                proof,
            );
            assert_eq!(res.is_ok(), expect_success);
            if expect_success {
                check_nonce_increase(old_nonces, signers);
            }

            let command = RemoveStatusListCredentialRaw {
                id,
                _marker: PhantomData,
            };

            let old_nonces = get_nonces(signers);
            let proof = get_pauth(&command, &signers[..]);
            let res = Mod::try_exec_action_over_status_list_credential(
                |_, _| Ok::<_, DispatchError>(()),
                command.clone(),
                proof,
            );
            assert_eq!(res.is_ok(), expect_success);

            if expect_success {
                check_nonce_increase(old_nonces, signers);
            }
            run_to_block(10 + 1 + i as u64);
        }
    })
}

/// Checks creation mechanism of the `StatusListCredential`.
#[test]
fn create_status_list_credential() {
    ext().execute_with(|| {
        let did = Did(random());
        let policy = Policy::one_of(&[did]);
        let id = StatusListCredentialId(rand::random());

        assert_noop!(
            Mod::create(
                Origin::signed(ABBA),
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::RevocationList2020Credential(
                        (0..10_000).map(|v| v as u8).collect(),
                    ),
                    policy: policy.clone(),
                }
            ),
            StatusListCredentialError::<Test>::StatusListCredentialTooBig
        );
        assert_noop!(
            Mod::create(
                Origin::signed(ABBA),
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::RevocationList2020Credential(
                        (0..5).map(|v| v as u8).collect(),
                    ),
                    policy: policy.clone(),
                }
            ),
            StatusListCredentialError::<Test>::StatusListCredentialTooSmall
        );
        assert_noop!(
            Mod::create(
                Origin::signed(ABBA),
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::StatusList2021Credential(
                        (0..10).map(|v| v as u8).collect(),
                    ),
                    policy: Policy::one_of(empty::<Did>()),
                }
            ),
            PolicyValidationError::Empty
        );
        assert_noop!(
            Mod::create(
                Origin::signed(ABBA),
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::StatusList2021Credential(
                        (0..10).map(|v| v as u8).collect(),
                    ),
                    policy: Policy::one_of(core::iter::repeat_with(|| Did(random())).take(16)),
                }
            ),
            PolicyValidationError::TooManyControllers
        );

        Mod::create_(
            id,
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect(),
                ),
                policy: policy.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            Mod::status_list_credential(id).unwrap(),
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect()
                ),
                policy: policy.clone()
            }
        );

        assert_noop!(
            Mod::create(
                Origin::signed(ABBA),
                id,
                StatusListCredentialWithPolicy {
                    status_list_credential: StatusListCredential::StatusList2021Credential(
                        (0..10).map(|v| v as u8).collect(),
                    ),
                    policy: Policy::one_of(core::iter::repeat_with(|| Did(random())).take(16)),
                }
            ),
            StatusListCredentialError::<Test>::StatusListCredentialAlreadyExists
        );
    });
}

/// Checks update mechanism of the `StatusListCredential`.
#[test]
fn update_status_list_credential() {
    ext().execute_with(|| {
        let did = Did(random());
        let keypair = create_did(did);
        let policy = Policy::one_of(&[did]);
        let id = StatusListCredentialId(rand::random());

        Mod::create_(
            id,
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect(),
                ),
                policy: policy.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            Mod::status_list_credential(id).unwrap(),
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect()
                ),
                policy: policy.clone()
            }
        );

        let update = UpdateStatusListCredentialRaw {
            id,
            credential: StatusListCredential::StatusList2021Credential(
                (0..10).map(|v| v as u8).collect(),
            ),
            _marker: PhantomData,
        };
        let auth = get_pauth(&update, &[(did, &keypair)][..]);

        assert_ok!(Mod::update(Origin::signed(ABBA), update, auth));
        assert_eq!(
            Mod::status_list_credential(id).unwrap(),
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect()
                ),
                policy: policy.clone()
            }
        );

        let update = UpdateStatusListCredentialRaw {
            id,
            credential: StatusListCredential::StatusList2021Credential(
                (0..10_000).map(|v| v as u8).collect(),
            ),
            _marker: PhantomData,
        };
        let auth = get_pauth(&update, &[(did, &keypair)][..]);
        assert_noop!(
            Mod::update(Origin::signed(ABBA), update, auth),
            StatusListCredentialError::<Test>::StatusListCredentialTooBig
        );
        let update = UpdateStatusListCredentialRaw {
            id,
            credential: StatusListCredential::StatusList2021Credential(
                (0..5).map(|v| v as u8).collect(),
            ),
            _marker: PhantomData,
        };
        let auth = get_pauth(&update, &[(did, &keypair)][..]);
        assert_noop!(
            Mod::update(Origin::signed(ABBA), update, auth),
            StatusListCredentialError::<Test>::StatusListCredentialTooSmall
        );
    });
}

/// Checks removal mechanism of the `StatusListCredential`.
#[test]
fn remove_status_list_credential() {
    ext().execute_with(|| {
        let did = Did(random());
        let keypair = create_did(did);
        let policy = Policy::one_of(&[did]);
        let id = StatusListCredentialId(rand::random());

        Mod::create_(
            id,
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect(),
                ),
                policy: policy.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            Mod::status_list_credential(id).unwrap(),
            StatusListCredentialWithPolicy {
                status_list_credential: StatusListCredential::StatusList2021Credential(
                    (0..10).map(|v| v as u8).collect()
                ),
                policy: policy.clone()
            }
        );

        let remove = RemoveStatusListCredentialRaw {
            id,
            _marker: PhantomData,
        };
        let auth = get_pauth(&remove, &[(did, &keypair)][..]);

        assert_ok!(Mod::remove(Origin::signed(ABBA), remove, auth));
        assert_eq!(Mod::status_list_credential(id), None);

        let remove = RemoveStatusListCredentialRaw {
            id,
            _marker: PhantomData,
        };
        let auth = get_pauth(&remove, &[(did, &keypair)][..]);
        assert_noop!(
            Mod::remove(Origin::signed(ABBA), remove, auth),
            PolicyExecutionError::NoEntity
        );
    });
}
