#![allow(clippy::type_complexity)]

use super::*;
use crate::{
    common::{Policy, ToStateChange},
    did::Did,
    tests::common::*,
    util::{Action, WithNonce},
};
use alloc::collections::BTreeMap;
use frame_support::assert_noop;
use sp_core::{sr25519, U256};
use sp_std::{iter::once, marker::PhantomData};

pub fn get_pauth<A: Action + Clone>(
    action: &A,
    signers: &[(Did, &sr25519::Pair)],
) -> Vec<DidSignatureWithNonce<Test>>
where
    WithNonce<Test, A>: ToStateChange<Test>,
{
    signers
        .iter()
        .map(|(did, kp)| {
            let did_detail = DIDModule::onchain_did_details(did).unwrap();
            let next_nonce = did_detail.next_nonce().unwrap();
            let sp = WithNonce::<Test, _>::new_with_nonce(action.clone(), next_nonce);
            let sig = did_sig_on_bytes(&sp.to_state_change().encode(), kp, *did, 1);
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
    let new_nonces = get_nonces(signers);
    assert_eq!(new_nonces.len(), old_nonces.len());
    for (d, new_nonce) in new_nonces {
        assert_eq!(old_nonces.get(&d).unwrap() + 1, new_nonce);
    }
}

/// Tests every failure case in the module.
/// If a failure case is not covered, thats a bug.
/// If an error variant from Error is not covered, thats a bug.
///
/// Tests in this module are named after the errors they check.
/// For example, `#[test] fn invalidpolicy` exercises the Error::InvalidPolicy.
mod errors {
    use crate::common::{PolicyExecutionError, PolicyValidationError};

    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `tests::common`
    use super::*;
    use alloc::collections::BTreeSet;
    use frame_support::dispatch::DispatchError;

    #[test]
    fn invalidpolicy() {
        if !in_ext() {
            return ext().execute_with(invalidpolicy);
        }

        let ar = AddRegistry {
            id: RGA,
            new_registry: Registry {
                policy: Policy::one_of(None::<Did>).unwrap(),
                add_only: false,
            },
        };

        let err = RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap_err();
        assert_eq!(err, PolicyValidationError::Empty.into());
    }

    // this test has caught at least one bug
    #[test]
    fn notauthorized() {
        if !in_ext() {
            return ext().execute_with(notauthorized);
        }

        fn assert_revoke_err(
            policy: Policy<Test>,
            signers: &[(Did, &sr25519::Pair)],
        ) -> DispatchError {
            let regid: RegistryId = RegistryId(random());
            let ar = AddRegistry {
                id: regid,
                new_registry: Registry {
                    policy,
                    add_only: false,
                },
            };
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let rev = RevokeRaw {
                _marker: PhantomData,
                registry_id: regid,
                revoke_ids: random::<[[u8; 32]; 32]>()
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect(),
            };
            let pauth = get_pauth(&rev, signers);
            dbg!(&rev);
            dbg!(&pauth);
            RevoMod::revoke(Origin::signed(ABBA), rev, pauth).unwrap_err()
        }

        run_to_block(10);

        let (a, b, c) = (DIDA, DIDB, DIDC);
        let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));

        let cases: &[(Policy<Test>, &[(Did, &sr25519::Pair)], &str)] = &[
            (Policy::one_of([a]).unwrap(), &[], "provide no signatures"),
            (
                Policy::one_of([a]).unwrap(),
                &[(b, &kpb)],
                "wrong account; wrong key",
            ),
            (
                Policy::one_of([a]).unwrap(),
                &[(a, &kpb)],
                "correct account; wrong key",
            ),
            (
                Policy::one_of([a]).unwrap(),
                &[(a, &kpb)],
                "wrong account; correct key",
            ),
            (
                Policy::one_of([a, b]).unwrap(),
                &[(c, &kpc)],
                "account not a controller",
            ),
            (
                Policy::one_of([a, b]).unwrap(),
                &[(a, &kpa), (b, &kpb)],
                "two signers",
            ),
            (Policy::one_of([a]).unwrap(), &[], "one controller; no sigs"),
            (
                Policy::one_of([a, b]).unwrap(),
                &[],
                "two controllers; no sigs",
            ),
        ];

        for (pol, set, description) in cases {
            dbg!(description);
            assert_eq!(
                assert_revoke_err(pol.clone(), set),
                PolicyExecutionError::NotAuthorized.into(),
                "{}",
                description
            );
        }
    }

    #[test]
    /// sign unrelated commands and ensure they fail
    fn notauthorized_wrong_command() {
        if !in_ext() {
            return ext().execute_with(notauthorized_wrong_command);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = false;

        run_to_block(10);

        let kpa = create_did(DIDA);
        let reg = Registry { policy, add_only };

        let ar = AddRegistry {
            id: registry_id,
            new_registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let unrevoke = UnRevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(RevokeId(Default::default())).collect(),
        };
        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof).unwrap();

        let rev = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(RevokeId(Default::default())).collect(),
        };
        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        assert_eq!(
            RevoMod::revoke(Origin::signed(ABBA), rev, ur_proof).unwrap_err(),
            PolicyExecutionError::NotAuthorized.into()
        );

        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, ur_proof).unwrap();
    }

    #[test]
    fn regexists() {
        if !in_ext() {
            return ext().execute_with(regexists);
        }

        let reg = Registry {
            policy: Policy::one_of([DIDA]).unwrap(),
            add_only: false,
        };
        let ar = AddRegistry {
            id: RGA,
            new_registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap();
        let err = RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap_err();
        assert_eq!(err, Error::<Test>::RegExists.into());
    }

    #[test]
    fn noreg() {
        if !in_ext() {
            return ext().execute_with(noreg);
        }

        let registry_id = RGA;

        let noreg: Result<(), DispatchError> = Err(PolicyExecutionError::NoEntity.into());

        assert_eq!(
            RevoMod::revoke(
                Origin::signed(ABBA),
                RevokeRaw {
                    _marker: PhantomData,
                    registry_id,
                    revoke_ids: once(RevokeId(Default::default())).collect(),
                },
                vec![]
            ),
            noreg
        );
        assert_eq!(
            RevoMod::unrevoke(
                Origin::signed(ABBA),
                UnRevokeRaw {
                    _marker: PhantomData,
                    registry_id,
                    revoke_ids: once(RevokeId(Default::default())).collect(),
                },
                vec![],
            ),
            noreg
        );
        assert_eq!(
            RevoMod::remove_registry(
                Origin::signed(ABBA),
                RemoveRegistryRaw {
                    _marker: PhantomData,
                    registry_id
                },
                vec![],
            ),
            noreg
        );
    }

    #[test]
    fn too_many_controllers() {
        if !in_ext() {
            return ext().execute_with(incorrect_nonce);
        }

        let registry_id = RGA;
        let err = Error::<Test>::TooManyControllers;

        let ar = AddRegistry {
            id: registry_id,
            new_registry: Registry {
                policy: Policy::one_of((0u8..16).map(U256::from).map(Into::into).map(Did)).unwrap(),
                add_only: false,
            },
        };

        assert_noop!(RevoMod::new_registry(Origin::signed(ABBA), ar), err);
    }

    #[test]
    fn emtpy_payload() {
        if !in_ext() {
            return ext().execute_with(incorrect_nonce);
        }
        let err = Error::<Test>::EmptyPayload;

        let kpa = create_did(DIDA);
        let registry_id = RGA;
        let reg = Registry {
            policy: Policy::one_of([DIDA]).unwrap(),
            add_only: false,
        };
        let ar = AddRegistry {
            id: RGA,
            new_registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
        let revoke_raw = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: Default::default(),
        };
        let proof = get_pauth(&revoke_raw, &[(DIDA, &kpa)]);

        assert_noop!(
            RevoMod::revoke(Origin::signed(ABBA), revoke_raw, proof),
            err
        );
    }

    #[test]
    fn incorrect_nonce() {
        if !in_ext() {
            return ext().execute_with(incorrect_nonce);
        }

        run_to_block(1);

        let kpa = create_did(DIDA);

        let registry_id = RGA;
        let err: Result<(), DispatchError> = Err(PolicyExecutionError::IncorrectNonce.into());

        let ar = AddRegistry {
            id: registry_id,
            new_registry: Registry {
                policy: Policy::one_of([DIDA]).unwrap(),
                add_only: false,
            },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let rev = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(RevokeId(Default::default())).collect(),
        };
        let proof = get_pauth(&rev, &[(DIDA, &kpa)]);

        // Increase nonce to make the auth chekc fail
        inc_nonce(&DIDA);
        assert_eq!(RevoMod::revoke(Origin::signed(ABBA), rev, proof), err);

        let unrevoke = UnRevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(RevokeId(Default::default())).collect(),
        };
        let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);

        // Increase nonce to make the auth check fail
        inc_nonce(&DIDA);
        assert_eq!(
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof,),
            err
        );

        let remove = RemoveRegistryRaw {
            _marker: PhantomData,
            registry_id,
        };
        let proof = get_pauth(&remove, &[(DIDA, &kpa)]);

        // Increase nonce to make the auth check fail
        inc_nonce(&DIDA);
        assert_eq!(
            RevoMod::remove_registry(Origin::signed(ABBA), remove, proof,),
            err
        );
    }

    #[test]
    fn addonly() {
        if !in_ext() {
            return ext().execute_with(addonly);
        }

        let registry_id = RGA;
        let err: Result<(), DispatchError> = Err(Error::<Test>::AddOnly.into());
        let revoke_ids: BTreeSet<_> = [RA, RB, RC].iter().cloned().collect();

        run_to_block(1);

        let kpa = create_did(DIDA);

        let ar = AddRegistry {
            id: registry_id,
            new_registry: Registry {
                policy: Policy::one_of([DIDA]).unwrap(),
                add_only: true,
            },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let unrevoke = UnRevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids,
        };
        let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        assert_eq!(
            RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof),
            err
        );

        let remove = RemoveRegistryRaw {
            _marker: PhantomData,
            registry_id,
        };
        let proof = get_pauth(&remove, &[(DIDA, &kpa)]);
        assert_eq!(
            RevoMod::remove_registry(Origin::signed(ABBA), remove, proof),
            err
        );
    }

    // Untested variants will be a match error.
    // To fix the match error, write a test for the variant then update the test.
    fn _all_included(dummy: Error<Test>) {
        match dummy {
            Error::__Ignore(_, _)
            | Error::RegExists
            | Error::EmptyPayload
            | Error::IncorrectNonce
            | Error::AddOnly
            | Error::TooManyControllers => {}
        }
    }
}

/// Tests every happy path for every public extrinsic call in the module.
/// If a happy path is not covered, thats a bug.
/// If a call is not covered, thats a bug.
///
/// Tests in this module are named after the calls they check.
/// For example, `#[test] fn new_registry` tests the happy path for Module::new_registry.
mod calls {
    use super::*;
    // Cannot do `use super::super::*` as that would import `Call` as `Call` which conflicts with `Call` in `tests::common`
    use super::super::{Call as RevCall, Registries, Revocations};
    use alloc::collections::BTreeSet;

    #[test]
    fn new_registry() {
        if !in_ext() {
            return ext().execute_with(new_registry);
        }

        let cases: &[(Policy<Test>, bool)] = &[
            (Policy::one_of([DIDA]).unwrap(), false),
            (Policy::one_of([DIDA, DIDB]).unwrap(), false),
            (Policy::one_of([DIDA]).unwrap(), true),
            (Policy::one_of([DIDA, DIDB]).unwrap(), true),
        ];
        for (policy, add_only) in cases.iter().cloned() {
            let reg_id = RegistryId(random());
            let reg = Registry { policy, add_only };
            let ar = AddRegistry {
                id: reg_id,
                new_registry: reg.clone(),
            };
            assert!(!Registries::<Test>::contains_key(reg_id));
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
            assert!(Registries::<Test>::contains_key(reg_id));
            assert_eq!(Registries::<Test>::get(reg_id).unwrap(), reg);
        }
    }

    #[test]
    fn revoke() {
        if !in_ext() {
            return ext().execute_with(revoke);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = true;

        run_to_block(1);

        let kpa = create_did(DIDA);

        let ar = AddRegistry {
            id: registry_id,
            new_registry: Registry { policy, add_only },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let cases: &[&[RevokeId]] = &[
            // &[],
            &[RevokeId(random())],
            &[RevokeId(random()), RevokeId(random())],
            &[RevokeId(random()), RevokeId(random()), RevokeId(random())],
            &[RA], // Test idempotence, step 1
            &[RA], // Test idempotence, step 2
        ];
        for (i, ids) in cases.iter().enumerate() {
            println!("Revoke ids: {:?}", ids);
            let revoke = RevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: ids.iter().cloned().collect(),
            };
            let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);
            let old_nonces = get_nonces(&[(DIDA, &kpa)]);
            RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
            assert!(ids
                .iter()
                .all(|id| Revocations::<Test>::contains_key(registry_id, id)));
            check_nonce_increase(old_nonces, &[(DIDA, &kpa)]);
            run_to_block(1 + 1 + i as u64);
        }
    }

    #[test]
    fn unrevoke() {
        if !in_ext() {
            return ext().execute_with(unrevoke);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = false;

        run_to_block(10);

        let kpa = create_did(DIDA);

        enum Action {
            Revoke,
            UnRevo,
            AsrtRv, // assert revoked
            AsrtNR, // assert not revoked
        }

        let ar = AddRegistry {
            id: registry_id,
            new_registry: Registry { policy, add_only },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let cases: &[(Action, &[RevokeId], u32)] = &[
            //(Action::UnRevo, &[], line!()),
            (Action::UnRevo, &[RevokeId(random())], line!()),
            (
                Action::UnRevo,
                &[RevokeId(random()), RevokeId(random())],
                line!(),
            ),
            (
                Action::UnRevo,
                &[RevokeId(random()), RevokeId(random()), RevokeId(random())],
                line!(),
            ),
            (Action::Revoke, &[RA, RB], line!()),
            (Action::AsrtRv, &[RA, RB], line!()),
            (Action::UnRevo, &[RA], line!()),
            (Action::AsrtNR, &[RA], line!()),
            (Action::AsrtRv, &[RB], line!()),
            (Action::UnRevo, &[RA, RB], line!()),
            (Action::AsrtNR, &[RA, RB], line!()),
            (Action::Revoke, &[RA, RB], line!()),
            (Action::AsrtRv, &[RA, RB], line!()),
            (Action::UnRevo, &[RA, RB], line!()),
            (Action::AsrtNR, &[RA, RB], line!()),
        ];
        for (i, (action, ids, line_no)) in cases.iter().enumerate() {
            eprintln!("running action from line {}", line_no);
            let revoke_ids: BTreeSet<RevokeId> = ids.iter().cloned().collect();
            match action {
                Action::Revoke => {
                    let revoke = RevokeRaw {
                        _marker: PhantomData,
                        registry_id,
                        revoke_ids,
                    };
                    let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);
                    let old_nonces = get_nonces(&[(DIDA, &kpa)]);
                    RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
                    check_nonce_increase(old_nonces, &[(DIDA, &kpa)]);
                }
                Action::UnRevo => {
                    let unrevoke = UnRevokeRaw {
                        _marker: PhantomData,
                        registry_id,
                        revoke_ids: revoke_ids.clone(),
                    };
                    let old_nonces = get_nonces(&[(DIDA, &kpa)]);
                    let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
                    RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof).unwrap();
                    check_nonce_increase(old_nonces, &[(DIDA, &kpa)]);
                }
                Action::AsrtRv => {
                    assert!(revoke_ids
                        .iter()
                        .all(|id| Revocations::<Test>::contains_key(registry_id, id)));
                }
                Action::AsrtNR => {
                    assert!(!revoke_ids
                        .iter()
                        .any(|id| Revocations::<Test>::contains_key(registry_id, id)));
                }
            }
            run_to_block(10 + 1 + i as u64)
        }
    }

    #[test]
    fn remove_registry() {
        if !in_ext() {
            return ext().execute_with(remove_registry);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = false;
        let kpa = create_did(DIDA);

        let reg = Registry { policy, add_only };
        let ar = AddRegistry {
            id: registry_id,
            new_registry: reg,
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
        assert!(Registries::<Test>::contains_key(registry_id));

        // destroy reg
        let rem = RemoveRegistryRaw {
            _marker: PhantomData,
            registry_id,
        };
        let proof = get_pauth(&rem, &[(DIDA, &kpa)]);
        let old_nonces = get_nonces(&[(DIDA, &kpa)]);
        RevoMod::remove_registry(Origin::signed(ABBA), rem, proof).unwrap();
        check_nonce_increase(old_nonces, &[(DIDA, &kpa)]);

        // assert not exists
        assert!(!Registries::<Test>::contains_key(registry_id));
    }

    // Untested variants will be a match error.
    // To fix the match error, write a test for the variant then update the test.
    fn _all_included(dummy: RevCall<Test>) {
        match dummy {
            RevCall::new_registry { .. }
            | RevCall::revoke { .. }
            | RevCall::unrevoke { .. }
            | RevCall::remove_registry { .. }
            | RevCall::__Ignore { .. } => {}
        }
    }
}

mod test {
    use sp_runtime::DispatchError;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `tests::common`
    use super::*;
    use crate::revoke::Registries;

    #[test]
    /// Exercises Module::ensure_auth, both success and failure cases.
    fn ensure_auth() {
        if !in_ext() {
            return ext().execute_with(ensure_auth);
        }

        run_to_block(10);

        let (a, b, c): (Did, Did, Did) = (Did(random()), Did(random()), Did(random()));
        let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));
        let rev = RevokeRaw {
            _marker: PhantomData,
            registry_id: RGA,
            revoke_ids: once(RevokeId(Default::default())).collect(),
        };

        let cases: &[(u32, Policy<Test>, &[(Did, &sr25519::Pair)], bool)] = &[
            (line!(), Policy::one_of([a]).unwrap(), &[(a, &kpa)], true),
            (line!(), Policy::one_of([a, b]).unwrap(), &[(a, &kpa)], true),
            (line!(), Policy::one_of([a, b]).unwrap(), &[(b, &kpb)], true),
            (line!(), Policy::one_of([a]).unwrap(), &[], false), // provide no signatures
            (line!(), Policy::one_of([a]).unwrap(), &[(b, &kpb)], false), // wrong account; wrong key
            (line!(), Policy::one_of([a]).unwrap(), &[(a, &kpb)], false), // correct account; wrong key
            (line!(), Policy::one_of([a]).unwrap(), &[(a, &kpb)], false), // wrong account; correct key
            (
                line!(),
                Policy::one_of([a, b]).unwrap(),
                &[(c, &kpc)],
                false,
            ), // account not a controller
            (
                line!(),
                Policy::one_of([a, b]).unwrap(),
                &[(a, &kpa), (b, &kpb)],
                false,
            ), // two signers
            (line!(), Policy::one_of([a]).unwrap(), &[], false),          // one controller; no sigs
            (line!(), Policy::one_of([a, b]).unwrap(), &[], false), // two controllers; no sigs
        ];
        for (i, (line_no, policy, signers, expect_success)) in cases.iter().enumerate() {
            eprintln!("running case from line {}", line_no);
            Registries::<Test>::insert(
                RGA,
                Registry {
                    policy: policy.clone(),
                    add_only: false,
                },
            );

            let old_nonces = get_nonces(signers);
            let command = &rev;
            let proof = get_pauth(command, signers);
            let res = RevoMod::try_exec_action_over_registry(
                |_, _| Ok::<_, DispatchError>(()),
                command.clone(),
                proof,
            );
            assert_eq!(res.is_ok(), *expect_success);

            if *expect_success {
                check_nonce_increase(old_nonces, signers);
            }
            run_to_block(10 + 1 + i as u64);
        }
    }

    #[test]
    /// Exercises the revocation registry convenience getter, get_revocation_registry.
    fn get_revocation_registry() {
        if !in_ext() {
            return ext().execute_with(get_revocation_registry);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = false;
        let reg = Registry { policy, add_only };

        let ar = AddRegistry {
            id: registry_id,
            new_registry: reg.clone(),
        };

        assert_eq!(RevoMod::get_revocation_registry(registry_id), None);
        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
        assert_eq!(RevoMod::get_revocation_registry(registry_id), Some(reg));
    }

    #[test]
    /// Exercises the revocation status convenience getter, get_revocation_status.
    fn get_revocation_status() {
        if !in_ext() {
            return ext().execute_with(get_revocation_status);
        }

        let policy = Policy::one_of([DIDA]).unwrap();
        let registry_id = RGA;
        let add_only = false;
        let reg = Registry { policy, add_only };
        let kpa = create_did(DIDA);
        let revid: RevokeId = RevokeId(random());

        let ar = AddRegistry {
            id: registry_id,
            new_registry: reg,
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
        let revoke = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(revid).collect(),
        };
        let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);

        assert_eq!(RevoMod::get_revocation_status(registry_id, revid), None);
        RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
        assert_eq!(RevoMod::get_revocation_status(registry_id, revid), Some(()));
    }
}
