use super::*;
use crate::{test_common::*, util::WithNonce, Action, ToStateChange};
use alloc::collections::BTreeMap;
use core::{iter::once, marker::PhantomData};
use frame_support::assert_noop;
use sp_core::{sr25519, U256};

pub fn get_pauth<A: Action<Test> + Clone>(
    action: &A,
    signers: &[(Did, &sr25519::Pair)],
) -> Vec<DidSigs<Test>>
where
    WithNonce<Test, A>: ToStateChange<Test>,
{
    signers
        .iter()
        .map(|(did, kp)| {
            let did_detail = DIDModule::onchain_did_details(&did).unwrap();
            let next_nonce = did_detail.next_nonce();
            let sp = WithNonce::<Test, _>::new_with_nonce(action.clone(), next_nonce);
            let sig =
                did_sig_on_bytes::<Test, _>(&sp.to_state_change().encode(), &kp, did.clone(), 1);
            DidSigs {
                sig,
                nonce: next_nonce,
            }
        })
        .collect()
}

pub fn inc_nonce(d: &Did) {
    let mut did_detail = DIDModule::onchain_did_details(&d).unwrap();
    did_detail.nonce = did_detail.next_nonce();
    DIDModule::insert_did_details(*d, did_detail);
}

pub fn get_nonces(signers: &[(Did, &sr25519::Pair)]) -> BTreeMap<Did, u64> {
    let mut nonces = BTreeMap::new();
    for (d, _) in signers {
        let did_detail = DIDModule::onchain_did_details(&d).unwrap();
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

/// Tests every failure case in the module.
/// If a failure case is not covered, thats a bug.
/// If an error variant from RevErr is not covered, thats a bug.
///
/// Tests in this module are named after the errors they check.
/// For example, `#[test] fn invalidpolicy` exercises the RevErr::InvalidPolicy.
mod errors {
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
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
            registry: Registry {
                policy: oneof(&[]),
                add_only: false,
            },
        };

        let err = RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap_err();
        assert_eq!(err, RevErr::<Test>::InvalidPolicy.into());
    }

    // this test has caught at least one bug
    #[test]
    fn notauthorized() {
        if !in_ext() {
            return ext().execute_with(notauthorized);
        }

        fn assert_revoke_err(policy: Policy, signers: &[(Did, &sr25519::Pair)]) -> DispatchError {
            let regid: RegistryId = random();
            let ar = AddRegistry {
                id: regid,
                registry: Registry {
                    policy,
                    add_only: false,
                },
            };
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

            let rev = RevokeRaw {
                _marker: PhantomData,
                registry_id: regid,
                revoke_ids: random::<[RevokeId; 32]>().iter().cloned().collect(),
            };
            let pauth = get_pauth(&rev, signers);
            dbg!(&rev);
            dbg!(&pauth);
            RevoMod::revoke(Origin::signed(ABBA), rev, pauth).unwrap_err()
        }

        run_to_block(10);

        let (a, b, c) = (DIDA, DIDB, DIDC);
        let (kpa, kpb, kpc) = (create_did(a), create_did(b), create_did(c));

        let cases: &[(Policy, &[(Did, &sr25519::Pair)], &str)] = &[
            (oneof(&[a]), &[], "provide no signatures"),
            (oneof(&[a]), &[(b, &kpb)], "wrong account; wrong key"),
            (oneof(&[a]), &[(a, &kpb)], "correct account; wrong key"),
            (oneof(&[a]), &[(a, &kpb)], "wrong account; correct key"),
            (oneof(&[a, b]), &[(c, &kpc)], "account not a controller"),
            (oneof(&[a, b]), &[(a, &kpa), (b, &kpb)], "two signers"),
            (oneof(&[a]), &[], "one controller; no sigs"),
            (oneof(&[a, b]), &[], "two controllers; no sigs"),
        ];

        for (pol, set, description) in cases {
            dbg!(description);
            assert_eq!(
                assert_revoke_err(pol.clone(), set),
                RevErr::<Test>::NotAuthorized.into(),
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

        let policy = oneof(&[DIDA]);
        let registry_id = RGA;
        let add_only = false;

        run_to_block(10);

        let kpa = create_did(DIDA);
        let reg = Registry { policy, add_only };

        let ar = AddRegistry {
            id: registry_id,
            registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let unrevoke = UnRevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(Default::default()).collect(),
        };
        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof).unwrap();

        let rev = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(Default::default()).collect(),
        };
        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        assert_eq!(
            RevoMod::revoke(Origin::signed(ABBA), rev, ur_proof).unwrap_err(),
            RevErr::<Test>::NotAuthorized.into()
        );

        let ur_proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
        RevoMod::unrevoke(Origin::signed(ABBA), unrevoke.clone(), ur_proof).unwrap();
    }

    #[test]
    fn regexists() {
        if !in_ext() {
            return ext().execute_with(regexists);
        }

        let reg = Registry {
            policy: oneof(&[DIDA]),
            add_only: false,
        };
        let ar = AddRegistry {
            id: RGA,
            registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap();
        let err = RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap_err();
        assert_eq!(err, RevErr::<Test>::RegExists.into());
    }

    #[test]
    fn noreg() {
        if !in_ext() {
            return ext().execute_with(noreg);
        }

        let registry_id = RGA;

        let noreg: Result<(), DispatchError> = Err(RevErr::<Test>::NoReg.into());

        assert_eq!(
            RevoMod::revoke(
                Origin::signed(ABBA),
                RevokeRaw {
                    _marker: PhantomData,
                    registry_id,
                    revoke_ids: once(Default::default()).collect(),
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
                    revoke_ids: once(Default::default()).collect(),
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
        let err = RevErr::<Test>::TooManyControllers;

        let ar = AddRegistry {
            id: registry_id,
            registry: Registry {
                policy: Policy::OneOf((0u8..16).map(U256::from).map(Into::into).map(Did).collect()),
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
        let err = RevErr::<Test>::EmptyPayload;

        let kpa = create_did(DIDA);
        let registry_id = RGA;
        let reg = Registry {
            policy: oneof(&[DIDA]),
            add_only: false,
        };
        let ar = AddRegistry {
            id: RGA,
            registry: reg,
        };
        RevoMod::new_registry(Origin::signed(ABBA), ar.clone()).unwrap();
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
        let err: Result<(), DispatchError> = Err(RevErr::<Test>::IncorrectNonce.into());

        let ar = AddRegistry {
            id: registry_id,
            registry: Registry {
                policy: oneof(&[DIDA]),
                add_only: false,
            },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let rev = RevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(Default::default()).collect(),
        };
        let proof = get_pauth(&rev, &[(DIDA, &kpa)]);

        // Increase nonce to make the auth chekc fail
        inc_nonce(&DIDA);
        assert_eq!(RevoMod::revoke(Origin::signed(ABBA), rev, proof), err);

        let unrevoke = UnRevokeRaw {
            _marker: PhantomData,
            registry_id,
            revoke_ids: once(Default::default()).collect(),
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
        let err: Result<(), DispatchError> = Err(RevErr::<Test>::AddOnly.into());
        let revoke_ids: BTreeSet<_> = [RA, RB, RC].iter().cloned().collect();

        run_to_block(1);

        let kpa = create_did(DIDA);

        let ar = AddRegistry {
            id: registry_id,
            registry: Registry {
                policy: oneof(&[DIDA]),
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
    fn _all_included(dummy: RevErr<Test>) {
        match dummy {
            RevErr::__Ignore(_, _)
            | RevErr::InvalidPolicy
            | RevErr::NotAuthorized
            | RevErr::RegExists
            | RevErr::NoReg
            | RevErr::IncorrectNonce
            | RevErr::AddOnly
            | RevErr::EmptyPayload
            | RevErr::TooManyControllers => {}
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
    // Cannot do `use super::super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
    use super::super::{Call as RevCall, Registries, Revocations};
    use alloc::collections::BTreeSet;
    use frame_support::{StorageDoubleMap, StorageMap};

    #[test]
    fn new_registry() {
        if !in_ext() {
            return ext().execute_with(new_registry);
        }

        let cases: &[(Policy, bool)] = &[
            (oneof(&[DIDA]), false),
            (oneof(&[DIDA, DIDB]), false),
            (oneof(&[DIDA]), true),
            (oneof(&[DIDA, DIDB]), true),
        ];
        for (policy, add_only) in cases.iter().cloned() {
            let reg_id = random();
            let reg = Registry { policy, add_only };
            let ar = AddRegistry {
                id: reg_id,
                registry: reg.clone(),
            };
            assert!(!Registries::contains_key(&reg_id));
            RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
            assert!(Registries::contains_key(reg_id));
            assert_eq!(Registries::get(reg_id).unwrap(), reg);
        }
    }

    #[test]
    fn revoke() {
        if !in_ext() {
            return ext().execute_with(revoke);
        }

        let policy = oneof(&[DIDA]);
        let registry_id = RGA;
        let add_only = true;

        run_to_block(1);

        let kpa = create_did(DIDA);

        let ar = AddRegistry {
            id: registry_id,
            registry: Registry { policy, add_only },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let cases: &[&[RevokeId]] = &[
            // &[],
            &[random()],
            &[random(), random()],
            &[random(), random(), random()],
            &[RA], // Test idempotence, step 1
            &[RA], // Test idempotence, step 2
        ];
        for (i, ids) in cases.into_iter().enumerate() {
            println!("Revoke ids: {:?}", ids);
            let revoke = RevokeRaw {
                _marker: PhantomData,
                registry_id,
                revoke_ids: ids.iter().cloned().collect(),
            };
            let proof = get_pauth(&revoke, &[(DIDA, &kpa)]);
            let old_nonces = get_nonces(&[((DIDA, &kpa))]);
            RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
            assert!(ids
                .iter()
                .all(|id| Revocations::contains_key(registry_id, id)));
            check_nonce_increase(old_nonces, &[((DIDA, &kpa))]);
            run_to_block(1 + 1 + i as u64);
        }
    }

    #[test]
    fn unrevoke() {
        if !in_ext() {
            return ext().execute_with(unrevoke);
        }

        let policy = oneof(&[DIDA]);
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
            registry: Registry { policy, add_only },
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();

        let cases: &[(Action, &[RevokeId], u32)] = &[
            //(Action::UnRevo, &[], line!()),
            (Action::UnRevo, &[random()], line!()),
            (Action::UnRevo, &[random(), random()], line!()),
            (Action::UnRevo, &[random(), random(), random()], line!()),
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
        for (i, (action, ids, line_no)) in cases.into_iter().enumerate() {
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
                    let old_nonces = get_nonces(&[((DIDA, &kpa))]);
                    RevoMod::revoke(Origin::signed(ABBA), revoke, proof).unwrap();
                    check_nonce_increase(old_nonces, &[((DIDA, &kpa))]);
                }
                Action::UnRevo => {
                    let unrevoke = UnRevokeRaw {
                        _marker: PhantomData,
                        registry_id,
                        revoke_ids: revoke_ids.clone(),
                    };
                    let old_nonces = get_nonces(&[((DIDA, &kpa))]);
                    let proof = get_pauth(&unrevoke, &[(DIDA, &kpa)]);
                    RevoMod::unrevoke(Origin::signed(ABBA), unrevoke, proof).unwrap();
                    check_nonce_increase(old_nonces, &[((DIDA, &kpa))]);
                }
                Action::AsrtRv => {
                    assert!(revoke_ids
                        .iter()
                        .all(|id| Revocations::contains_key(registry_id, id)));
                }
                Action::AsrtNR => {
                    assert!(!revoke_ids
                        .iter()
                        .any(|id| Revocations::contains_key(registry_id, id)));
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

        let policy = oneof(&[DIDA]);
        let registry_id = RGA;
        let add_only = false;
        let kpa = create_did(DIDA);

        let reg = Registry { policy, add_only };
        let ar = AddRegistry {
            id: registry_id,
            registry: reg.clone(),
        };

        RevoMod::new_registry(Origin::signed(ABBA), ar).unwrap();
        assert!(Registries::contains_key(registry_id));

        // destroy reg
        let rem = RemoveRegistryRaw {
            _marker: PhantomData,
            registry_id,
        };
        let proof = get_pauth(&rem, &[(DIDA, &kpa)]);
        let old_nonces = get_nonces(&[((DIDA, &kpa))]);
        RevoMod::remove_registry(Origin::signed(ABBA), rem, proof).unwrap();
        check_nonce_increase(old_nonces, &[((DIDA, &kpa))]);

        // assert not exists
        assert!(!Registries::contains_key(registry_id));
    }

    // Untested variants will be a match error.
    // To fix the match error, write a test for the variant then update the test.
    fn _all_included(dummy: RevCall<Test>) {
        match dummy {
            RevCall::new_registry(_)
            | RevCall::revoke(_, _)
            | RevCall::unrevoke(_, _)
            | RevCall::remove_registry(_, _)
            | RevCall::__PhantomItem(_, _) => {}
        }
    }
}

mod test {
    use frame_support::StorageMap;
    use sp_runtime::DispatchError;
    // Cannot do `use super::*` as that would import `Call` as `Call` which conflicts with `Call` in `test_common`
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
            revoke_ids: once(Default::default()).collect(),
        };

        let cases: &[(u32, Policy, &[(Did, &sr25519::Pair)], bool)] = &[
            (line!(), oneof(&[a]), &[(a, &kpa)], true),
            (line!(), oneof(&[a, b]), &[(a, &kpa)], true),
            (line!(), oneof(&[a, b]), &[(b, &kpb)], true),
            (line!(), oneof(&[a]), &[], false), // provide no signatures
            (line!(), oneof(&[a]), &[(b, &kpb)], false), // wrong account; wrong key
            (line!(), oneof(&[a]), &[(a, &kpb)], false), // correct account; wrong key
            (line!(), oneof(&[a]), &[(a, &kpb)], false), // wrong account; correct key
            (line!(), oneof(&[a, b]), &[(c, &kpc)], false), // account not a controller
            (line!(), oneof(&[a, b]), &[(a, &kpa), (b, &kpb)], false), // two signers
            (line!(), oneof(&[a]), &[], false), // one controller; no sigs
            (line!(), oneof(&[a, b]), &[], false), // two controllers; no sigs
        ];
        for (i, (line_no, policy, signers, expect_success)) in cases.into_iter().enumerate() {
            eprintln!("running case from line {}", line_no);
            Registries::insert(
                RGA,
                Registry {
                    policy: policy.clone(),
                    add_only: false,
                },
            );

            let old_nonces = get_nonces(signers);
            let command = &rev;
            let proof = get_pauth(command, &signers);
            let res = RevoMod::try_exec_action_over_registry(command.clone(), proof, |_, _| {
                Ok::<_, DispatchError>(())
            });
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

        let policy = oneof(&[DIDA]);
        let registry_id = RGA;
        let add_only = false;
        let reg = Registry { policy, add_only };

        let ar = AddRegistry {
            id: registry_id,
            registry: reg.clone(),
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

        let policy = oneof(&[DIDA]);
        let registry_id = RGA;
        let add_only = false;
        let reg = Registry { policy, add_only };
        let kpa = create_did(DIDA);
        let revid: RevokeId = random();

        let ar = AddRegistry {
            id: registry_id,
            registry: reg.clone(),
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
