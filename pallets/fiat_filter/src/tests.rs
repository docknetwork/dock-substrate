use crate::fiat_rate::{
    PRICE_ANCHOR_OP_PER_BYTE, PRICE_ATTEST_PER_IRI_BYTE, PRICE_BLOB_OP_PER_BYTE, PRICE_DID_OP,
    PRICE_REVOKE_OP_CONST_FACTOR, PRICE_REVOKE_PER_REVOCATION, PRICE_REVOKE_REGISTRY_OP,
};
use crate::test_mock::*;
use codec::Encode;
use core_mods::StateChange;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::traits::Currency;
use frame_support::weights::Pays;
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;
use rand::random;
use sp_core::{sr25519, Pair};

mod tests_did_calls {
    use super::*;
    use did::{
        Bytes32, Bytes64, DidRemoval, DidSignature, KeyDetail, KeyUpdate, PublicKey, DID_BYTE_SIZE,
    };

    type DidMod = did::Module<TestRt>;

    #[test]
    fn call_did_new() {
        ext().execute_with(|| {
            let d: did::Did = rand::random();
            let kp = gen_kp();
            let key_detail = did::KeyDetail::new(
                d,
                did::PublicKey::Sr25519(did::Bytes32 {
                    value: kp.public().0,
                }),
            );

            let call = Call::DIDMod(did::Call::<TestRt>::new(d.clone(), key_detail));
            let expected_fees = PRICE_DID_OP / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
    #[test]
    fn call_did_update_key__OK() {
        ext().execute_with(|| {
            let did_alice = [1; DID_BYTE_SIZE];
            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0;
            let detail = KeyDetail::new(
                did_alice.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_1 }),
            );

            // Add a DID
            let new_res = DidMod::new(Origin::signed(ALICE), did_alice.clone(), detail.clone());
            assert_ok!(new_res);

            let (_current_detail, modified_in_block) = DidMod::get_key_detail(&did_alice).unwrap();

            // Correctly update DID's key.
            // Prepare a key update
            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0;
            let key_update = KeyUpdate::new(
                did_alice.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_2 }),
                None,
                modified_in_block as u32,
            );
            let sig_value = pair_1
                .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                .0;
            let sig = DidSignature::Sr25519(did::Bytes64 { value: sig_value });

            // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
            let call = Call::DIDMod(did::Call::<TestRt>::update_key(key_update, sig));
            let expected_fees = PRICE_DID_OP / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
    #[test]
    fn call_did_remove() {
        ext().execute_with(|| {
            let (did_alice, kp) = newdid(ALICE);
            let blockno = block_no() as u32;

            let to_remove = DidRemoval::new(did_alice.clone(), blockno);
            let sig = DidSignature::Sr25519(Bytes64 {
                value: kp
                    .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                    .0,
            });

            let call = Call::DIDMod(did::Call::<TestRt>::remove(to_remove, sig));
            let expected_fees = PRICE_DID_OP / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
}

#[test]
fn call_anchor_deploy() {
    use anchor;

    ext().execute_with(|| {
        let dat = (0..32).map(|_| rand::random()).collect();

        let call = Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat));
        let expected_fees = 32 * PRICE_ANCHOR_OP_PER_BYTE / RATE_DOCK_USD;
        let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
    });
}

mod test_attest_calls {
    use super::*;

    #[test]
    fn call_attest__iri_none() {
        use attest::Attestation;

        ext().execute_with(|| {
            let (attester, kp) = newdid(ALICE);
            let att = Attestation {
                priority: 1,
                iri: None,
            };
            let size_attested = att.iri.clone().unwrap_or([1].to_vec()).len() as u32;
            assert_eq!(size_attested, 1);
            let sig = sign(&StateChange::Attestation((attester, att.clone())), &kp);

            let call = Call::AttestMod(attest::Call::<TestRt>::set_claim(attester, att, sig));
            let expected_fees = size_attested * PRICE_ATTEST_PER_IRI_BYTE / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }

    #[test]
    fn call_attest__iri_some() {
        use attest::Attestation;

        ext().execute_with(|| {
            let (attester, kp) = newdid(ALICE);
            let att = Attestation {
                priority: 1,
                iri: Some("http://hello.world".as_bytes().to_vec()),
            };
            let size_attested = att.iri.clone().unwrap_or([1].to_vec()).len() as u32;
            assert_eq!(size_attested, 18);
            let sig = sign(&StateChange::Attestation((attester, att.clone())), &kp);

            let call = Call::AttestMod(attest::Call::<TestRt>::set_claim(attester, att, sig));
            let expected_fees = size_attested * PRICE_ATTEST_PER_IRI_BYTE / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
}

#[test]
fn call_blob_new() {
    use blob::{Blob, BlobId};
    ext().execute_with(|| {
        let id: BlobId = rand::random();
        let noise = random_bytes(999);
        let (author, author_kp) = newdid(ALICE);
        let blob = Blob {
            id,
            blob: noise.clone(),
            author,
        };
        let sig = sign(&StateChange::Blob(blob.clone()), &author_kp);

        let call = Call::BlobMod(blob::Call::<TestRt>::new(blob, sig));

        let expected_fees = 999 * PRICE_BLOB_OP_PER_BYTE / RATE_DOCK_USD;
        let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
    });
}

mod tests_revoke_calls {
    use super::*;
    use did::Did;
    use revoke::{Policy, Registry, RegistryId, RemoveRegistry, Revoke, RevokeId, UnRevoke};

    pub const REV_ID: RevokeId = [7u8; 32];

    pub fn policy_oneof(dids: &[Did]) -> Policy {
        Policy::OneOf(dids.iter().cloned().collect())
    }
    pub fn new_reg(did: Did) -> (RegistryId, Registry) {
        pub const REG_ID: RegistryId = [3u8; 32];
        let reg = Registry {
            policy: policy_oneof(&[did]),
            add_only: false,
        };
        let created = RevokeMod::new_registry(Origin::signed(ALICE), REG_ID, reg.clone());
        assert_ok!(created);
        (REG_ID, reg)
    }

    #[test]
    fn call_revoke_revoke() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);

            let cases: &[&[RevokeId]] = &[
                &[],
                &[random()],
                &[random(), random()],
                &[random(), random(), random()],
                &[REV_ID], // Test idempotence, step 1
                &[REV_ID], // Test idempotence, step 2
            ];
            for ids in cases {
                let revoke = Revoke {
                    registry_id: reg_id,
                    revoke_ids: ids.iter().cloned().collect(),
                    last_modified: block_no() as u32,
                };
                let revocation_size = ids.len() as u32;
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::Revoke(revoke.clone()), &kp_alice),
                ))
                .collect();

                let call = Call::RevokeMod(revoke::Call::<TestRt>::revoke(revoke, proof));
                let expected_fees_nusd =
                    PRICE_REVOKE_OP_CONST_FACTOR + revocation_size * PRICE_REVOKE_PER_REVOCATION;
                let expected_fees = expected_fees_nusd / RATE_DOCK_USD;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                // assert ids in registry
                for rev_id in ids.iter() {
                    let rev_status = RevokeMod::get_revocation_status(reg_id, rev_id);
                    assert!(rev_status.is_some())
                }
            }
        });
    }

    #[test]
    fn call_revoke_unrevoke() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);
            let last_modified = block_no() as u32;

            let cases: &[&[RevokeId]] = &[
                &[],
                &[random()],
                &[random(), random()],
                &[random(), random(), random()],
                &[REV_ID], // Test idempotence, step 1
                &[REV_ID], // Test idempotence, step 2
            ];
            for ids in cases {
                for id in ids.iter() {
                    // assert not revoked
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, None);
                }

                // 1. revoke
                let revoke = Revoke {
                    registry_id: reg_id,
                    revoke_ids: ids.iter().cloned().collect(),
                    last_modified,
                };
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::Revoke(revoke.clone()), &kp_alice),
                ))
                .collect();
                let revoke_res = RevokeMod::revoke(Origin::signed(ALICE), revoke.clone(), proof);
                assert_ok!(revoke_res);
                // assert revoked
                for id in ids.iter() {
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, Some(()));
                }

                // 2. unrevoke
                let unrevoke = UnRevoke {
                    registry_id: reg_id,
                    revoke_ids: revoke.revoke_ids.clone(),
                    last_modified,
                };
                let unrevoke_size = unrevoke.revoke_ids.len() as u32;
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::UnRevoke(unrevoke.clone()), &kp_alice),
                ))
                .collect();

                let call = Call::RevokeMod(revoke::Call::<TestRt>::unrevoke(unrevoke, proof));
                let expected_fees_nusd =
                    PRICE_REVOKE_OP_CONST_FACTOR + unrevoke_size * PRICE_REVOKE_PER_REVOCATION;
                let expected_fees = expected_fees_nusd / RATE_DOCK_USD;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                // assert unrevoked
                for id in ids.iter() {
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, None);
                }
            }
        });
    }

    #[test]
    fn call_revoke_new_registry() {
        ext().execute_with(|| {
            let (did_alice, _) = newdid(ALICE);
            let (did_bob, _) = newdid(BOB);

            let cases: &[(Policy, bool)] = &[
                (policy_oneof(&[did_alice]), false),
                (policy_oneof(&[did_alice, did_bob]), false),
                (policy_oneof(&[did_alice]), true),
                (policy_oneof(&[did_alice, did_bob]), true),
            ];
            for (policy, add_only) in cases.iter().cloned() {
                let reg_id = random();
                let reg = Registry { policy, add_only };

                let got_reg = <revoke::Module<TestRt>>::get_revocation_registry(reg_id);
                assert!(got_reg.is_none());

                let call =
                    Call::RevokeMod(revoke::Call::<TestRt>::new_registry(reg_id, reg.clone()));

                let expected_fees = PRICE_REVOKE_REGISTRY_OP / RATE_DOCK_USD;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                let got_reg = <revoke::Module<TestRt>>::get_revocation_registry(reg_id);
                assert!(got_reg.is_some());
                let (created_reg, created_bloc) = got_reg.unwrap();
                assert_eq!(created_reg, reg);
                assert_eq!(created_bloc, block_no());
            }
        });
    }
    #[test]
    fn call_revoke_remove_registry() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);
            let last_modified = block_no() as u32;

            // destroy reg
            let rem = RemoveRegistry {
                registry_id: reg_id,
                last_modified,
            };
            let proof = std::iter::once((
                did_alice,
                sign(&StateChange::RemoveRegistry(rem.clone()), &kp_alice),
            ))
            .collect();

            let call = Call::RevokeMod(revoke::Call::<TestRt>::remove_registry(rem, proof));

            let expected_fees = PRICE_REVOKE_REGISTRY_OP / RATE_DOCK_USD;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

            // assert registry removed
            let got_reg = RevokeMod::get_revocation_registry(reg_id);
            assert_eq!(got_reg, None);
        });
    }
}

mod tests_fail_modes {
    use super::*;
    use crate::Config;
    use frame_support::dispatch::DispatchError;

    #[test]
    fn anchor_new__Err_no_balance() {
        ext().execute_with(|| {
            // empty alice's balance
            let _ = <TestRt as Config>::Currency::make_free_balance_be(&ALICE, 0);
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();
            // execute call
            let (_fee_microdock, executed) =
                measure_fees(Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat)));
            assert_noop!(
                executed,
                DispatchError::Module {
                    index: 1,
                    error: 3,
                    message: Some("InsufficientBalance")
                },
            );
        });
    }

    #[test]
    fn anchor_new__Err_insufficient_balance() {
        ext().execute_with(|| {
            // reduce alice's balance to just under the required fee
            let _ = <TestRt as Config>::Currency::make_free_balance_be(&ALICE, 20);
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();
            // execute call
            let (_fee_microdock, executed) =
                measure_fees(Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat)));
            assert_noop!(
                executed,
                DispatchError::Module {
                    index: 1,
                    error: 3,
                    message: Some("InsufficientBalance")
                },
            );
        });
    }

    #[test]
    fn anchor_new__Err_unsigned() {
        ext().execute_with(|| {
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();

            // execute call
            let balance_pre = <TestRt as Config>::Currency::free_balance(ALICE);
            let call = Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat));
            let executed =
                FiatFilterModule::execute_call(RawOrigin::None.into(), Box::new(call.clone()));
            let balance_post = <TestRt as Config>::Currency::free_balance(ALICE);
            let fee_microdock = balance_pre - balance_post;

            assert_noop!(executed, DispatchError::BadOrigin);

            // the call signature isn't valid, we can't charge the account any fees
            assert_eq!(fee_microdock, 0);
        });
    }

    #[test]
    fn balance_transfer__Err_unexpectedCall() {
        ext().execute_with(|| {
            // prepare data
            let call = Call::Balances(pallet_balances::Call::<TestRt>::transfer(BOB, 200));

            // // execute call
            let (fee_microdock, executed) = measure_fees(call);

            let pdi = executed.unwrap_err();
            // Comparing error with assert_noop will be brittle as that would contain weight which can change over time
            assert_eq!(
                pdi.error,
                DispatchError::from(Error::<TestRt>::UnexpectedCall)
            );
            assert_eq!(pdi.post_info.pays_fee, Pays::Yes);
            assert!(pdi.post_info.actual_weight.is_some());

            // the call signature isn't valid, we can't charge the account any fees
            assert_eq!(fee_microdock, 0);
        });
    }
}

mod tests_dock_fiat_rate {
    use crate::fiat_rate::*;
    use crate::test_mock::testrt_price2::{ext_price2, measure_fees};
    use crate::test_mock::testrt_price2::{Call, TestRt as TestRt2};
    use crate::test_mock::RATE_DOCK_USD_2;
    use core_mods::anchor;
    use frame_support::assert_ok;
    use frame_support::weights::Pays;

    #[test]
    fn call_anchor_deploy__OK_different_rate() {
        ext_price2().execute_with(|| {
            let dat = (0..32).map(|_| rand::random()).collect();
            let call = Call::AnchorMod(anchor::Call::<TestRt2>::deploy(dat));

            let expected_fees = 32 * PRICE_ANCHOR_OP_PER_BYTE / RATE_DOCK_USD_2;

            let (fee_microdock, executed) = measure_fees(call);
            assert_ok!(executed);

            let pdi = executed.unwrap();
            assert!(pdi.pays_fee == Pays::No);
            assert_eq!(fee_microdock, expected_fees);
        });
    }
}
