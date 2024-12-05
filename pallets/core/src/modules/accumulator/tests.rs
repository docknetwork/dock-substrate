use super::*;
use crate::tests::common::*;
use frame_support::assert_err;
use sp_core::{Hasher, H256};

fn accumulator_events() -> Vec<(super::Event, Vec<H256>)> {
    System::events()
        .iter()
        .filter_map(|event_record| {
            let frame_system::EventRecord::<TestEvent, H256> {
                phase: _p,
                event,
                topics,
            } = event_record;
            match event {
                TestEvent::Accum(e) => Some((e.clone(), topics.clone())),
                _ => None,
            }
        })
        .collect()
}

crate::did_or_did_method_key! {
    newdid =>

    #[test]
    fn accumulator_errors() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let author = AccumulatorOwner(author.into());
            let mut next_nonce = 1;
            check_nonce(&author, next_nonce - 1);

            run_to_block(11);

            let (author_1, author_1_kp) = newdid();
            let author_1 = AccumulatorOwner(author_1.into());
            let next_nonce_1 = 1;
            check_nonce(&author_1, next_nonce_1 - 1);

            run_to_block(30);

            assert!(vec![3; 300]
                .try_into()
                .map(
                    |accumulated| Accumulator::<Test>::Positive(AccumulatorCommon {
                        accumulated,
                        key_ref: AccumPublicKeyStorageKey(author, 1u8.into()),
                    })
                )
                .is_err());

            let id = AccumulatorId(rand::random());

            let accumulator = Accumulator::Positive(AccumulatorCommon {
                key_ref: AccumPublicKeyStorageKey(author, 1u8.into()),
                accumulated: vec![3; 100].try_into().unwrap(),
            });

            let add_accum = AddAccumulator {
                id,
                accumulator,
                nonce: next_nonce,
            };
            let sig = did_sig(&add_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum, sig),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(40);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3].try_into().unwrap()),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100].try_into().unwrap(),
            };
            let ap = AddAccumulatorParams {
                params,
                nonce: next_nonce,
            };
            let sig = did_sig::<Test, _, _, _>(&ap, &author_kp, author, 1);
            AccumMod::add_params(Origin::signed(1), ap, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(50);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100].try_into().unwrap(),
            };
            let ak = AddAccumulatorPublicKey {
                public_key: key,
                nonce: next_nonce,
            };
            let sig = did_sig::<Test, _, _, _>(&ak, &author_kp, author, 1);
            AccumMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(60);

            let id = AccumulatorId(rand::random());
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32].try_into().unwrap(),
                key_ref: AccumPublicKeyStorageKey(author, 1u8.into()),
            });
            let add_accum = AddAccumulator {
                id,
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = did_sig(&add_accum, &author_kp, author, 1);
            AccumMod::add_accumulator(Origin::signed(1), add_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Cannot add with same id again
            let add_accum = AddAccumulator {
                id,
                accumulator,
                nonce: next_nonce,
            };
            let sig = did_sig(&add_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum, sig),
                Error::<Test>::AccumulatorAlreadyExists
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(70);

            let mut update_accum = UpdateAccumulator {
                id: AccumulatorId(rand::random()),
                new_accumulated: vec![4; 32].try_into().unwrap(),
                additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
                removals: Some(vec![vec![9, 4].into()]),
                witness_update_info: Some(vec![1, 1, 2, 3].into()),
                nonce: next_nonce,
            };
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                did::Error::<Test>::NoEntity
            );

            update_accum.id = id;
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(80);

            let mut update_accum = UpdateAccumulator {
                id,
                new_accumulated: vec![5; 300].try_into().unwrap(),
                additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
                removals: Some(vec![vec![9, 4].into()]),
                witness_update_info: Some(vec![1, 1, 2, 3].into()),
                nonce: next_nonce,
            };
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.new_accumulated = vec![5; 100].into();
            update_accum.additions = Some(vec![
                vec![89; 2].into(),
                vec![45; 6].into(),
                vec![55; 8].into(),
                vec![56; 4].into(),
                vec![57; 5].into(),
                vec![10; 5].into(),
                vec![5; 8].into(),
                vec![35; 2].into(),
                vec![11; 4].into(),
                vec![15; 4].into(),
                vec![25; 5].into(),
            ]);
            update_accum.removals = None;
            update_accum.witness_update_info = Some(vec![11, 12, 21, 23, 35, 50].into());
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(90);

            update_accum.nonce = next_nonce - 1;
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                crate::did::Error::<Test>::InvalidNonce
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.nonce = next_nonce;
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(100);

            update_accum.nonce = next_nonce;
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only accumulator owner can update it
            update_accum.nonce = next_nonce_1;
            let sig = did_sig(&update_accum, &author_1_kp, author_1, 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            update_accum.nonce = next_nonce;
            let sig = did_sig(&update_accum, &author_kp, author, 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only accumulator owner can remove it
            let rem_accum = RemoveAccumulator {
                id,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rem_accum, &author_1_kp, author_1, 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            let rem_accum = RemoveAccumulator {
                id,
                nonce: next_nonce,
            };
            let sig = did_sig(&rem_accum, &author_kp, author, 1);
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only key owner can remove it
            let rem = RemoveAccumulatorPublicKey {
                key_ref: AccumPublicKeyStorageKey(author, 1u8.into()),
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rem, &author_1_kp, author_1, 1);
            assert_err!(
                AccumMod::remove_public_key(Origin::signed(1), rem, sig),
                Error::<Test>::NotPublicKeyOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            let rem = RemoveAccumulatorPublicKey {
                key_ref: AccumPublicKeyStorageKey(author, 1u8.into()),
                nonce: next_nonce,
            };
            let sig: DidOrDidMethodKeySignature<AccumulatorOwner> = did_sig(&rem, &author_kp, author, 1);
            AccumMod::remove_public_key(Origin::signed(1), rem, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only params owner can remove it
            let rem = RemoveAccumulatorParams {
                params_ref: AccumParametersStorageKey(author, 1u8.into()),
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rem, &author_1_kp, author_1, 1);
            assert_err!(
                AccumMod::remove_params(Origin::signed(1), rem, sig),
                Error::<Test>::NotParamsOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rem = RemoveAccumulatorParams {
                params_ref: AccumParametersStorageKey(author, 1u8.into()),
                nonce: next_nonce,
            };
            let sig = did_sig(&rem, &author_kp, author, 1);
            AccumMod::remove_params(Origin::signed(1), rem, sig).unwrap();
            check_nonce(&author, next_nonce);
        });
    }

    #[test]
    fn add_remove_accumulator() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let author = AccumulatorOwner(author.into());
            let mut next_nonce = 1;

            run_to_block(20);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3].try_into().unwrap()),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100].try_into().unwrap(),
            };
            let ap = AddAccumulatorParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = did_sig::<Test, _, _, _>(&ap, &author_kp, author, 1);
            AccumMod::add_params(
                Origin::signed(1),
                AddAccumulatorParams {
                    params: params.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                AccumulatorParams::get(author, IncId::from(1u8)),
                Some(params)
            );
            assert!(
                accumulator_events().contains(&(super::super::Event::ParamsAdded(author, 1u8.into()), vec![]))
            );

            run_to_block(30);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100].try_into().unwrap(),
            };
            let ak = AddAccumulatorPublicKey {
                public_key: key.clone(),
                nonce: next_nonce,
            };
            let sig = did_sig::<Test, _, _, _>(&ak, &author_kp, author, 1);
            AccumMod::add_public_key(
                Origin::signed(1),
                AddAccumulatorPublicKey {
                    public_key: key.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(AccumulatorKeys::get(author, IncId::from(1u8)), Some(key));
            assert!(
                accumulator_events().contains(&(super::super::Event::KeyAdded(author, 1u8.into()), vec![]))
            );

            run_to_block(40);
            let mut current_block = 40;

            macro_rules! check {
                ($id: ident, $key_id: expr, $created_at: expr) => {{
                    let accumulator = Accumulator::Positive(AccumulatorCommon {
                        accumulated: vec![3; 32].try_into().unwrap(),
                        key_ref: AccumPublicKeyStorageKey(author, $key_id.into()),
                    });
                    let add_accum = AddAccumulator {
                        id: $id,
                        accumulator: accumulator.clone(),
                        nonce: next_nonce,
                    };
                    let sig = did_sig(&add_accum, &author_kp, author, 1);
                    AccumMod::add_accumulator(Origin::signed(1), add_accum, sig).unwrap();
                    check_nonce(&author, next_nonce);
                    next_nonce += 1;
                    assert_eq!(
                        Accumulators::<Test>::get($id),
                        Some(AccumulatorWithUpdateInfo::new(accumulator.clone(), $created_at))
                    );
                    assert!(accumulator_events().contains(&(
                        super::super::Event::AccumulatorAdded($id, accumulator.accumulated().to_vec().into()),
                        vec![<Test as frame_system::Config>::Hashing::hash(&$id[..])]
                    )));

                    let resp = AccumMod::get_accumulator_with_public_key_and_params(&$id).unwrap();
                    if ($key_id == 0) {
                        assert!(resp.1.is_none())
                    } else {
                        assert!(resp.1.is_some())
                    }

                    run_to_block(current_block + 10);
                    current_block += 10;

                    let mut update_accum = UpdateAccumulator {
                        id: $id,
                        new_accumulated: vec![4; 32].try_into().unwrap(),
                        additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
                        removals: Some(vec![vec![9, 4].into()]),
                        witness_update_info: Some(vec![1, 2, 3, 4].into()),
                        nonce: next_nonce + 1,
                    };
                    let sig = did_sig(&update_accum, &author_kp, author, 1);
                    assert_err!(
                        AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                        crate::did::Error::<Test>::InvalidNonce
                    );
                    check_nonce(&author, next_nonce - 1);

                    update_accum.nonce = next_nonce - 1;
                    let sig = did_sig(&update_accum, &author_kp, author, 1);
                    assert_err!(
                        AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                        crate::did::Error::<Test>::InvalidNonce
                    );
                    check_nonce(&author, next_nonce - 1);

                    update_accum.nonce = next_nonce;
                    let sig = did_sig(&update_accum, &author_kp, author, 1);
                    AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
                    check_nonce(&author, next_nonce);
                    next_nonce += 1;

                    let accumulator = Accumulator::Positive(AccumulatorCommon {
                        accumulated: vec![4; 32].try_into().unwrap(),
                        key_ref: AccumPublicKeyStorageKey(author, $key_id.into()),
                    });
                    assert_eq!(
                        Accumulators::<Test>::get($id),
                        Some(AccumulatorWithUpdateInfo {
                            created_at: $created_at,
                            last_updated_at: current_block,
                            accumulator: accumulator.clone()
                        })
                    );
                    assert!(accumulator_events().contains(&(
                        super::super::Event::AccumulatorUpdated($id, accumulator.accumulated().to_vec().into()),
                        vec![<Test as frame_system::Config>::Hashing::hash(&$id[..])]
                    )));

                    run_to_block(current_block + 10);
                    current_block += 10;

                    let update_accum = UpdateAccumulator {
                        id: $id,
                        new_accumulated: vec![5; 32].try_into().unwrap(),
                        additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
                        removals: None,
                        witness_update_info: Some(vec![1, 1, 0, 11, 8, 19].into()),
                        nonce: next_nonce,
                    };
                    let sig = did_sig(&update_accum, &author_kp, author, 1);
                    AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
                    check_nonce(&author, next_nonce);
                    next_nonce += 1;

                    let accumulator = Accumulator::Positive(AccumulatorCommon {
                        accumulated: vec![5; 32].try_into().unwrap(),
                        key_ref: AccumPublicKeyStorageKey(author, $key_id.into()),
                    });
                    assert_eq!(
                        Accumulators::<Test>::get($id),
                        Some(AccumulatorWithUpdateInfo {
                            created_at: $created_at,
                            last_updated_at: current_block,
                            accumulator: accumulator.clone()
                        })
                    );
                    assert!(accumulator_events().contains(&(
                        super::super::Event::AccumulatorUpdated($id, accumulator.accumulated().to_vec().into()),
                        vec![<Test as frame_system::Config>::Hashing::hash(&$id[..])]
                    )));

                    run_to_block(current_block + 10);
                    current_block += 10;

                    let mut rem_accum = RemoveAccumulator {
                        id: $id,
                        nonce: next_nonce - 1,
                    };
                    let sig = did_sig(&rem_accum, &author_kp, author, 1);
                    assert_err!(
                        AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                        crate::did::Error::<Test>::InvalidNonce
                    );
                    check_nonce(&author, next_nonce - 1);

                    rem_accum.nonce = next_nonce + 1;
                    let sig = did_sig(&rem_accum, &author_kp, author, 1);
                    assert_err!(
                        AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                        crate::did::Error::<Test>::InvalidNonce
                    );
                    check_nonce(&author, next_nonce - 1);

                    rem_accum.nonce = next_nonce;
                    let sig = did_sig(&rem_accum, &author_kp, author, 1);
                    AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();
                    check_nonce(&author, next_nonce);
                    assert_eq!(Accumulators::<Test>::get($id), None);
                    assert!(accumulator_events().contains(&(
                        super::super::Event::AccumulatorRemoved($id),
                        vec![<Test as frame_system::Config>::Hashing::hash(&$id[..])]
                    )));
                    assert!(AccumMod::get_accumulator_with_public_key_and_params(&$id).is_none());
                    next_nonce += 1;

                    current_block += 10;
                    run_to_block(current_block);
                }}
            }

            let id = AccumulatorId(rand::random());
            check!(id, 1_u32, 40);

            // Accumulator can be created with a key ref of 0.
            let id1 = AccumulatorId(rand::random());
            let created_at = current_block;
            check!(id1, 0_u32, created_at);

            // Multiple accumulators can be created with a key ref of 0.
            let id2 = AccumulatorId(rand::random());
            let created_at = current_block;
            check!(id2, 0_u32, created_at);

            // Cannot create an accumulator without a key with a key reference of non-zero
            let id3 = AccumulatorId(rand::random());
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32].try_into().unwrap(),
                key_ref: AccumPublicKeyStorageKey(author, 2_u32.into()),
            });
            let add_accum = AddAccumulator {
                id: id3,
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = did_sig(&add_accum, &author_kp, author, 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum, sig),
                Error::<Test>::PublicKeyDoesntExist
            );
        });
    }
}
