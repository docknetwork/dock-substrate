use super::*;
use crate::tests::common::*;
use frame_support::assert_err;
use sp_core::{sr25519, Hasher, H256};

fn sign_add_params<T: Config>(
    keypair: &sr25519::Pair,
    params: &AddAccumulatorParams<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(params, keypair, signer, key_id)
}

fn sign_remove_params<T: Config>(
    keypair: &sr25519::Pair,
    remove: &RemoveAccumulatorParams<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(remove, keypair, signer, key_id)
}

fn sign_add_key<T: Config>(
    keypair: &sr25519::Pair,
    public_key: &AddAccumulatorPublicKey<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(public_key, keypair, signer, key_id)
}

fn sign_remove_key<T: Config>(
    keypair: &sr25519::Pair,
    remove: &RemoveAccumulatorPublicKey<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(remove, keypair, signer, key_id)
}

fn sign_add_accum<T: Config>(
    keypair: &sr25519::Pair,
    accum: &AddAccumulator<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(accum, keypair, signer, key_id)
}

fn sign_remove_accum<T: Config>(
    keypair: &sr25519::Pair,
    remove: &RemoveAccumulator<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(remove, keypair, signer, key_id)
}

fn sign_update_accum<T: Config>(
    keypair: &sr25519::Pair,
    update: &UpdateAccumulator<T>,
    signer: AccumulatorOwner,
    key_id: u32,
) -> DidSignature<AccumulatorOwner> {
    did_sig::<T, _, _>(update, keypair, signer, key_id)
}

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

#[test]
fn accumulator_errors() {
    ext().execute_with(|| {
        run_to_block(10);

        let (author, author_kp) = newdid();
        let author = AccumulatorOwner(author);
        let mut next_nonce = 10 + 1;
        check_nonce(&author, next_nonce - 1);

        run_to_block(11);

        let (author_1, author_1_kp) = newdid();
        let author_1 = AccumulatorOwner(author_1);
        let next_nonce_1 = 11 + 1;
        check_nonce(&author_1, next_nonce_1 - 1);

        run_to_block(30);

        assert!(vec![3; 300]
            .try_into()
            .map(
                |accumulated| Accumulator::<Test>::Positive(AccumulatorCommon {
                    accumulated,
                    key_ref: (author, 1u8.into()),
                })
            )
            .is_err());

        let id = AccumulatorId(rand::random());

        let accumulator = Accumulator::Positive(AccumulatorCommon {
            key_ref: (author, 1u8.into()),
            accumulated: vec![3; 100].try_into().unwrap(),
        });

        let add_accum = AddAccumulator {
            id,
            accumulator,
            nonce: next_nonce,
        };
        let sig = sign_add_accum(&author_kp, &add_accum, author, 1);
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
        let sig = sign_add_params::<Test>(&author_kp, &ap, author, 1);
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
        let sig = sign_add_key::<Test>(&author_kp, &ak, author, 1);
        AccumMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        run_to_block(60);

        let id = AccumulatorId(rand::random());
        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![3; 32].try_into().unwrap(),
            key_ref: (author, 1u8.into()),
        });
        let add_accum = AddAccumulator {
            id,
            accumulator: accumulator.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_accum(&author_kp, &add_accum, author, 1);
        AccumMod::add_accumulator(Origin::signed(1), add_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Cannot add with same id again
        let add_accum = AddAccumulator {
            id,
            accumulator,
            nonce: next_nonce,
        };
        let sig = sign_add_accum(&author_kp, &add_accum, author, 1);
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
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        assert_err!(
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
            Error::<Test>::AccumulatorDoesntExist
        );

        update_accum.id = id;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
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
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
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
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        run_to_block(90);

        update_accum.nonce = next_nonce - 1;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        assert_err!(
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
            sp_runtime::DispatchError::Other("Incorrect nonce")
        );
        check_nonce(&author, next_nonce - 1);

        update_accum.nonce = next_nonce;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        run_to_block(100);

        update_accum.nonce = next_nonce;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Only accumulator owner can update it
        update_accum.nonce = next_nonce_1;
        let sig = sign_update_accum(&author_1_kp, &update_accum, author_1, 1);
        assert_err!(
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
            Error::<Test>::NotAccumulatorOwner
        );
        check_nonce(&author_1, next_nonce_1 - 1);
        update_accum.nonce = next_nonce;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Only accumulator owner can remove it
        let rem_accum = RemoveAccumulator {
            id,
            nonce: next_nonce_1,
        };
        let sig = sign_remove_accum(&author_1_kp, &rem_accum, author_1, 1);
        assert_err!(
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig),
            Error::<Test>::NotAccumulatorOwner
        );
        check_nonce(&author_1, next_nonce_1 - 1);
        let rem_accum = RemoveAccumulator {
            id,
            nonce: next_nonce,
        };
        let sig = sign_remove_accum(&author_kp, &rem_accum, author, 1);
        AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Only key owner can remove it
        let rem = RemoveAccumulatorPublicKey {
            key_ref: (author, 1u8.into()),
            nonce: next_nonce_1,
        };
        let sig = sign_remove_key(&author_1_kp, &rem, author_1, 1);
        assert_err!(
            AccumMod::remove_public_key(Origin::signed(1), rem, sig),
            Error::<Test>::NotAccumulatorOwner
        );
        check_nonce(&author_1, next_nonce_1 - 1);
        let rem = RemoveAccumulatorPublicKey {
            key_ref: (author, 1u8.into()),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rem, author, 1);
        AccumMod::remove_public_key(Origin::signed(1), rem, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Only params owner can remove it
        let rem = RemoveAccumulatorParams {
            params_ref: (author, 1u8.into()),
            nonce: next_nonce_1,
        };
        let sig = sign_remove_params(&author_1_kp, &rem, author_1, 1);
        assert_err!(
            AccumMod::remove_params(Origin::signed(1), rem, sig),
            Error::<Test>::NotAccumulatorOwner
        );
        check_nonce(&author_1, next_nonce_1 - 1);

        let rem = RemoveAccumulatorParams {
            params_ref: (author, 1u8.into()),
            nonce: next_nonce,
        };
        let sig = sign_remove_params(&author_kp, &rem, author, 1);
        AccumMod::remove_params(Origin::signed(1), rem, sig).unwrap();
        check_nonce(&author, next_nonce);
    });
}

#[test]
fn add_remove_accumulator() {
    ext().execute_with(|| {
        run_to_block(10);

        let (author, author_kp) = newdid();
        let author = AccumulatorOwner(author);
        let mut next_nonce = 10 + 1;

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
        let sig = sign_add_params::<Test>(&author_kp, &ap, author, 1);
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
            accumulator_events().contains(&(super::Event::ParamsAdded(author, 1u8.into()), vec![]))
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
        let sig = sign_add_key::<Test>(&author_kp, &ak, author, 1);
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
            accumulator_events().contains(&(super::Event::KeyAdded(author, 1u8.into()), vec![]))
        );

        run_to_block(40);

        let id = AccumulatorId(rand::random());
        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![3; 32].try_into().unwrap(),
            key_ref: (author, 1u8.into()),
        });
        let add_accum = AddAccumulator {
            id,
            accumulator: accumulator.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_accum(&author_kp, &add_accum, author, 1);
        AccumMod::add_accumulator(Origin::signed(1), add_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            Accumulators::<Test>::get(id),
            Some(AccumulatorWithUpdateInfo::new(accumulator.clone(), 40))
        );
        assert!(accumulator_events().contains(&(
            super::Event::AccumulatorAdded(id, accumulator.accumulated().to_vec().into()),
            vec![<Test as frame_system::Config>::Hashing::hash(&id[..])]
        )));

        run_to_block(50);

        let mut update_accum = UpdateAccumulator {
            id,
            new_accumulated: vec![4; 32].try_into().unwrap(),
            additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
            removals: Some(vec![vec![9, 4].into()]),
            witness_update_info: Some(vec![1, 2, 3, 4].into()),
            nonce: next_nonce + 1,
        };
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        assert_err!(
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
            sp_runtime::DispatchError::Other("Incorrect nonce")
        );
        check_nonce(&author, next_nonce - 1);

        update_accum.nonce = next_nonce - 1;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        assert_err!(
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
            sp_runtime::DispatchError::Other("Incorrect nonce")
        );
        check_nonce(&author, next_nonce - 1);

        update_accum.nonce = next_nonce;
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![4; 32].try_into().unwrap(),
            key_ref: (author, 1u8.into()),
        });
        assert_eq!(
            Accumulators::<Test>::get(id),
            Some(AccumulatorWithUpdateInfo {
                created_at: 40,
                last_updated_at: 50,
                accumulator: accumulator.clone()
            })
        );
        assert!(accumulator_events().contains(&(
            super::Event::AccumulatorUpdated(id, accumulator.accumulated().to_vec().into()),
            vec![<Test as frame_system::Config>::Hashing::hash(&id[..])]
        )));

        run_to_block(60);

        let update_accum = UpdateAccumulator {
            id,
            new_accumulated: vec![5; 32].try_into().unwrap(),
            additions: Some(vec![vec![0, 1, 2].into(), vec![3, 5, 4].into()]),
            removals: None,
            witness_update_info: Some(vec![1, 1, 0, 11, 8, 19].into()),
            nonce: next_nonce,
        };
        let sig = sign_update_accum(&author_kp, &update_accum, author, 1);
        AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![5; 32].try_into().unwrap(),
            key_ref: (author, 1u8.into()),
        });
        assert_eq!(
            Accumulators::<Test>::get(id),
            Some(AccumulatorWithUpdateInfo {
                created_at: 40,
                last_updated_at: 60,
                accumulator: accumulator.clone()
            })
        );
        assert!(accumulator_events().contains(&(
            super::Event::AccumulatorUpdated(id, accumulator.accumulated().to_vec().into()),
            vec![<Test as frame_system::Config>::Hashing::hash(&id[..])]
        )));

        run_to_block(70);

        let mut rem_accum = RemoveAccumulator {
            id,
            nonce: next_nonce - 1,
        };
        let sig = sign_remove_accum(&author_kp, &rem_accum, author, 1);
        assert_err!(
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
            sp_runtime::DispatchError::Other("Incorrect nonce")
        );
        check_nonce(&author, next_nonce - 1);

        rem_accum.nonce = next_nonce + 1;
        let sig = sign_remove_accum(&author_kp, &rem_accum, author, 1);
        assert_err!(
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
            sp_runtime::DispatchError::Other("Incorrect nonce")
        );
        check_nonce(&author, next_nonce - 1);

        rem_accum.nonce = next_nonce;
        let sig = sign_remove_accum(&author_kp, &rem_accum, author, 1);
        AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();
        check_nonce(&author, next_nonce);
        assert_eq!(Accumulators::<Test>::get(id), None);
        assert!(accumulator_events().contains(&(
            super::Event::AccumulatorRemoved(id),
            vec![<Test as frame_system::Config>::Hashing::hash(&id[..])]
        )));
    });
}
