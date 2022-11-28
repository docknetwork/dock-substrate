use super::*;
use crate::{
    did::{tests::check_did_detail, AddControllers},
    test_common::*,
};
use frame_support::assert_err;
use sp_core::{sr25519, H256};

fn sign_add_params<T: Config>(
    keypair: &sr25519::Pair,
    ap: &AddBBSPlusParams<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<BBSPlusParamsOwner> {
    did_sig::<T, _, _>(ap, keypair, BBSPlusParamsOwner(signer), key_id)
}

fn sign_remove_params<T: Config>(
    keypair: &sr25519::Pair,
    rp: &RemoveBBSPlusParams<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<BBSPlusParamsOwner> {
    did_sig::<T, _, _>(rp, keypair, BBSPlusParamsOwner(signer), key_id)
}

fn sign_add_key<T: Config>(
    keypair: &sr25519::Pair,
    ak: &AddBBSPlusPublicKey<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<Controller> {
    did_sig::<T, _, _>(ak, keypair, Controller(signer), key_id)
}

fn sign_remove_key<T: Config>(
    keypair: &sr25519::Pair,
    rk: &RemoveBBSPlusPublicKey<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<Controller> {
    did_sig::<T, _, _>(rk, keypair, Controller(signer), key_id)
}

fn bbs_plus_events() -> Vec<super::Event> {
    System::events()
        .iter()
        .filter_map(|event_record| {
            let system::EventRecord::<TestEvent, H256> {
                phase: _p,
                event,
                topics: _t,
            } = event_record;
            match event {
                TestEvent::BBSPlus(e) => Some(e.clone()),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn add_remove_params() {
    ext().execute_with(|| {
        run_to_block(5);

        let (author, author_kp) = newdid();
        let mut next_nonce = 5 + 1;
        check_nonce(&author, next_nonce - 1);

        run_to_block(6);

        let (author_1, author_1_kp) = newdid();
        let mut next_nonce_1 = 6 + 1;
        check_nonce(&author_1, next_nonce_1 - 1);

        run_to_block(10);

        let params_bytes = vec![1u8; 600];
        let mut params = BBSPlusParameters {
            label: Some(vec![0, 1, 2, 3]),
            curve_type: CurveType::Bls12381,
            bytes: params_bytes,
        };
        let ap = AddBBSPlusParams {
            params: params.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);

        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_err!(
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: next_nonce
                },
                sig.clone()
            ),
            Error::<Test>::ParamsTooBig
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author),
            1u8.into()
        )));
        check_nonce(&author, next_nonce - 1);

        run_to_block(15);

        params.bytes = vec![1u8; 500];

        assert_err!(
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: next_nonce
                },
                sig.clone()
            ),
            did::Error::<Test>::InvalidSignature
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            None
        );
        assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author),
            1u8.into()
        )));
        check_nonce(&author, next_nonce - 1);

        run_to_block(20);

        let ap = AddBBSPlusParams {
            params: params.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
        BBSPlusMod::add_params(
            Origin::signed(1),
            AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce,
            },
            sig,
        )
        .unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(1u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );

        assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author),
            1u8.into()
        )));

        run_to_block(21);

        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
            None
        );
        let params_1 = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![1u8; 100],
        };
        let ap = AddBBSPlusParams {
            params: params_1.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
        BBSPlusMod::add_params(
            Origin::signed(1),
            AddBBSPlusParams {
                params: params_1.clone(),
                nonce: next_nonce,
            },
            sig,
        )
        .unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(2u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
            Some(params_1)
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author),
            2u8.into()
        )));

        run_to_block(25);

        let params_2 = BBSPlusParameters {
            label: Some(vec![0, 9, 1]),
            curve_type: CurveType::Bls12381,
            bytes: vec![9u8; 100],
        };
        let ap = AddBBSPlusParams {
            params: params_2.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_add_params::<Test>(&author_1_kp, &ap, author_1.clone(), 1);
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
            None
        );
        BBSPlusMod::add_params(
            Origin::signed(1),
            AddBBSPlusParams {
                params: params_2.clone(),
                nonce: next_nonce_1,
            },
            sig,
        )
        .unwrap();
        check_nonce(&author_1, next_nonce_1);
        next_nonce_1 += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(1u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
            Some(params_2.clone())
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(2u8)
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author_1),
            1u8.into()
        )));

        run_to_block(30);

        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            None
        );
        let params_3 = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![8u8; 100],
        };
        let ap = AddBBSPlusParams {
            params: params_3.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
        BBSPlusMod::add_params(
            Origin::signed(1),
            AddBBSPlusParams {
                params: params_3.clone(),
                nonce: next_nonce,
            },
            sig,
        )
        .unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(3u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            Some(params_3.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
            BBSPlusParamsOwner(author),
            3u8.into()
        )));

        let rf = (BBSPlusParamsOwner(author.clone()), 5u8.into());
        let rp = RemoveBBSPlusParams {
            params_ref: rf,
            nonce: next_nonce,
        };
        let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
        assert_err!(
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()),
            Error::<Test>::ParamsDontExist
        );
        check_nonce(&author, next_nonce - 1);

        let rf = (BBSPlusParamsOwner(author.clone()), 2u8.into());
        let mut rp = RemoveBBSPlusParams {
            params_ref: rf,
            nonce: next_nonce_1,
        };

        let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
        assert_err!(
            BBSPlusMod::remove_params(Origin::signed(1), rp.clone(), sig.clone()),
            Error::<Test>::NotOwner
        );
        check_nonce(&author_1, next_nonce_1 - 1);

        rp.nonce = next_nonce;
        let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
        BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(3u8)
        );
        // Entry gone from storage
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
            None
        );
        // Other entries remain as it is
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            Some(params_3.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
            Some(params_2.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
            BBSPlusParamsOwner(author),
            2u8.into()
        )));

        let rp = RemoveBBSPlusParams::<Test> {
            params_ref: rf,
            nonce: next_nonce,
        };
        let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
        // Cannot remove as already removed
        assert_err!(
            BBSPlusMod::remove_params(
                Origin::signed(1),
                RemoveBBSPlusParams {
                    params_ref: rf,
                    nonce: next_nonce
                },
                sig.clone()
            ),
            Error::<Test>::ParamsDontExist
        );
        check_nonce(&author, next_nonce - 1);

        let rf = (BBSPlusParamsOwner(author_1.clone()), 1u8.into());
        let rp = RemoveBBSPlusParams {
            params_ref: rf,
            nonce: next_nonce_1,
        };
        let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
        BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
        check_nonce(&author_1, next_nonce_1);
        next_nonce_1 += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(1u8)
        );
        // Entry gone from storage
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
            None
        );
        // Other entries remain as it is
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            Some(params_3.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
            BBSPlusParamsOwner(author_1),
            1u8.into()
        )));

        let rp = RemoveBBSPlusParams::<Test> {
            params_ref: rf,
            nonce: next_nonce_1,
        };
        let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
        // Cannot remove as already removed
        assert_err!(
            BBSPlusMod::remove_params(
                Origin::signed(1),
                RemoveBBSPlusParams {
                    params_ref: rf,
                    nonce: next_nonce_1
                },
                sig.clone()
            ),
            Error::<Test>::ParamsDontExist
        );
        check_nonce(&author_1, next_nonce_1 - 1);

        let rf = (BBSPlusParamsOwner(author.clone()), 3u8.into());
        let rp = RemoveBBSPlusParams {
            params_ref: rf,
            nonce: next_nonce,
        };
        let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
        BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(3u8)
        );
        // Entry gone from storage
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            None
        );
        // Other entries remain as it is
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
            BBSPlusParamsOwner(author),
            3u8.into()
        )));

        let rf = (BBSPlusParamsOwner(author.clone()), 1u8.into());
        let rp = RemoveBBSPlusParams {
            params_ref: rf,
            nonce: next_nonce,
        };
        let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
        BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(3u8)
        );
        // Entry gone from storage
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            None
        );
        assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
            BBSPlusParamsOwner(author),
            1u8.into()
        )));
    });
}

#[test]
fn add_remove_public_key() {
    ext().execute_with(|| {
        run_to_block(10);

        let (author, author_kp) = newdid();
        let mut next_nonce = 10 + 1;
        check_nonce(&author, next_nonce - 1);

        run_to_block(15);

        let mut key = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![1u8; 200],
        };
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);

        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_err!(
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
            Error::<Test>::PublicKeyTooBig
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));
        check_nonce(&author, next_nonce - 1);

        run_to_block(30);

        key.bytes = vec![1u8; 100];
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author.clone(),
            nonce: next_nonce,
        };

        assert_err!(
            BBSPlusMod::add_public_key(Origin::signed(1), ak.clone(), sig.clone()),
            did::Error::<Test>::InvalidSignature
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), None);
        assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));
        check_nonce(&author, next_nonce - 1);

        run_to_block(35);

        let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));

        assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);
        let key_1 = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![1u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), Some(key_1));
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3u8.into())));

        run_to_block(45);

        let (author_1, author_kp_1) = newdid();
        let mut next_nonce_1 = 45 + 1;

        run_to_block(50);

        let key_2 = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![9u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key_2.clone(),
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(1u8)), None);
        assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), None);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
        check_nonce(&author_1, next_nonce_1);
        next_nonce_1 += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(2u8)),
            Some(key_2.clone())
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 2u8.into())));

        run_to_block(55);

        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
            None
        );
        let key_3 = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![8u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key_3.clone(),
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(4u8)),
            Some(key_3.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3u8.into())));

        run_to_block(60);

        let rf = (author.clone(), 5u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
        assert_err!(
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
            Error::<Test>::PublicKeyDoesntExist
        );
        check_nonce(&author, next_nonce - 1);

        let rf = (author.clone(), 3u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
        assert_err!(
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
            Error::<Test>::NotOwner
        );

        let rf = (author.clone(), 3u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
        BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;

        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        // Entry gone from storage
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);
        // Other entries remain as it is
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(4u8)),
            Some(key_3.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), Some(key_2));

        let rf = (author.clone(), 3u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
        // Cannot remove as already removed
        assert_err!(
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
            Error::<Test>::PublicKeyDoesntExist
        );
        check_nonce(&author, next_nonce - 1);

        run_to_block(70);

        let rf = (author_1.clone(), 2u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
        BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
        check_nonce(&author_1, next_nonce_1);
        next_nonce_1 += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        // Entry gone from storage
        assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), None);
        // Other entries remain as it is
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(4u8)), Some(key_3));
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author_1, 2u8.into())));

        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
        // Cannot remove as already removed
        assert_err!(
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
            Error::<Test>::PublicKeyDoesntExist
        );
        check_nonce(&author_1, next_nonce_1 - 1);

        let rf = (author.clone(), 4u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
        BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        // Entry gone from storage
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(4u8)), None);
        // Other entries remain as it is
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), Some(key));
        assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 4u8.into())));

        let rf = (author.clone(), 2u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
        BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        // Counter doesn't go back
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        // Entry gone from storage
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), None);
        assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 2u8.into())));

        run_to_block(80);

        let params = BBSPlusParameters {
            label: Some(vec![0, 1, 2, 3]),
            curve_type: CurveType::Bls12381,
            bytes: vec![19; 100],
        };
        let ap = AddBBSPlusParams {
            params: params.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
        BBSPlusMod::add_params(
            Origin::signed(1),
            AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce,
            },
            sig,
        )
        .unwrap();
        check_nonce(&author, next_nonce);
        next_nonce += 1;
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(1u8)
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );

        // Add key with reference to non-existent params
        let key_4 = BBSPlusPublicKey {
            params_ref: Some((BBSPlusParamsOwner(author.clone()), 4u8.into())),
            curve_type: CurveType::Bls12381,
            bytes: vec![92u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key_4.clone(),
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
        assert_err!(
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
            Error::<Test>::ParamsDontExist
        );
        check_nonce(&author_1, next_nonce_1 - 1);
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );

        // Add key with reference to existent params
        let key_4 = BBSPlusPublicKey {
            params_ref: Some((BBSPlusParamsOwner(author.clone()), 1u8.into())),
            curve_type: CurveType::Bls12381,
            bytes: vec![92u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key_4.clone(),
            did: author_1.clone(),
            nonce: next_nonce_1,
        };
        let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
        check_nonce(&author_1, next_nonce_1);
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(3u8)),
            Some(key_4.clone())
        );
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 3u8.into())));

        let ak = AddBBSPlusPublicKey {
            key: key_4.clone(),
            did: author.clone(),
            nonce: next_nonce,
        };
        let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
        check_nonce(&author, next_nonce);
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(1u8)
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(5u8)), Some(key_4));
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 5u8.into())));
    });
}

#[test]
fn add_remove_public_key_by_controller() {
    ext().execute_with(|| {
        run_to_block(10);

        let (did, did_kp) = newdid();
        let mut next_nonce = 10 + 1;
        check_did_detail(&did, 1, 1, 1, next_nonce - 1);

        run_to_block(20);

        let (did_1, did_1_kp) = newdid();
        let mut next_nonce_1 = 20 + 1;
        check_nonce(&did_1, next_nonce_1 - 1);
        check_did_detail(&did_1, 1, 1, 1, next_nonce_1 - 1);

        // Make `did` controller of `did`
        let add_controllers = AddControllers {
            did: did_1,
            controllers: vec![did].into_iter().map(Controller).collect(),
            nonce: next_nonce_1,
        };
        let sig = did_sig::<_, _, _>(&add_controllers, &did_1_kp, Controller(did_1), 1);
        DIDModule::add_controllers(Origin::signed(1), add_controllers, sig).unwrap();
        assert!(DIDModule::is_controller(&did_1, &Controller(did.clone())));
        check_did_detail(&did_1, 1, 1, 2, next_nonce_1);
        check_did_detail(&did, 1, 1, 1, next_nonce - 1);
        next_nonce_1 += 1;

        let key = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![8u8; 100],
        };
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: did_1,
            nonce: next_nonce,
        };
        let sig = sign_add_key(&did_kp, &ak, did.clone(), 1);
        BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();

        check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
        check_did_detail(&did, 1, 1, 1, next_nonce);

        next_nonce += 1;

        assert_eq!(
            BbsPlusKeys::get(&did_1, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(BbsPlusKeys::get(&did, IncId::from(2u8)), None);
        assert!(bbs_plus_events().contains(&super::Event::KeyAdded(did_1, 2u8.into())));

        let rf = (did_1, 2u8.into());
        let rk = RemoveBBSPlusPublicKey {
            key_ref: rf,
            did: did_1,
            nonce: next_nonce,
        };
        let sig = sign_remove_key(&did_kp, &rk, did.clone(), 1);
        BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();

        check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
        check_did_detail(&did, 1, 1, 1, next_nonce);

        assert_eq!(BbsPlusKeys::get(&did_1, IncId::from(2u8)), None);
        assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(did_1, 2u8.into())));
    })
}

#[test]
fn add_params_keys() {
    ext().execute_with(|| {
        run_to_block(10);
        let (author, _) = newdid();
        let next_nonce = 10 + 1;

        run_to_block(20);
        let (author_1, _) = newdid();

        run_to_block(30);
        let (author_2, _) = newdid();

        let params = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![5; 100],
        };
        let params_1 = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![6; 100],
        };

        let key = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![1; 80],
        };
        let key_1 = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![2; 80],
        };
        let key_2 = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![3; 80],
        };

        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(0u8)
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_2)),
            IncId::from(0u8)
        );

        run_to_block(35);

        assert!(BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce
            },
            BBSPlusParamsOwner(author)
        )
        .is_ok());
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(1u8)
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );

        run_to_block(40);

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author.clone(),
            nonce: did_detail.next_nonce(),
        };
        assert_eq!(did_detail.nonce + 1, ak.nonce);
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);

        run_to_block(50);

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key_1.clone(),
            did: author.clone(),
            nonce: did_detail.next_nonce(),
        };
        assert_eq!(did_detail.nonce + 1, ak.nonce);
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(3u8)),
            Some(key_1.clone())
        );

        run_to_block(60);

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key_2.clone(),
            did: author.clone(),
            nonce: did_detail.next_nonce(),
        };
        assert_eq!(did_detail.nonce + 1, ak.nonce);
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(3u8)),
            Some(key_1.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(4u8)),
            Some(key_2.clone())
        );

        run_to_block(70);

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        assert!(BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params_1.clone(),
                nonce: did_detail.next_nonce()
            },
            BBSPlusParamsOwner(author)
        )
        .is_ok());
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author)),
            IncId::from(2u8)
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(3u8)),
            Some(key_1.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author, IncId::from(4u8)),
            Some(key_2.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
            Some(params.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
            Some(params_1.clone())
        );

        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(0u8)
        );
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_2)),
            IncId::from(0u8)
        );

        run_to_block(80);

        let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author_1.clone(),
            nonce: did_detail_1.next_nonce(),
        };
        assert_eq!(did_detail_1.nonce + 1, ak.nonce);
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(2u8)),
            Some(key.clone())
        );

        run_to_block(90);

        let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
        assert!(BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params.clone(),
                nonce: did_detail_1.next_nonce()
            },
            BBSPlusParamsOwner(author_1)
        )
        .is_ok());
        assert_eq!(
            ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
            IncId::from(1u8)
        );
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(
            BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
            Some(params.clone())
        );

        run_to_block(100);

        let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key_1.clone(),
            did: author_1.clone(),
            nonce: did_detail_1.next_nonce(),
        };
        assert_eq!(did_detail_1.nonce + 1, ak.nonce);
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(2u8)),
            Some(key.clone())
        );
        assert_eq!(
            BbsPlusKeys::get(&author_1, IncId::from(3u8)),
            Some(key_1.clone())
        );
    });
}

#[test]
fn get_params_and_keys() {
    ext().execute_with(|| {
        let (author, _) = newdid();

        let (author_1, _) = newdid();

        let params = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![5; 100],
        };
        let params_1 = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![6; 100],
        };
        let params_2 = BBSPlusParameters {
            label: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![7; 100],
        };

        let key = BBSPlusPublicKey {
            params_ref: None,
            curve_type: CurveType::Bls12381,
            bytes: vec![1; 80],
        };
        let key_1 = BBSPlusPublicKey {
            params_ref: Some((BBSPlusParamsOwner(author.clone()), 1u8.into())),
            curve_type: CurveType::Bls12381,
            bytes: vec![2; 80],
        };
        let key_2 = BBSPlusPublicKey {
            params_ref: Some((BBSPlusParamsOwner(author_1.clone()), 1u8.into())),
            curve_type: CurveType::Bls12381,
            bytes: vec![3; 80],
        };

        assert_eq!(
            BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)).len(),
            0
        );
        assert_eq!(
            BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author_1)).len(),
            0
        );
        assert_eq!(
            BBSPlusMod::get_public_key_with_params(&(author, 0u8.into())),
            None
        );
        assert_eq!(
            BBSPlusMod::get_public_key_with_params(&(author_1, 0u8.into())),
            None
        );

        BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params.clone(),
                nonce: 0, // Doesn't matter
            },
            BBSPlusParamsOwner(author),
        )
        .unwrap();
        BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params_1.clone(),
                nonce: 0, // Doesn't matter
            },
            BBSPlusParamsOwner(author_1),
        )
        .unwrap();
        BBSPlusMod::add_params_(
            AddBBSPlusParams {
                params: params_2.clone(),
                nonce: 0, // Doesn't matter
            },
            BBSPlusParamsOwner(author_1),
        )
        .unwrap();

        assert_eq!(
            BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)),
            {
                let mut m = BTreeMap::new();
                m.insert(1u8.into(), params.clone());
                m
            }
        );

        assert_eq!(
            BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author_1)),
            {
                let mut m = BTreeMap::new();
                m.insert(1u8.into(), params_1.clone());
                m.insert(2u8.into(), params_2.clone());
                m
            }
        );

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key.clone(),
            did: author.clone(),
            nonce: did_detail.next_nonce(),
        };
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BBSPlusMod::get_public_key_with_params(&(author, 2u8.into())),
            Some((key.clone(), None))
        );

        let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key_1.clone(),
            did: author_1.clone(),
            nonce: did_detail_1.next_nonce(),
        };
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BBSPlusMod::get_public_key_with_params(&(author_1, 2u8.into())),
            Some((key_1.clone(), Some(params.clone())))
        );

        let did_detail = DIDModule::onchain_did_details(&author).unwrap();
        let ak = AddBBSPlusPublicKey {
            key: key_2.clone(),
            did: author.clone(),
            nonce: did_detail.next_nonce(),
        };
        assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
            BBSPlusMod::add_public_key_,
            ak,
        )
        .is_ok());
        assert_eq!(
            BBSPlusMod::get_public_key_with_params(&(author, 3u8.into())),
            Some((key_2.clone(), Some(params_1.clone())))
        );

        assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author_1)), {
            let mut m = BTreeMap::new();
            m.insert(2u8.into(), (key_1.clone(), Some(params.clone())));
            m
        });

        assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author)), {
            let mut m = BTreeMap::new();
            m.insert(2u8.into(), (key.clone(), None));
            m.insert(3u8.into(), (key_2.clone(), Some(params_1.clone())));
            m
        });

        BbsPlusParams::remove(&BBSPlusParamsOwner(author), IncId::from(1u8));

        assert_eq!(
            BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)).len(),
            0
        );

        assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author_1)), {
            let mut m = BTreeMap::new();
            m.insert(2u8.into(), (key_1.clone(), None));
            m
        });
    });
}
