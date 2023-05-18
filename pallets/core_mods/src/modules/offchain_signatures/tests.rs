use super::*;
use crate::{
    did::{tests::check_did_detail, AddControllers},
    offchain_signatures,
    test_common::*,
    types::CurveType,
    util::Bytes,
};
use alloc::collections::BTreeMap;
use frame_support::assert_err;
use sp_core::{sr25519, H256};
use sp_runtime::traits::CheckedConversion;

fn sign_add_params<T: Config>(
    keypair: &sr25519::Pair,
    ap: &AddOffchainSignatureParams<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<SignatureParamsOwner> {
    did_sig::<T, _, _>(ap, keypair, SignatureParamsOwner(signer), key_id)
}

fn sign_remove_params<T: Config>(
    keypair: &sr25519::Pair,
    rp: &RemoveOffchainSignatureParams<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<SignatureParamsOwner> {
    did_sig::<T, _, _>(rp, keypair, SignatureParamsOwner(signer), key_id)
}

fn sign_add_key<T: Config>(
    keypair: &sr25519::Pair,
    ak: &AddOffchainSignaturePublicKey<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<Controller> {
    did_sig::<T, _, _>(ak, keypair, Controller(signer), key_id)
}

fn sign_remove_key<T: Config>(
    keypair: &sr25519::Pair,
    rk: &RemoveOffchainSignaturePublicKey<T>,
    signer: Did,
    key_id: u32,
) -> DidSignature<Controller> {
    did_sig::<T, _, _>(rk, keypair, Controller(signer), key_id)
}

macro_rules! with_each_scheme {
    ($key: ident, $params: ident $($tt: tt)+) => {
        mod bbs {
            use super::*;
            use BBSPublicKey as $key;
            use BBSParams as $params;

            $($tt)+
        }

        mod bbs_plus {
            use super::*;
            use BBSPlusPublicKey as $key;
            use BBSPlusParams as $params;

            $($tt)+
        }

        mod ps {
            use super::*;
            use PSPublicKey as $key;
            use PSParams as $params;

            $($tt)+
        }
    }
}

fn sig_events() -> Vec<super::Event> {
    System::events()
        .iter()
        .filter_map(|event_record| {
            let system::EventRecord::<TestEvent, H256> {
                phase: _p,
                event,
                topics: _t,
            } = event_record;
            match event {
                TestEvent::OffchainSignature(e) => Some(e.clone()),
                _ => None,
            }
        })
        .collect()
}

with_each_scheme! {
    SchemeKey,
    SchemeParams

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
            let mut params =
                SchemeParams::new(Bytes(vec![0, 1, 2, 3]), params_bytes, CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params.clone().into(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);

            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_err!(
                SignatureMod::add_params(
                    Origin::signed(1),
                    AddOffchainSignatureParams {
                        params: params.clone().into(),
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsTooBig
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(
                !sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author),
                    1u8.into()
                ))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(15);

            params.bytes = vec![1u8; 500].into();

            assert_err!(
                SignatureMod::add_params(
                    Origin::signed(1),
                    AddOffchainSignatureParams {
                        params: params.clone().into(),
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                did::Error::<Test>::InvalidSignature
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                None
            );
            assert!(
                !sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author),
                    1u8.into()
                ))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(20);

            let ap = AddOffchainSignatureParams {
                params: params.clone().into(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            SignatureMod::add_params(
                Origin::signed(1),
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );

            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author),
                    1u8.into()
                ))
            );

            run_to_block(21);

            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(2u8)),
                None
            );
            let params_1 = SchemeParams::new(None, vec![1u8; 100], CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params_1.clone().into(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            SignatureMod::add_params(
                Origin::signed(1),
                AddOffchainSignatureParams {
                    params: params_1.clone().into(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(2u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(2u8)),
                Some(params_1.into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author),
                    2u8.into()
                ))
            );

            run_to_block(25);

            let params_2 =
                SchemeParams::new(Bytes(vec![0, 9, 1]), vec![9u8; 100], CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params_2.clone().into(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_params::<Test>(&author_1_kp, &ap, author_1.clone(), 1);
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author_1), IncId::from(1u8)),
                None
            );
            SignatureMod::add_params(
                Origin::signed(1),
                AddOffchainSignatureParams {
                    params: params_2.clone().into(),
                    nonce: next_nonce_1,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(1u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author_1), IncId::from(1u8)),
                Some(params_2.clone().into())
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(2u8)
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author_1),
                    1u8.into()
                ))
            );

            run_to_block(30);

            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                None
            );
            let params_3 = SchemeParams::new(None, vec![8u8; 100], CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params_3.clone().into(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            SignatureMod::add_params(
                Origin::signed(1),
                AddOffchainSignatureParams {
                    params: params_3.clone().into(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(3u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                    SignatureParamsOwner(author),
                    3u8.into()
                ))
            );

            let rf = (SignatureParamsOwner(author.clone()), 5u8.into());
            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params::<Test>(&author_kp, &rp, author.clone(), 1);
            assert_err!(
                SignatureMod::remove_params(Origin::signed(1), rp, sig.clone()),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (SignatureParamsOwner(author.clone()), 2u8.into());
            let mut rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce_1,
            };

            let sig = sign_remove_params::<Test>(&author_1_kp, &rp, author_1.clone(), 1);
            assert_err!(
                SignatureMod::remove_params(Origin::signed(1), rp.clone(), sig.clone()),
                Error::<Test>::NotOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            rp.nonce = next_nonce;
            let sig = sign_remove_params::<Test>(&author_kp, &rp, author.clone(), 1);
            SignatureMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(2u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author_1), IncId::from(1u8)),
                Some(params_2.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                    SignatureParamsOwner(author),
                    2u8.into()
                ))
            );

            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params::<Test>(&author_kp, &rp, author.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_params(
                    Origin::signed(1),
                    RemoveOffchainSignatureParams {
                        params_ref: rf,
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (SignatureParamsOwner(author_1.clone()), 1u8.into());
            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce_1,
            };
            let sig = sign_remove_params::<Test>(&author_1_kp, &rp, author_1.clone(), 1);
            SignatureMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(1u8)
            );
            // Entry gone from storage
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author_1), IncId::from(1u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                    SignatureParamsOwner(author_1),
                    1u8.into()
                ))
            );

            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce_1,
            };
            let sig = sign_remove_params::<Test>(&author_1_kp, &rp, author_1.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_params(
                    Origin::signed(1),
                    RemoveOffchainSignatureParams {
                        params_ref: rf,
                        nonce: next_nonce_1
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rf = (SignatureParamsOwner(author.clone()), 3u8.into());
            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params::<Test>(&author_kp, &rp, author.clone(), 1);
            SignatureMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                    SignatureParamsOwner(author),
                    3u8.into()
                ))
            );

            let rf = (SignatureParamsOwner(author.clone()), 1u8.into());
            let rp = RemoveOffchainSignatureParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params::<Test>(&author_kp, &rp, author.clone(), 1);
            SignatureMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                None
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                    SignatureParamsOwner(author),
                    1u8.into()
                ))
            );
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

            let mut key = SchemeKey::new(vec![1u8; 200], None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);

            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_err!(
                SignatureMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::PublicKeyTooBig
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(
                !sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(30);

            key.bytes = vec![1u8; 100].into();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author.clone(),
                nonce: next_nonce,
            };

            assert_err!(
                SignatureMod::add_public_key(Origin::signed(1), ak.clone(), sig.clone()),
                did::Error::<Test>::InvalidSignature
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(PublicKeys::get(&author, IncId::from(2u8)), None);
            assert!(
                !sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(35);

            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );

            assert_eq!(PublicKeys::get(&author, IncId::from(3u8)), None);
            let key_1 = SchemeKey::new(vec![1u8; 100], None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(3u8)),
                Some(key_1.into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 3u8.into()))
            );

            run_to_block(45);

            let (author_1, author_kp_1) = newdid();
            let mut next_nonce_1 = 45 + 1;

            run_to_block(50);

            let key_2 = SchemeKey::new(vec![9u8; 100], None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::get(&author_1, IncId::from(1u8)), None);
            assert_eq!(PublicKeys::get(&author_1, IncId::from(2u8)), None);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(2u8)),
                Some(key_2.clone().into())
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author_1, 2u8.into()))
            );

            run_to_block(55);

            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(3u8)),
                None
            );
            let key_3 = SchemeKey::new(vec![8u8; 100], None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key_3.clone().into(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(4u8)),
                Some(key_3.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 3u8.into()))
            );

            run_to_block(60);

            let rf = (author.clone(), 5u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (author.clone(), 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::NotOwner
            );

            let rf = (author.clone(), 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::get(&author, IncId::from(3u8)), None);
            // Other entries remain as it is
            assert_eq!(
                PublicKeys::get(&author, IncId::from(4u8)),
                Some(key_3.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(2u8)),
                Some(key_2.into())
            );

            let rf = (author.clone(), 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(70);

            let rf = (author_1.clone(), 2u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::get(&author_1, IncId::from(2u8)), None);
            // Other entries remain as it is
            assert_eq!(
                PublicKeys::get(&author, IncId::from(4u8)),
                Some(key_3.into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(
                    author_1,
                    2u8.into()
                ))
            );

            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rf = (author.clone(), 4u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::get(&author, IncId::from(4u8)), None);
            // Other entries remain as it is
            assert_eq!(PublicKeys::get(&author, IncId::from(2u8)), Some(key.into()));
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(author, 4u8.into()))
            );

            let rf = (author.clone(), 2u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::get(&author, IncId::from(2u8)), None);
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(author, 2u8.into()))
            );

            run_to_block(80);

            let params =
                SchemeParams::new(Bytes(vec![0, 1, 2, 3]), vec![19; 100], CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params.clone().into(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            SignatureMod::add_params(
                Origin::signed(1),
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );

            // Add key with reference to non-existent params
            let key_4 = SchemeKey::new(
                vec![92u8; 100],
                Some((SignatureParamsOwner(author.clone()), 4u8.into())),
                CurveType::Bls12381,
            );
            let ak = AddOffchainSignaturePublicKey {
                key: key_4.clone().into(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_err!(
                SignatureMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );

            // Add key with reference to existent params
            let key_4 = SchemeKey::new(
                vec![92u8; 100],
                Some((SignatureParamsOwner(author.clone()), 1u8.into())),
                CurveType::Bls12381,
            );
            let ak = AddOffchainSignaturePublicKey {
                key: key_4.clone().into(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(3u8)),
                Some(key_4.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author_1, 3u8.into()))
            );

            let ak = AddOffchainSignaturePublicKey {
                key: key_4.clone().into(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(5u8)),
                Some(key_4.into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 5u8.into()))
            );
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

            let key = SchemeKey::new(vec![8u8; 100], None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: did_1,
                nonce: next_nonce,
            };
            let sig = sign_add_key(&did_kp, &ak, did.clone(), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();

            check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
            check_did_detail(&did, 1, 1, 1, next_nonce);

            next_nonce += 1;

            assert_eq!(
                PublicKeys::get(&did_1, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(PublicKeys::get(&did, IncId::from(2u8)), None);
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(did_1, 2u8.into()))
            );

            let rf = (did_1, 2u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: did_1,
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&did_kp, &rk, did.clone(), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();

            check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
            check_did_detail(&did, 1, 1, 1, next_nonce);

            assert_eq!(PublicKeys::get(&did_1, IncId::from(2u8)), None);
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(did_1, 2u8.into()))
            );
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

            let params = SchemeParams::new(None, vec![5; 100], CurveType::Bls12381);
            let params_1 = SchemeParams::new(None, vec![6; 100], CurveType::Bls12381);

            let key = SchemeKey::new(vec![1; 80], None, CurveType::Bls12381);
            let key_1 = SchemeKey::new(vec![2; 80], None, CurveType::Bls12381);
            let key_2 = SchemeKey::new(vec![3; 80], None, CurveType::Bls12381);

            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_2)),
                IncId::from(0u8)
            );

            run_to_block(35);

            assert!(SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: next_nonce
                },
                SignatureParamsOwner(author)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(PublicKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );

            run_to_block(40);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author.clone(),
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(PublicKeys::get(&author, IncId::from(3u8)), None);

            run_to_block(50);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author.clone(),
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );

            run_to_block(60);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author.clone(),
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(4u8)),
                Some(key_2.clone().into())
            );

            run_to_block(70);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            assert!(SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params_1.clone().into(),
                    nonce: did_detail.next_nonce().unwrap()
                },
                SignatureParamsOwner(author)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author)),
                IncId::from(2u8)
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author, IncId::from(4u8)),
                Some(key_2.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(1u8)),
                Some(params.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author), IncId::from(2u8)),
                Some(params_1.clone().into())
            );

            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_2)),
                IncId::from(0u8)
            );

            run_to_block(80);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone().into())
            );

            run_to_block(90);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            assert!(SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: did_detail_1.next_nonce().unwrap()
                },
                SignatureParamsOwner(author_1)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&SignatureParamsOwner(author_1)),
                IncId::from(1u8)
            );
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                SignatureParams::get(&SignatureParamsOwner(author_1), IncId::from(1u8)),
                Some(params.clone().into())
            );

            run_to_block(100);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::get(&author_1, IncId::from(3u8)),
                Some(key_1.clone().into())
            );
        });
    }

    #[test]
    fn get_params_and_keys() {
        ext().execute_with(|| {
            let (author, _) = newdid();

            let (author_1, _) = newdid();

            let params = SchemeParams::new(None, vec![5; 100], CurveType::Bls12381);
            let params_1 = SchemeParams::new(None, vec![6; 100], CurveType::Bls12381);
            let params_2 = SchemeParams::new(None, vec![7; 100], CurveType::Bls12381);

            let key = SchemeKey::new(vec![1; 80], None, CurveType::Bls12381);
            let key_1 = SchemeKey::new(
                vec![2; 80],
                Some((SignatureParamsOwner(author.clone()), 1u8.into())),
                CurveType::Bls12381,
            );
            let key_2 = SchemeKey::new(
                vec![3; 80],
                Some((SignatureParamsOwner(author_1.clone()), 1u8.into())),
                CurveType::Bls12381,
            );

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author)).count(),
                0
            );
            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author_1)).count(),
                0
            );
            assert_eq!(
                SignatureMod::did_public_key(&author, IncId::from(0u8))
                    .and_then(|key| -> Option<SchemeKey> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                None
            );
            assert_eq!(
                SignatureMod::did_public_key(&author_1, IncId::from(0u8))
                    .and_then(|key| -> Option<SchemeKey> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                None
            );

            SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: 0, // Doesn't matter
                },
                SignatureParamsOwner(author),
            )
            .unwrap();
            SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params_1.clone().into(),
                    nonce: 0, // Doesn't matter
                },
                SignatureParamsOwner(author_1),
            )
            .unwrap();
            SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params_2.clone().into(),
                    nonce: 0, // Doesn't matter
                },
                SignatureParamsOwner(author_1),
            )
            .unwrap();

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author)).collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params.clone().into());
                    m
                }
            );

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author_1)).collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params_1.clone().into());
                    m.insert(2u8.into(), params_2.clone().into());
                    m
                }
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author.clone(),
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(&author, IncId::from(2u8))
                    .and_then(|key| -> Option<SchemeKey> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key.clone().into(), None))
            );

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(&author_1, IncId::from(2u8))
                    .and_then(|key| -> Option<SchemeKey> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key_1.clone().into(), Some(params.clone().into())))
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author.clone(),
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert!(<did::Pallet<Test>>::try_exec_action_over_onchain_did(
                SignatureMod::add_public_key_,
                ak,
            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(&author, IncId::from(3u8))
                    .and_then(|key| -> Option<SchemeKey> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key_2.clone().into(), Some(params_1.clone())))
            );

            assert_eq!(
                SignatureMod::did_public_keys(&Controller(author_1))
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key_1.clone().into(), Some(params.clone())));
                    m
                }
            );

            assert_eq!(
                SignatureMod::did_public_keys(&Controller(author))
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key.clone(), None));
                    m.insert(3u8.into(), (key_2.clone().into(), Some(params_1.into())));
                    m
                }
            );

            SignatureParams::remove(&SignatureParamsOwner(author), IncId::from(1u8));

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author)).count(),
                0
            );

            assert_eq!(
                SignatureMod::did_public_keys(&Controller(author_1))
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key_1.clone().into(), None));
                    m
                }
            );
        });
    }
}