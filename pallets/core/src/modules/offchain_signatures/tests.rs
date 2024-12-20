use super::*;
use crate::{
    common::CurveType,
    did::{base::*, tests::check_did_detail, AddControllers},
    offchain_signatures,
    tests::common::*,
    util::{Action, ActionWithNonce, BoundedBytes},
};
use alloc::collections::BTreeMap;
use frame_support::assert_err;
use sp_core::H256;
use sp_runtime::traits::CheckedConversion;

macro_rules! with_each_scheme {
    ($key: ident, $params: ident $($tt: tt)+) => {
        mod bbs {
            use super::*;
            use BBSPublicKey as $key;
            use BBSParameters as $params;

            $($tt)+
        }

        mod bbs_plus {
            use super::*;
            use BBSPlusPublicKey as $key;
            use BBSPlusParameters as $params;

            $($tt)+
        }

        mod ps {
            use super::*;
            use PSPublicKey as $key;
            use PSParameters as $params;

            $($tt)+
        }

        mod bbdt16 {
            use super::*;
            use BBDT16PublicKey as $key;
            use BBDT16Parameters as $params;

            $($tt)+
        }
    }
}

fn sig_events() -> Vec<super::Event> {
    System::events()
        .iter()
        .filter_map(|event_record| {
            let frame_system::EventRecord::<TestEvent, H256> {
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

    crate::did_or_did_method_key! {
        newdidordidmethodkey =>

        #[test]
        fn add_remove_params() {
            ext().execute_with(|| {
                run_to_block(5);

                let (author, author_kp) = newdidordidmethodkey();
                let mut next_nonce = 1;
                check_nonce(&author, next_nonce - 1);

                run_to_block(6);

                let (author_1, author_1_kp) = newdidordidmethodkey();
                let mut next_nonce_1 = 1;
                check_nonce(&author_1, next_nonce_1 - 1);

                run_to_block(10);

                assert!(vec![1u8; 600].try_into().map(|params_bytes| SchemeParams::<Test>::new(BoundedBytes::try_from(vec![0, 1, 2, 3]).unwrap(), params_bytes, CurveType::Bls12381)).is_err());

                check_nonce(&author, next_nonce - 1);

                run_to_block(15);

                let params = SchemeParams::<Test>::new(BoundedBytes::try_from(vec![0, 1, 2, 3]).unwrap(), vec![1u8; 500].try_into().unwrap(), CurveType::Bls12381);

                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(0u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    None
                );
                assert!(
                    !sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                        SignatureParamsOwner(author.into()),
                        1u8.into()
                    ))
                );
                check_nonce(&author, next_nonce - 1);

                run_to_block(20);

                let ap = AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: next_nonce,
                };
                let sig = did_sig(&ap, &author_kp, SignatureParamsOwner(author.into()), 1);
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
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(1u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    Some(params.clone().into())
                );

                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                        SignatureParamsOwner(author.into()),
                        1u8.into()
                    ))
                );

                run_to_block(21);

                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(2u8)),
                    None
                );
                let params_1 = SchemeParams::<Test>::new(None, vec![1u8; 100].try_into().unwrap(), CurveType::Bls12381);
                let ap = AddOffchainSignatureParams {
                    params: params_1.clone().into(),
                    nonce: next_nonce,
                };
                let sig = did_sig(&ap, &author_kp, SignatureParamsOwner(author.into()), 1);
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
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(2u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(2u8)),
                    Some(params_1.into())
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                        SignatureParamsOwner(author.into()),
                        2u8.into()
                    ))
                );

                run_to_block(25);

                let params_2 =
                    SchemeParams::<Test>::new(BoundedBytes::try_from(vec![0, 9, 1]).unwrap(), vec![9u8; 100].try_into().unwrap(), CurveType::Bls12381);
                let ap = AddOffchainSignatureParams {
                    params: params_2.clone().into(),
                    nonce: next_nonce_1,
                };
                let sig = did_sig(&ap, &author_1_kp, SignatureParamsOwner(author_1.into()), 1);
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                    IncId::from(0u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author_1.into()), IncId::from(1u8)),
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
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                    IncId::from(1u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author_1.into()), IncId::from(1u8)),
                    Some(params_2.clone().into())
                );
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(2u8)
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                        SignatureParamsOwner(author_1.into()),
                        1u8.into()
                    ))
                );

                run_to_block(30);

                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                    None
                );
                let params_3 = SchemeParams::<Test>::new(None, vec![8u8; 100].try_into().unwrap(), CurveType::Bls12381);
                let ap = AddOffchainSignatureParams {
                    params: params_3.clone().into(),
                    nonce: next_nonce,
                };
                let sig = did_sig(&ap, &author_kp, SignatureParamsOwner(author.into()), 1);
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
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(3u8)
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                    Some(params_3.clone().into())
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsAdded(
                        SignatureParamsOwner(author.into()),
                        3u8.into()
                    ))
                );

                let rf = (SignatureParamsOwner(author.into()), 5u8.into());
                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce,
                };
                let sig = did_sig(&rp, &author_kp, SignatureParamsOwner(author.into()), 1);
                assert_err!(
                    SignatureMod::remove_params(Origin::signed(1), rp, sig),
                    Error::<Test>::ParamsDontExist
                );
                check_nonce(&author, next_nonce - 1);

                let rf = (SignatureParamsOwner(author.into()), 2u8.into());
                let mut rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce_1,
                };

                let sig = did_sig(&rp, &author_1_kp, SignatureParamsOwner(author_1.into()), 1);
                assert_err!(
                    SignatureMod::remove_params(Origin::signed(1), rp.clone(), sig),
                    Error::<Test>::NotOwner
                );
                check_nonce(&author_1, next_nonce_1 - 1);

                rp.nonce = next_nonce;
                let sig = did_sig(&rp, &author_kp, SignatureParamsOwner(author.into()), 1);
                SignatureMod::remove_params(Origin::signed(1), rp, sig).unwrap();
                check_nonce(&author, next_nonce);
                next_nonce += 1;
                // Counter doesn't go back
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(3u8)
                );
                // Entry gone from storage
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(2u8)),
                    None
                );
                // Other entries remain as it is
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                    Some(params_3.clone().into())
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    Some(params.clone().into())
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author_1.into()), IncId::from(1u8)),
                    Some(params_2.into())
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                        SignatureParamsOwner(author.into()),
                        2u8.into()
                    ))
                );

                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce,
                };
                let sig = did_sig(&rp, &author_kp, SignatureParamsOwner(author.into()), 1);
                // Cannot remove as already removed
                assert_err!(
                    SignatureMod::remove_params(
                        Origin::signed(1),
                        RemoveOffchainSignatureParams {
                            params_ref: rf,
                            nonce: next_nonce
                        },
                        sig
                    ),
                    Error::<Test>::ParamsDontExist
                );
                check_nonce(&author, next_nonce - 1);

                let rf = (SignatureParamsOwner(author_1.into()), 1u8.into());
                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce_1,
                };
                let sig = did_sig(&rp, &author_1_kp, SignatureParamsOwner(author_1.into()), 1);
                SignatureMod::remove_params(Origin::signed(1), rp, sig).unwrap();
                check_nonce(&author_1, next_nonce_1);
                next_nonce_1 += 1;
                // Counter doesn't go back
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                    IncId::from(1u8)
                );
                // Entry gone from storage
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author_1.into()), IncId::from(1u8)),
                    None
                );
                // Other entries remain as it is
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                    Some(params_3.into())
                );
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    Some(params.clone().into())
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                        SignatureParamsOwner(author_1.into()),
                        1u8.into()
                    ))
                );

                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce_1,
                };
                let sig = did_sig(&rp, &author_1_kp, SignatureParamsOwner(author_1.into()), 1);
                // Cannot remove as already removed
                assert_err!(
                    SignatureMod::remove_params(
                        Origin::signed(1),
                        RemoveOffchainSignatureParams {
                            params_ref: rf,
                            nonce: next_nonce_1
                        },
                        sig
                    ),
                    Error::<Test>::ParamsDontExist
                );
                check_nonce(&author_1, next_nonce_1 - 1);

                let rf = (SignatureParamsOwner(author.into()), 3u8.into());
                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce,
                };
                let sig = did_sig(&rp, &author_kp, SignatureParamsOwner(author.into()), 1);
                SignatureMod::remove_params(Origin::signed(1), rp, sig).unwrap();
                check_nonce(&author, next_nonce);
                next_nonce += 1;
                // Counter doesn't go back
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(3u8)
                );
                // Entry gone from storage
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                    None
                );
                // Other entries remain as it is
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    Some(params.into())
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                        SignatureParamsOwner(author.into()),
                        3u8.into()
                    ))
                );

                let rf = (SignatureParamsOwner(author.into()), 1u8.into());
                let rp = RemoveOffchainSignatureParams::<Test> {
                    params_ref: rf,
                    nonce: next_nonce,
                };
                let sig = did_sig(&rp, &author_kp, SignatureParamsOwner(author.into()), 1);
                SignatureMod::remove_params(Origin::signed(1), rp, sig).unwrap();
                check_nonce(&author, next_nonce);
                // Counter doesn't go back
                assert_eq!(
                    ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                    IncId::from(3u8)
                );
                // Entry gone from storage
                assert_eq!(
                    SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                    None
                );
                assert!(
                    sig_events().contains(&offchain_signatures::Event::ParamsRemoved(
                        SignatureParamsOwner(author.into()),
                        1u8.into()
                    ))
                );
            });
        }

        #[test]
        fn add_remove_public_key_by_controller() {
            ext().execute_with(|| {
                run_to_block(10);

                let (did, did_kp) = newdidordidmethodkey();
                let mut next_nonce = 1;
                check_did_detail(&did, 1, 1, 1, next_nonce - 1);

                run_to_block(20);

                let (did_1, did_1_kp) = newdid();
                let mut next_nonce_1 = 1;
                check_nonce(&did_1, next_nonce_1 - 1);
                check_did_detail(&did_1, 1, 1, 1, next_nonce_1 - 1);

                // Make `did` controller of `did`
                let add_controllers = AddControllers {
                    did: did_1,
                    controllers: vec![did].into_iter().map(Into::into).map(Controller).collect(),
                    nonce: next_nonce_1,
                };
                let sig = did_sig(&add_controllers, &did_1_kp, Controller(did_1.into()), 1);
                DIDModule::add_controllers(Origin::signed(1), add_controllers, sig).unwrap();
                assert!(DIDModule::is_controller(&did_1, &Controller(did.into())));
                check_did_detail(&did_1, 1, 1, 2, next_nonce_1);
                check_did_detail(&did, 1, 1, 1, next_nonce - 1);
                next_nonce_1 += 1;

                let key = SchemeKey::new(vec![8u8; 100].try_into().unwrap(), None, CurveType::Bls12381);
                let ak = AddOffchainSignaturePublicKey {
                    key: key.clone().into(),
                    did: did_1,
                    nonce: next_nonce,
                };
                let sig = did_sig(&ak, &did_kp, Controller(did.into()), 1);
                SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();

                check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
                check_did_detail(&did, 1, 1, 1, next_nonce);

                next_nonce += 1;

                assert_eq!(
                    PublicKeys::<Test>::get(did_1, IncId::from(2u8)),
                    Some(key.into())
                );
                if let DidOrDidMethodKey::Did(did) = did.into() {
                    assert_eq!(PublicKeys::<Test>::get(did, IncId::from(2u8)), None);
                }
                assert!(
                    sig_events().contains(&offchain_signatures::Event::KeyAdded(did_1, 2u8.into()))
                );

                let rf = (did_1, 2u8.into());
                let rk = RemoveOffchainSignaturePublicKey {
                    key_ref: rf,
                    did: did_1,
                    nonce: next_nonce,
                };
                let sig = did_sig(&rk, &did_kp, Controller(did.into()), 1);
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig).unwrap();

                check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
                check_did_detail(&did, 1, 1, 1, next_nonce);

                assert_eq!(PublicKeys::<Test>::get(did_1, IncId::from(2u8)), None);
                assert!(
                    sig_events().contains(&offchain_signatures::Event::KeyRemoved(did_1, 2u8.into()))
                );
            })
        }
    }

    #[test]
    fn add_remove_public_key() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let mut next_nonce = 1;
            check_nonce(&author, next_nonce - 1);

            run_to_block(15);

            assert!(vec![1u8; 200].try_into().map(|bytes| SchemeKey::<Test>::new(bytes, None, CurveType::Bls12381)).is_err());

            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert!(
                !sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(30);

            let key = SchemeKey::new(vec![1u8; 100].try_into().unwrap(), None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author,
                nonce: next_nonce,
            };

            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(1u8)), None);
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(2u8)), None);
            assert!(
                !sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(35);

            let sig = did_sig(&ak, &author_kp, Controller(author.into()), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(1u8)), None);
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 2u8.into()))
            );

            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(3u8)), None);
            let key_1 = SchemeKey::new(vec![1u8; 100].try_into().unwrap(), None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&ak, &author_kp, Controller(author.into()), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(3u8)),
                Some(key_1.into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 3u8.into()))
            );

            run_to_block(45);

            let (author_1, author_kp_1) = newdid();
            let mut next_nonce_1 = 1;

            run_to_block(50);

            let key_2 = SchemeKey::new(vec![9u8; 100].try_into().unwrap(), None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&ak, &author_kp_1, Controller(author_1.into()), 1);
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            assert_eq!(PublicKeys::<Test>::get(author_1, IncId::from(1u8)), None);
            assert_eq!(PublicKeys::<Test>::get(author_1, IncId::from(2u8)), None);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(2u8)),
                Some(key_2.clone().into())
            );
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author_1, 2u8.into()))
            );

            run_to_block(55);

            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(3u8)),
                None
            );
            let key_3 = SchemeKey::new(vec![8u8; 100].try_into().unwrap(), None, CurveType::Bls12381);
            let ak = AddOffchainSignaturePublicKey {
                key: key_3.clone().into(),
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&ak, &author_kp, Controller(author.into()), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(4u8)),
                Some(key_3.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 3u8.into()))
            );

            run_to_block(60);

            let rf = (author, 5u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&rk, &author_kp, Controller(author.into()), 1);
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (author, 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rk, &author_kp_1, Controller(author_1.into()), 1);
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig),
                Error::<Test>::NotOwner
            );

            let rf = (author, 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&rk, &author_kp, Controller(author.into()), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(3u8)), None);
            // Other entries remain as it is
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(4u8)),
                Some(key_3.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(2u8)),
                Some(key_2.into())
            );

            let rf = (author, 3u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&rk, &author_kp, Controller(author.into()), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(70);

            let rf = (author_1, 2u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rk, &author_kp_1, Controller(author_1.into()), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::<Test>::get(author_1, IncId::from(2u8)), None);
            // Other entries remain as it is
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(4u8)),
                Some(key_3.into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
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
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&rk, &author_kp_1, Controller(author_1.into()), 1);
            // Cannot remove as already removed
            assert_err!(
                SignatureMod::remove_public_key(Origin::signed(1), rk, sig),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rf = (author, 4u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&rk, &author_kp, Controller(author.into()), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(4u8)), None);
            // Other entries remain as it is
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(2u8)), Some(key.into()));
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(author, 4u8.into()))
            );

            let rf = (author, 2u8.into());
            let rk = RemoveOffchainSignaturePublicKey {
                key_ref: rf,
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&rk, &author_kp, Controller(author.into()), 1);
            SignatureMod::remove_public_key(Origin::signed(1), rk, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(2u8)), None);
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyRemoved(author, 2u8.into()))
            );

            run_to_block(80);

            let params =
                SchemeParams::<Test>::new(BoundedBytes::try_from(vec![0, 1, 2, 3]).unwrap(), vec![19; 100].try_into().unwrap(), CurveType::Bls12381);
            let ap = AddOffchainSignatureParams {
                params: params.clone().into(),
                nonce: next_nonce,
            };
            let sig = did_sig(&ap, &author_kp, SignatureParamsOwner(author.into()), 1);
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
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(1u8)
            );
            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                Some(params.into())
            );

            // Add key with reference to non-existent params
            let key_4 = SchemeKey::new(
                vec![92u8; 100].try_into().unwrap(),
                Some((SignatureParamsOwner(author.into()), 4u8.into())),
                CurveType::Bls12381,
            );
            let ak = AddOffchainSignaturePublicKey {
                key: key_4.into(),
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&ak, &author_kp_1, Controller(author_1.into()), 1);
            assert_err!(
                SignatureMod::add_public_key(Origin::signed(1), ak, sig),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );

            // Add key with reference to existent params
            let key_4 = SchemeKey::new(
                vec![92u8; 100].try_into().unwrap(),
                Some((SignatureParamsOwner(author.into()), 1u8.into())),
                CurveType::Bls12381,
            );
            let ak = AddOffchainSignaturePublicKey {
                key: key_4.clone().into(),
                did: author_1,
                nonce: next_nonce_1,
            };
            let sig = did_sig(&ak, &author_kp_1, Controller(author_1.into()), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author_1, next_nonce_1);
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(3u8)),
                Some(key_4.clone().into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author_1, 3u8.into()))
            );

            let ak = AddOffchainSignaturePublicKey {
                key: key_4.clone().into(),
                did: author,
                nonce: next_nonce,
            };
            let sig = did_sig(&ak, &author_kp, Controller(author.into()), 1);
            SignatureMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(1u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(5u8)),
                Some(key_4.into())
            );
            assert!(
                sig_events().contains(&offchain_signatures::Event::KeyAdded(author, 5u8.into()))
            );
        });
    }

    #[test]
    fn add_params_keys() {
        ext().execute_with(|| {
            run_to_block(10);
            let (author, _) = newdid();
            let next_nonce = 1;

            run_to_block(20);
            let (author_1, _) = newdid();

            run_to_block(30);
            let (author_2, _) = newdid();

            let params = SchemeParams::<Test>::new(None, vec![5; 100].try_into().unwrap(), CurveType::Bls12381);
            let params_1 = SchemeParams::<Test>::new(None, vec![6; 100].try_into().unwrap(), CurveType::Bls12381);

            let key = SchemeKey::new(vec![1; 80].try_into().unwrap(), None, CurveType::Bls12381);
            let key_1 = SchemeKey::new(vec![2; 80].try_into().unwrap(), None, CurveType::Bls12381);
            let key_2 = SchemeKey::new(vec![3; 80].try_into().unwrap(), None, CurveType::Bls12381);

            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_2.into())),
                IncId::from(0u8)
            );

            run_to_block(35);

            ParamsCounter::<Test>::mutate(SignatureParamsOwner(author.into()), |counter| assert!(SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: next_nonce
                },
                counter,
                SignatureParamsOwner(author.into())
            )
            .is_ok()));
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(1u8)
            );
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(1u8)), None);
            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                Some(params.clone().into())
            );

            run_to_block(40);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author,
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap())
            )
            .is_ok());
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(PublicKeys::<Test>::get(author, IncId::from(3u8)), None);

            run_to_block(50);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author,
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );

            run_to_block(60);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author,
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(4u8)),
                Some(key_2.clone().into())
            );

            run_to_block(70);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            ActionWithNonceWrapper::<Test, _, _>::new(0, SignatureParamsOwner(author.into()),  AddOffchainSignatureParams {
                params: params_1.clone().into(),
                nonce: did_detail.next_nonce().unwrap()
            }).modify::<Test, _, _, _, _>(
                |action, counter| SignatureMod::add_params_(action.action, counter, SignatureParamsOwner(author.into()))
            )
            .unwrap();
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author.into())),
                IncId::from(2u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(3u8)),
                Some(key_1.clone().into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author, IncId::from(4u8)),
                Some(key_2.into())
            );
            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(1u8)),
                Some(params.clone().into())
            );
            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author.into()), IncId::from(2u8)),
                Some(params_1.into())
            );

            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_2.into())),
                IncId::from(0u8)
            );

            run_to_block(80);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author_1,
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(2u8)),
                Some(key.clone().into())
            );

            run_to_block(90);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            ParamsCounter::<Test>::mutate(SignatureParamsOwner(author_1.into()), |counter| assert!(SignatureMod::add_params_(
                AddOffchainSignatureParams {
                    params: params.clone().into(),
                    nonce: did_detail_1.next_nonce().unwrap()
                },
                counter,
                SignatureParamsOwner(author_1.into())
            )
            .is_ok()));
            assert_eq!(
                ParamsCounter::<Test>::get(SignatureParamsOwner(author_1.into())),
                IncId::from(1u8)
            );
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(2u8)),
                Some(key.clone().into())
            );
            assert_eq!(
                SignatureParams::<Test>::get(SignatureParamsOwner(author_1.into()), IncId::from(1u8)),
                Some(params.into())
            );

            run_to_block(100);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author_1,
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(2u8)),
                Some(key.into())
            );
            assert_eq!(
                PublicKeys::<Test>::get(author_1, IncId::from(3u8)),
                Some(key_1.into())
            );
        });
    }

    #[test]
    fn get_params_and_keys() {
        ext().execute_with(|| {
            let (author, _) = newdid();

            let (author_1, _) = newdid();

            let params = SchemeParams::<Test>::new(None, vec![5; 100].try_into().unwrap(), CurveType::Bls12381);
            let params_1 = SchemeParams::<Test>::new(None, vec![6; 100].try_into().unwrap(), CurveType::Bls12381);
            let params_2 = SchemeParams::<Test>::new(None, vec![7; 100].try_into().unwrap(), CurveType::Bls12381);

            let key = SchemeKey::new(vec![1; 80].try_into().unwrap(), None, CurveType::Bls12381);
            let key_1 = SchemeKey::new(
                vec![2; 80].try_into().unwrap(),
                Some((SignatureParamsOwner(author.into()), 1u8.into())),
                CurveType::Bls12381,
            );
            let key_2 = SchemeKey::new(
                vec![3; 80].try_into().unwrap(),
                Some((SignatureParamsOwner(author_1.into()), 1u8.into())),
                CurveType::Bls12381,
            );

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author.into())).count(),
                0
            );
            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author_1.into())).count(),
                0
            );
            assert_eq!(
                SignatureMod::did_public_key(author, IncId::from(0u8))
                    .and_then(|key| -> Option<SchemeKey<Test>> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                None
            );
            assert_eq!(
                SignatureMod::did_public_key(author_1, IncId::from(0u8))
                    .and_then(|key| -> Option<SchemeKey<Test>> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                None
            );

            ActionWithNonceWrapper::<Test, _, _>::new(0, SignatureParamsOwner(author.into()), AddOffchainSignatureParams {
                params: params.clone().into(),
                nonce: 0, // Doesn't matter
            }).modify::<Test, _, _, _, _>(
                |action, counter| SignatureMod::add_params_(action.action, counter, SignatureParamsOwner(author.into()))
            )
            .unwrap();
            ActionWithNonceWrapper::<Test, _, _>::new(0, SignatureParamsOwner(author_1.into()), AddOffchainSignatureParams {
                params: params_1.clone().into(),
                nonce: 0, // Doesn't matter
            }).modify::<Test, _, _, _, _>(
                |action, counter| SignatureMod::add_params_(action.action, counter, SignatureParamsOwner(author_1.into()))
            ).unwrap();

            ActionWithNonceWrapper::<Test, _, _>::new(0, SignatureParamsOwner(author_1.into()), AddOffchainSignatureParams {
                params: params_2.clone().into(),
                nonce: 0, // Doesn't matter
            }).modify::<Test, _, _, _, _>(
                |action, counter| SignatureMod::add_params_(action.action, counter, SignatureParamsOwner(author_1.into()))
            ).unwrap();

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author.into())).collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params.clone().into());
                    m
                }
            );

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author_1.into())).collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params_1.clone().into());
                    m.insert(2u8.into(), params_2.into());
                    m
                }
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key.clone().into(),
                did: author,
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(author, IncId::from(2u8))
                    .and_then(|key| -> Option<SchemeKey<Test>> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key.clone(), None))
            );

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_1.clone().into(),
                did: author_1,
                nonce: did_detail_1.next_nonce().unwrap(),
            };
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(author_1, IncId::from(2u8))
                    .and_then(|key| -> Option<SchemeKey<Test>> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key_1.clone(), Some(params.clone())))
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddOffchainSignaturePublicKey {
                key: key_2.clone().into(),
                did: author,
                nonce: did_detail.next_nonce().unwrap(),
            };
            assert!(ak.execute_and_increase_nonce(
                |action, details| SignatureMod::add_public_key_(action, details.as_mut().unwrap()),

            )
            .is_ok());
            assert_eq!(
                SignatureMod::did_public_key(author, IncId::from(3u8))
                    .and_then(|key| -> Option<SchemeKey<Test>> { key.try_into().ok() })
                    .map(SchemeKey::with_params),
                Some((key_2.clone(), Some(params_1.clone())))
            );

            assert_eq!(
                SignatureMod::did_public_keys(&author_1)
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey<Test>>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key_1.clone(), Some(params)));
                    m
                }
            );

            assert_eq!(
                SignatureMod::did_public_keys(&author)
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey<Test>>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key, None));
                    m.insert(3u8.into(), (key_2, Some(params_1)));
                    m
                }
            );

            SignatureParams::<Test>::remove(SignatureParamsOwner(author.into()), IncId::from(1u8));

            assert_eq!(
                SignatureMod::did_params(&SignatureParamsOwner(author.into())).count(),
                0
            );

            assert_eq!(
                SignatureMod::did_public_keys(&author_1)
                    .map(|(idx, key)| (idx, key.checked_into::<SchemeKey<Test>>().unwrap().with_params()))
                    .collect::<BTreeMap<_, _>>(),
                {
                    let mut m = BTreeMap::new();
                    m.insert(2u8.into(), (key_1, None));
                    m
                }
            );
        });
    }
}
