#![allow(clippy::type_complexity)]

use super::{types::*, *};
use crate::{
    did::base::*,
    tests::common::*,
    util::{Action, AddOrRemoveOrModify, Bytes, MultiTargetUpdate, OnlyExistent, SetOrModify},
};
use alloc::collections::{BTreeMap, BTreeSet};
use core::num::NonZeroU32;
use frame_support::{assert_noop, assert_ok};
use rand::{distributions::Alphanumeric, Rng};

type Mod = super::Pallet<Test>;

crate::did_or_did_method_key! {
    newdid =>

    #[test]
    fn init_or_update_trust_registry() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();
            let (other, other_kp) = newdid();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let alice = 1u64;

            let sig = did_sig(
                &init_or_update_trust_registry,
                &convener_kp,
                Convener(convener.into()),
                1,
            );
            let other_did_sig = did_sig(
                &init_or_update_trust_registry,
                &convener_kp,
                Convener(other.into()),
                1,
            );
            let other_kp_sig = did_sig(
                &init_or_update_trust_registry,
                &other_kp,
                Convener(convener.into()),
                1,
            );

            assert_noop!(
                Mod::init_or_update_trust_registry(
                    Origin::signed(alice),
                    init_or_update_trust_registry.clone(),
                    other_did_sig
                ),
                did::Error::<Test>::InvalidSignature
            );
            assert_noop!(
                Mod::init_or_update_trust_registry(
                    Origin::signed(alice),
                    init_or_update_trust_registry.clone(),
                    other_kp_sig
                ),
                did::Error::<Test>::InvalidSignature
            );
            Mod::init_or_update_trust_registry(
                Origin::signed(alice),
                init_or_update_trust_registry.clone(),
                sig,
            )
            .unwrap();

            let init_or_update_trust_registry_already_exists = InitOrUpdateTrustRegistry::<Test> {
                registry_id: init_or_update_trust_registry.registry_id,
                name: (0..10)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let other_did_sig = did_sig(
                &init_or_update_trust_registry_already_exists,
                &other_kp,
                Convener(other.into()),
                1,
            );
            assert_noop!(
                Mod::init_or_update_trust_registry(
                    Origin::signed(alice),
                    init_or_update_trust_registry_already_exists,
                    other_did_sig
                ),
                Error::<Test>::NotTheConvener
            );

            let reinit_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: init_or_update_trust_registry.registry_id,
                name: (0..10)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 3,
            };
            let sig = did_sig(
                &reinit_or_update_trust_registry,
                &convener_kp,
                Convener(convener.into()),
                1,
            );
            assert_ok!(Mod::init_or_update_trust_registry(
                Origin::signed(alice),
                reinit_or_update_trust_registry,
                sig
            ));
        })
    }

    #[test]
    fn suspend_issuers() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();
            let (other, other_kp) = newdid();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let alice = 1u64;

            ActionWrapper::<Test, _, _>::new(
                2,
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .execute::<Test, _, _, _, _>(|action, set| {
                Mod::init_or_update_trust_registry_(action.action, set, Convener(convener.into()))
            })
            .unwrap();

            let schemas: BTreeMap<_, _> = [(
                TrustRegistrySchemaId(rand::random()),
                UnboundedTrustRegistrySchemaMetadata {
                    issuers: UnboundedIssuersWith(
                        [(
                            Issuer(did::DidOrDidMethodKey::Did(Did(rand::random()))),
                            UnboundedVerificationPrices(
                                (0..5)
                                    .map(|_| {
                                        let s = (0..10)
                                            .map(|_| rng.sample(Alphanumeric) as char)
                                            .collect::<String>();

                                        (s, VerificationPrice(random()))
                                    })
                                    .collect()
                            ),
                        )]
                        .into_iter()
                        .collect(),
                    ),
                    verifiers: UnboundedTrustRegistrySchemaVerifiers(
                        (0..5)
                            .map(|_| Verifier(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .collect()
                    ),
                },
            )]
            .into_iter()
            .collect();

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(schemas
                    .clone()
                    .into_iter()
                    .map(|(schema_id, schema_metadata)| {
                        (schema_id, SetOrAddOrRemoveOrModify::Add(schema_metadata.into()))
                    })
                    .collect()),
                nonce: 3,
            };

            add_schema_metadata
                .execute_view(|action, reg| {
                    Mod::set_schemas_metadata_(action, reg, ConvenerOrIssuerOrVerifier(convener.into()))
                })
                .unwrap();

            let suspend_issuers = SuspendIssuers {
                issuers: schemas
                    .values()
                    .next()
                    .unwrap()
                    .issuers
                    .keys()
                    .copied()
                    .chain(once(Issuer(Did(rand::random()).into())))
                    .collect(),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 2u32.into(),
            };
            let sig = did_sig(&suspend_issuers, &convener_kp, convener, 1u32);

            assert_noop!(
                Pallet::<Test>::suspend_issuers(Origin::signed(alice), suspend_issuers, sig),
                Error::<Test>::NoSuchIssuer
            );

            let suspend_issuers = SuspendIssuers {
                issuers: schemas
                    .values()
                    .next()
                    .unwrap()
                    .issuers
                    .keys()
                    .copied()
                    .collect(),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 2u32.into(),
            };
            let sig = did_sig(&suspend_issuers, &other_kp, other, 1u32);

            assert_noop!(
                Pallet::<Test>::suspend_issuers(Origin::signed(alice), suspend_issuers, sig),
                Error::<Test>::NotTheConvener
            );

            let suspend_issuers = SuspendIssuers {
                issuers: schemas
                    .values()
                    .next()
                    .unwrap()
                    .issuers
                    .keys()
                    .copied()
                    .collect(),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 2u32.into(),
            };
            let sig = did_sig(&suspend_issuers, &convener_kp, convener, 1u32);

            assert!(TrustRegistryIssuerConfigurations::<Test>::iter()
                .filter(|(_, issuer, _)| suspend_issuers.issuers.contains(issuer))
                .all(|(_, _, config)| !config.suspended));

            assert_ok!(Pallet::<Test>::suspend_issuers(
                Origin::signed(alice),
                suspend_issuers.clone(),
                sig
            ));

            assert!(TrustRegistryIssuerConfigurations::<Test>::iter()
                .filter(|(_, issuer, _)| suspend_issuers.issuers.contains(issuer))
                .all(|(_, _, config)| config.suspended));
        })
    }

    #[test]
    fn delegate_issuers() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, _convener_kp) = newdid();
            let (other, other_kp) = newdid();
            let (other_1, other_kp_1) = newdid();
            let other_schemas = (0..5)
                .map(|_| TrustRegistrySchemaId(rand::random()))
                .collect::<BTreeSet<_>>();
            let other_1_schemas = (0..5)
                .map(|_| TrustRegistrySchemaId(rand::random()))
                .collect::<BTreeSet<_>>();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let alice = 1u64;

            ActionWrapper::<Test, _, _>::new(
                init_or_update_trust_registry.nonce(),
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .execute::<Test, _, _, _, _>(|action, reg| {
                Mod::init_or_update_trust_registry_(action.action, reg, Convener(convener.into()))
            })
            .unwrap();

            let delegated = UnboundedDelegatedIssuers(
                (0..10)
                    .map(|idx| Issuer(Did([idx; 32]).into()))
                    .collect()
            );
            let update_delegated = UpdateDelegatedIssuers {
                delegated: SetOrModify::Set(delegated.clone()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 2u32.into(),
            };
            let sig = did_sig(&update_delegated, &other_kp, other, 1u32);

            let shared_schemas = (0..5)
                .map(|_| TrustRegistrySchemaId(rand::random()))
                .collect::<BTreeSet<_>>();

            assert_noop!(
                Pallet::<Test>::update_delegated_issuers(
                    Origin::signed(alice),
                    update_delegated.clone(),
                    sig.clone()
                ),
                Error::<Test>::NoSuchIssuer
            );

            TrustRegistryIssuerSchemas::<Test>::insert(
                init_or_update_trust_registry.registry_id,
                Issuer(other.into()),
                IssuerSchemas(
                    shared_schemas.clone().into_iter().chain(
                        other_schemas.clone()
                    ).collect::<BTreeSet<_>>().try_into().unwrap()
                )
            );
            TrustRegistryIssuerSchemas::<Test>::insert(
                init_or_update_trust_registry.registry_id,
                Issuer(other_1.into()),
                IssuerSchemas(
                    shared_schemas.clone().into_iter().chain(
                        other_1_schemas.clone()
                    ).collect::<BTreeSet<_>>().try_into().unwrap()
                )
            );

            assert_eq!(
                TrustRegistryIssuerConfigurations::<Test>::get(
                    init_or_update_trust_registry.registry_id,
                    Issuer(other.into())
                )
                .delegated,
                Default::default()
            );

            assert_eq!(
                TrustRegistryDelegatedIssuerSchemas::<Test>::get(
                    init_or_update_trust_registry.registry_id,
                    Issuer(other.into())
                ),
                DelegatedIssuerSchemas(Default::default())
            );

            assert_ok!(Pallet::<Test>::update_delegated_issuers(
                Origin::signed(alice),
                update_delegated,
                sig
            ),);

            for delegated_issuer in delegated.iter().cloned() {
                assert_eq!(
                    TrustRegistryDelegatedIssuerSchemas::<Test>::get(
                        init_or_update_trust_registry.registry_id,
                        Issuer(delegated_issuer.into())
                    ),
                    DelegatedIssuerSchemas(
                        shared_schemas
                            .clone()
                            .into_iter()
                            .chain(other_schemas.clone())
                            .map(|id| (id, NonZeroU32::new(1).unwrap().into()))
                            .collect::<BTreeMap<_, _>>().try_into().unwrap()
                    )
                );
            }

            let update_delegated = UpdateDelegatedIssuers {
                delegated: SetOrModify::Set(delegated.clone()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 2u32.into(),
            };
            let sig = did_sig(&update_delegated, &other_kp_1, other_1, 1u32);

            assert_ok!(
                Pallet::<Test>::update_delegated_issuers(
                    Origin::signed(alice),
                    update_delegated.clone(),
                    sig.clone()
                )
            );

            for delegated_issuer in delegated.iter().cloned() {
                assert_eq!(
                    TrustRegistryDelegatedIssuerSchemas::<Test>::get(
                        init_or_update_trust_registry.registry_id,
                        Issuer(delegated_issuer.into())
                    ),
                    DelegatedIssuerSchemas(
                        shared_schemas
                            .clone()
                            .into_iter()
                            .map(|id| (id, NonZeroU32::new(2).unwrap().into())
                        ).chain(
                            other_schemas.clone()
                                .into_iter()
                                .chain(other_1_schemas.clone())
                                .map(|id| (id, NonZeroU32::new(1).unwrap().into()))
                        ).collect::<BTreeMap<_, _>>().try_into().unwrap()
                    )
                );
            }

            let update_delegated = UpdateDelegatedIssuers::<Test> {
                delegated: SetOrModify::Set(Default::default()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: 3u32.into(),
            };
            let sig = did_sig(&update_delegated, &other_kp, other, 1u32);

            assert_eq!(
                TrustRegistryIssuerConfigurations::<Test>::get(
                    init_or_update_trust_registry.registry_id,
                    Issuer(other.into())
                )
                .delegated,
                delegated.clone().try_into().unwrap()
            );

            assert_ok!(
                Pallet::<Test>::update_delegated_issuers(
                    Origin::signed(alice),
                    update_delegated.clone(),
                    sig.clone()
                )
            );

            for delegated_issuer in delegated.iter().cloned() {
                assert_eq!(
                    TrustRegistryDelegatedIssuerSchemas::<Test>::get(
                        init_or_update_trust_registry.registry_id,
                        Issuer(delegated_issuer.into())
                    ),
                    DelegatedIssuerSchemas(
                        shared_schemas
                            .clone()
                            .into_iter()
                            .map(|id| (id, NonZeroU32::new(1).unwrap().into()))
                            .chain(
                                other_1_schemas
                                    .clone()
                                    .into_iter()
                                    .map(|id| (id, NonZeroU32::new(1).unwrap().into()))
                            ).collect::<BTreeMap<_, _>>().try_into().unwrap()
                    )
                );
            }

            assert_eq!(
                TrustRegistryIssuerConfigurations::<Test>::get(
                    init_or_update_trust_registry.registry_id,
                    Issuer(other.into())
                )
                .delegated,
                Default::default()
            );
            assert_eq!(
                TrustRegistryIssuerConfigurations::<Test>::get(
                    init_or_update_trust_registry.registry_id,
                    Issuer(other_1.into())
                )
                .delegated,
                delegated.clone().try_into().unwrap()
            );
        })
    }

    #[test]
    fn add_schemas_metadata() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();
            let (other, other_kp) = newdid();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let sig = did_sig(
                &init_or_update_trust_registry,
                &convener_kp,
                Convener(convener.into()),
                1,
            );
            let alice = 1u64;

            Mod::init_or_update_trust_registry(
                Origin::signed(alice),
                init_or_update_trust_registry.clone(),
                sig,
            )
            .unwrap();

            let schemas: BTreeMap<_, _> = [(
                TrustRegistrySchemaId(rand::random()),
                UnboundedTrustRegistrySchemaMetadata {
                    issuers: UnboundedIssuersWith(
                        [(
                            Issuer(did::DidOrDidMethodKey::Did(Did(rand::random()))),
                            UnboundedVerificationPrices(
                                (0..5)
                                    .map(|_| {
                                        let s = (0..10)
                                            .map(|_| rng.sample(Alphanumeric) as char)
                                            .collect::<String>();

                                        (s, VerificationPrice(random()))
                                    })
                                    .collect()
                            ),
                        )]
                        .into_iter()
                        .collect()
                    ),
                    verifiers: UnboundedTrustRegistrySchemaVerifiers(
                        (0..5)
                            .map(|_| Verifier(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .collect()
                    ),
                },
            )]
            .into_iter()
            .collect();

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(schemas
                    .clone()
                    .into_iter()
                    .map(|(schema_id, schema_metadata)| {
                        (schema_id, SetOrAddOrRemoveOrModify::Add(schema_metadata.into()))
                    })
                    .collect()),
                nonce: 3,
            };
            let sig = did_sig(
                &add_schema_metadata,
                &convener_kp,
                Convener(convener.into()),
                1,
            );

            Mod::set_schemas_metadata(Origin::signed(alice), add_schema_metadata.clone(), sig).unwrap();

            assert_eq!(
                TrustRegistrySchemasMetadata::get(
                    add_schema_metadata.schemas.clone().unwrap_modify().keys().next().unwrap(),
                    init_or_update_trust_registry.registry_id
                ),
                add_schema_metadata
                    .schemas
                    .clone()
                    .unwrap_modify()
                    .values()
                    .map(|value| match value {
                        SetOrAddOrRemoveOrModify::Add(value) => TrustRegistrySchemaMetadata::<Test>::try_from(value.clone()).unwrap(),
                        _ => unreachable!(),
                    })
                    .next()
            );

            let add_other_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: add_schema_metadata.schemas.clone(),
                nonce: 2,
            };

            let other_sig = did_sig(
                &add_other_schema_metadata,
                &other_kp,
                Convener(other.into()),
                1,
            );

            assert_noop!(
                Mod::set_schemas_metadata(Origin::signed(alice), add_other_schema_metadata, other_sig).map_err(|e| e.error),
                Error::<Test>::SenderCantApplyThisUpdate
            );

            let add_other_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: add_schema_metadata.schemas.clone(),
                nonce: 4,
            };

            let sig = did_sig(
                &add_other_schema_metadata,
                &convener_kp,
                Convener(convener.into()),
                1,
            );

            assert_noop!(
                Mod::set_schemas_metadata(Origin::signed(alice), add_other_schema_metadata, sig).map_err(|e| e.error),
                Error::<Test>::EntityAlreadyExists
            );
        })
    }

    #[test]
    fn set_schemas_metadata() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();
            let (verifier, _) = newdid();
            let (issuer, _) = newdid();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: 2,
            };
            let sig = did_sig(
                &init_or_update_trust_registry,
                &convener_kp,
                Convener(convener.into()),
                1,
            );
            let alice = 1u64;

            Mod::init_or_update_trust_registry(
                Origin::signed(alice),
                init_or_update_trust_registry.clone(),
                sig,
            )
            .unwrap();

            let build_initial_prices = |count, sym_length| {
                UnboundedVerificationPrices(
                    (0..count)
                        .map(|_| (0..sym_length).map(|_| random::<u8>() as char).collect::<String>())
                        .chain(vec!["A", "B", "C", "D"].into_iter().map(|v| v.to_string()))
                        .map(|symbol| (symbol, VerificationPrice(random())))
                        .collect::<BTreeMap<_, _>>()
                )
            };

            let schema_ids: Vec<_> = (0..5)
                .map(|_| rand::random())
                .map(TrustRegistrySchemaId)
                .collect();

            let mut schemas: BTreeMap<_, _> = schema_ids
                .iter()
                .copied()
                .zip(0..)
                .map(|(id, idx)| {
                    let issuers = UnboundedIssuersWith(
                        (0..5)
                            .map(|_| Issuer(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .chain((idx == 0).then_some(Issuer(issuer.into())))
                            .map(|issuer| (issuer, build_initial_prices(5, 5)))
                            .collect::<BTreeMap<_, _>>()
                    );
                    let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                        (0..5)
                            .map(|_| Verifier(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .chain((idx == 0).then_some(Verifier(verifier.into())))
                            .collect::<BTreeSet<_>>()
                    );

                    (id, UnboundedTrustRegistrySchemaMetadata { issuers, verifiers })
                })
                .collect();

            let initial_schemas = schemas.clone();
            let second_fourth_schemas = BTreeMap::from_iter([(schema_ids[2], schemas.get(&schema_ids[2]).cloned().unwrap()), (schema_ids[4], schemas.get(&schema_ids[4]).cloned().unwrap())]);

            let mut too_large_schemas = schema_ids
                .iter()
                .copied()
                .zip(0..4)
                .map(|(id, idx)| {
                    let issuers = UnboundedIssuersWith(
                        (0..if idx == 0 { 50 } else { 5 })
                            .map(|_| Issuer(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .chain((idx == 0).then_some(Issuer(issuer.into())))
                            .map(|issuer| (issuer, build_initial_prices(if idx == 2 { 100 } else { 5 }, if idx == 3 { 100 } else { 5 })))
                            .collect::<BTreeMap<_, _>>()
                    );
                    let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                        (0..if idx == 1 { 50 } else { 5 })
                            .map(|_| Verifier(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                            .chain((idx == 0).then_some(Verifier(verifier.into())))
                            .collect::<BTreeSet<_>>()
                    );

                    (id, UnboundedTrustRegistrySchemaMetadata { issuers, verifiers })
                });

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(schemas
                    .clone()
                    .into_iter()
                    .map(|(schema_id, schema_metadata)| {
                        (schema_id, SetOrAddOrRemoveOrModify::Add(schema_metadata.into()))
                    })
                    .collect()),
                nonce: 3,
            };
            let sig = did_sig(
                &add_schema_metadata,
                &convener_kp,
                Convener(convener.into()),
                1,
            );
            let random_did = Did(rand::random());
            let new_schema_id = TrustRegistrySchemaId([123; 32]);

            Mod::set_schemas_metadata(Origin::signed(alice), add_schema_metadata, sig).unwrap();

            let cases = [
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        UnboundedSchemaMetadataModification::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(issuer.into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter([
                                                (
                                                    "W".to_string(),
                                                    SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                                ),
                                                (
                                                    "A".to_string(),
                                                    SetOrAddOrRemoveOrModify::Remove,
                                                ),
                                                (
                                                    "C".to_string(),
                                                    SetOrAddOrRemoveOrModify::Set(VerificationPrice(400)),
                                                ),
                                                (
                                                    "EF".to_string(),
                                                    SetOrAddOrRemoveOrModify::Set(VerificationPrice(500)),
                                                ),
                                            ]),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(verifier.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(issuer.into()),
                                )
                            }));

                            let schema = schemas.get_mut(&schema_ids[0]).unwrap();
                            let issuer = schema.issuers.get_mut(&Issuer(issuer.into())).unwrap();
                            issuer
                                .try_add("W".to_string(), VerificationPrice(100))
                                .unwrap();
                            issuer
                                .remove(&"A".to_string())
                                .unwrap();
                            issuer
                                .try_add("C".to_string(), VerificationPrice(400))
                                .unwrap();
                            issuer
                                .try_add("EF".to_string(), VerificationPrice(500))
                                .unwrap();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(Did(rand::random()).into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter([(
                                                "W".to_string(),
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                            )]),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(verifier.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(Did(rand::random()).into()),
                                        SetOrAddOrRemoveOrModify::Set(UnboundedVerificationPrices(
                                            [(
                                                "W".to_string(),
                                                VerificationPrice(100),
                                            )]
                                            .into_iter()
                                            .collect()
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(verifier.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                        },
                    )
                        as Box<
                            dyn FnOnce(
                                SetSchemasMetadata<Test>,
                                &mut BTreeMap<TrustRegistrySchemaId, UnboundedTrustRegistrySchemaMetadata>,
                            ),
                        >,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(
                                            (*schemas
                                                .get(&schema_ids[0])
                                                .unwrap()
                                                .issuers
                                                .keys()
                                                .nth(2)
                                                .unwrap())
                                            .into(),
                                        ),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter([(
                                                "EC".to_string(),
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(600)),
                                            )]),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }),);

                            let schema = schemas.get_mut(&schema_ids[0]).unwrap();
                            let key = *schema.issuers.keys().nth(2).unwrap();
                            let issuer = schema.issuers.get_mut(&key).unwrap();
                            issuer
                                .try_add("EC".to_string(), VerificationPrice(600))
                                .unwrap();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(random_did.into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter([(
                                                "W".to_string(),
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                            )]),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(random_did.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::EntityDoesntExist
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![
                        (
                            schema_ids[0],
                            SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                UnboundedTrustRegistrySchemaMetadataUpdate {
                                    issuers: Some(UnboundedIssuersUpdate::Modify(
                                        MultiTargetUpdate::from_iter([(
                                            Issuer(issuer.into()),
                                            SetOrAddOrRemoveOrModify::Set(UnboundedVerificationPrices(
                                                [(
                                                    "A".to_string(),
                                                    VerificationPrice(800),
                                                )]
                                                .into_iter()
                                                .collect()

                                            )),
                                        )]),
                                    )),
                                    verifiers: None,
                                },
                            )),
                        ),
                        (
                            schema_ids[1],
                            SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                UnboundedTrustRegistrySchemaMetadataUpdate {
                                    issuers: Some(UnboundedIssuersUpdate::Modify(
                                        MultiTargetUpdate::from_iter([(
                                            Issuer(
                                                (*schemas
                                                    .get(&schema_ids[1])
                                                    .unwrap()
                                                    .issuers
                                                    .keys()
                                                    .nth(3)
                                                    .unwrap())
                                                .into(),
                                            ),
                                            SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                                MultiTargetUpdate::from_iter([(
                                                    "W".to_string(),
                                                    SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                                )]),
                                            )),
                                        )]),
                                    )),
                                    verifiers: None,
                                },
                            )),
                        ),
                    ])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            let schema_1 = schemas.get_mut(&schema_ids[1]).unwrap();
                            let issuer_3 = (*schema_1.issuers.keys().nth(3).unwrap()).into();
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer_3),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }),);

                            schema_1
                                .issuers
                                .get_mut(&Issuer(issuer_3))
                                .unwrap()
                                .try_add("W".to_string(), VerificationPrice(100))
                                .unwrap();

                            let _ = schema_1;

                            let schema_0 = schemas.get_mut(&schema_ids[0]).unwrap();
                            let issuer =
                                schema_0.issuers.get_mut(&Issuer(issuer.into())).unwrap();
                            *issuer = Default::default();
                            issuer
                                .try_add("A".to_string(), VerificationPrice(800))
                                .unwrap();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(Did(rand::random()).into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter([(
                                                "W".to_string(),
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                            )]),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(verifier.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(issuer.into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter((0..20).map(|idx| {
                                                (
                                                    idx.to_string(),
                                                    SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                                )
                                            })),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(issuer.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::TooManyEntities
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter((0..50).map(|idx| {
                                        (
                                            Issuer(Did([idx as u8; 32]).into()),
                                            SetOrAddOrRemoveOrModify::Set(
                                                (0..15)
                                                    .map(|p_idx| {
                                                        (
                                                            (0..10)
                                                                .map(|idx| {
                                                                    (98 + idx + p_idx) as u8 as char
                                                                })
                                                                .collect::<String>()
                                                                .try_into()
                                                                .unwrap(),
                                                            VerificationPrice(1000),
                                                        )
                                                    })
                                                    .collect::<BTreeMap<_, _>>()
                                                    .try_into()
                                                    .unwrap(),
                                            ),
                                        )
                                    })),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.execute_view(|action, reg| Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into())
                                )).map_err(DispatchError::from),
                                Error::<Test>::TooManyEntities
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: Some(UnboundedIssuersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Issuer(issuer.into()),
                                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                                            MultiTargetUpdate::from_iter((0..19).map(|idx| {
                                                (
                                                    idx.to_string(),
                                                    SetOrAddOrRemoveOrModify::Add(VerificationPrice(100)),
                                                )
                                            })),
                                        )),
                                    )]),
                                )),
                                verifiers: None,
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_ok!(update.execute_view(|action, registry| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    registry,
                                    ConvenerOrIssuerOrVerifier(issuer.into()),
                                )
                            }));

                            let schema_0 = schemas.get_mut(&schema_ids[0]).unwrap();
                            let issuer =
                                schema_0.issuers.get_mut(&Issuer(issuer.into())).unwrap();

                            for (key, price) in (0..19)
                                .map(|idx| (idx.to_string(), VerificationPrice(100)))
                            {
                                issuer.try_add(key, price).unwrap();
                            }
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: None,
                                verifiers: UnboundedVerifiersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Verifier(verifier.into()),
                                        AddOrRemoveOrModify::Remove,
                                    )]),
                                )
                                .into(),
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(verifier.into()),
                                )
                            }));

                            let schema = schemas.get_mut(&schema_ids[0]).unwrap();
                            schema.verifiers.remove(&Verifier(verifier.into()));
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: None,
                                verifiers: UnboundedVerifiersUpdate::Modify(
                                    MultiTargetUpdate::from_iter([(
                                        Verifier(issuer.into()),
                                        AddOrRemoveOrModify::Add(()),
                                    )]),
                                )
                                .into(),
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(verifier.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            let schema = schemas.get_mut(&schema_ids[0]).unwrap();
                            schema
                                .verifiers
                                .try_add(Verifier(issuer.into()), ())
                                .unwrap();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Modify(OnlyExistent(
                            UnboundedTrustRegistrySchemaMetadataUpdate {
                                issuers: None,
                                verifiers: UnboundedVerifiersUpdate::Set(
                                    Default::default(),
                                )
                                .into(),
                            },
                        )),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            let schema = schemas.get_mut(&schema_ids[0]).unwrap();
                            *schema.verifiers = Default::default();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Add(UnboundedTrustRegistrySchemaMetadata {
                            issuers: Default::default(),
                            verifiers: Default::default(),
                        }),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::EntityAlreadyExists
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![
                        (schema_ids[4], SetOrAddOrRemoveOrModify::Remove),
                        (
                            new_schema_id,
                            SetOrAddOrRemoveOrModify::Add(
                                schemas.get(&schema_ids[3]).cloned().unwrap().into(),
                            ),
                        ),
                    ])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            let new_schema = schemas.get(&schema_ids[3]).cloned().unwrap();

                            schemas.remove(&schema_ids[4]);
                            schemas.insert(new_schema_id, new_schema);
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(schema_ids[0], SetOrAddOrRemoveOrModify::Remove)])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.clone().execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            schemas.remove(&schema_ids[0]);
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Add(schemas.get(&schema_ids[2]).cloned().unwrap().into()),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            let new_schema = schemas.get(&schema_ids[2]).cloned().unwrap();

                            schemas.insert(schema_ids[0].clone(), new_schema);
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(second_fourth_schemas.clone())),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            *schemas = second_fourth_schemas;
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(Default::default())),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            *schemas = Default::default();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(initial_schemas.clone())),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into()),
                                    )
                                }).map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.execute_view(|action, reg| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    reg,
                                    ConvenerOrIssuerOrVerifier(convener.into()),
                                )
                            }));

                            *schemas = initial_schemas.clone();
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(too_large_schemas.next()))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into()),
                                    )
                                }),
                                StepError::Conversion(Error::<Test>::IssuersSizeExceeded.into())
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(too_large_schemas.next()))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into()),
                                    )
                                }),
                                StepError::Conversion(Error::<Test>::VerifiersSizeExceeded.into())
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(too_large_schemas.next()))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into()),
                                    )
                                }),
                                StepError::Conversion(Error::<Test>::VerificationPricesSizeExceeded.into())
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(too_large_schemas.next()))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                        _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update.clone().execute_view(|action, reg| {
                                    Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into()),
                                    )
                                }),
                                StepError::Conversion(Error::<Test>::PriceCurrencySymbolSizeExceeded.into())
                            );
                        },
                    ) as _,
                ),
            ];

            for (line, updates, execute) in cases {
                let update = SetSchemasMetadata {
                    registry_id: init_or_update_trust_registry.registry_id,
                    schemas: updates,
                    nonce: 2,
                };

                execute(update, &mut schemas);

                assert_eq!(
                    Schemas::<Test>::try_from(UnboundedSchemas(schemas.clone())).unwrap(),
                    Schemas::<Test>(
                        TrustRegistrySchemasMetadata::iter()
                            .map(|(schema_id, _, value)| (schema_id, value))
                            .collect::<BTreeMap<_, _>>()
                            .try_into()
                            .unwrap()
                    ),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas.keys().cloned().collect::<BTreeSet<_>>(),
                    TrustRegistriesStoredSchemas::<Test>::get(init_or_update_trust_registry.registry_id).0.into(),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas
                        .iter()
                        .flat_map(|(id, schema)| schema
                            .verifiers
                            .iter()
                            .copied()
                            .map(|verifier| (*id, verifier)))
                        .collect::<BTreeSet<_>>(),
                    TrustRegistryVerifierSchemas::<Test>::iter()
                        .flat_map(|(_, verifier, schemas)| schemas
                            .0
                            .into_iter()
                            .map(move |schema_id| (schema_id, verifier)))
                        .collect(),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas
                        .iter()
                        .flat_map(|(id, schema)| schema
                            .issuers
                            .keys()
                            .copied()
                            .map(|issuer| (*id, issuer)))
                        .collect::<BTreeSet<_>>(),
                    TrustRegistryIssuerSchemas::<Test>::iter()
                        .flat_map(|(_, issuer, schemas)| schemas
                            .0
                            .into_iter()
                            .map(move |schema_id| (schema_id, issuer)))
                        .collect(),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas
                        .iter()
                        .flat_map(|(_id, schema)|
                            schema
                                .issuers
                                .keys()
                                .copied()
                        )
                        .collect::<BTreeSet<_>>(),
                    IssuersTrustRegistries::<Test>::iter()
                        .filter(|(_, set)| !set.is_empty())
                        .map(|(issuer, _)| issuer)
                        .collect(),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas
                        .iter()
                        .flat_map(|(_id, schema)|
                            schema
                                .verifiers
                                .keys()
                                .copied()
                        )
                        .collect::<BTreeSet<_>>(),
                    VerifiersTrustRegistries::<Test>::iter()
                        .filter(|(_, set)| !set.is_empty())
                        .map(|(verifier, _)| verifier)
                        .collect(),
                    "Failed test on line {:?}",
                    line
                );
            }
        })
    }
}
