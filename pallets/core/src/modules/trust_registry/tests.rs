#![allow(clippy::type_complexity)]

use super::{types::*, *};
use crate::{
    common::{SigValue, SignatureWithNonce},
    did::base::*,
    tests::common::*,
    util::{
        Action, ActionWithNonceWrapper, AddOrRemoveOrModify, Bytes, IncOrDec, MultiTargetUpdate,
        OnlyExistent, SetOrModify, SingleTargetUpdate, WithNonce,
    },
};
use alloc::collections::{BTreeMap, BTreeSet};
use core::num::NonZeroU32;
use frame_support::{assert_noop, assert_ok};
use itertools::Itertools;
use rand::{distributions::Alphanumeric, Rng};
use sp_runtime::DispatchError;

type Mod = super::Pallet<Test>;

fn change_participants<P: sp_core::Pair>(
    registry_id: TrustRegistryId,
    participants: impl IntoIterator<Item = (impl Into<DidOrDidMethodKey>, P, AddOrRemoveOrModify<()>)>,
    convener_with_kp: impl Into<Option<(DidOrDidMethodKey, P)>>,
) -> DispatchResult
where
    P::Signature: Into<SigValue>,
{
    let alice = 1u64;
    let (parts, part_keys, changes): (Vec<_>, Vec<_>, Vec<_>) = participants
        .into_iter()
        .map(|(did, key, change)| (did.into(), key, change))
        .multiunzip();

    let payload = ChangeParticipantsRaw {
        registry_id: TrustRegistryIdForParticipants(registry_id),
        participants: parts
            .iter()
            .zip(changes)
            .map(|(participant, change)| (IssuerOrVerifier(*participant), change))
            .collect(),
        _marker: PhantomData,
    };

    let sigs = parts
        .into_iter()
        .zip(part_keys)
        .chain(convener_with_kp.into())
        .map(|(signer, key)| {
            let nonce = did_nonce::<Test, _>(signer).unwrap();

            let sig = did_sig(
                &WithNonce::new_with_nonce(payload.clone(), nonce),
                &key,
                ConvenerOrIssuerOrVerifier(signer),
                1,
            );

            SignatureWithNonce::new(sig, nonce)
        })
        .collect();

    Mod::change_participants(Origin::signed(alice), payload, sigs)
}

fn add_participants<P: sp_core::Pair>(
    registry_id: TrustRegistryId,
    participants: impl IntoIterator<Item = (impl Into<DidOrDidMethodKey>, P)>,
    convener_with_kp: impl Into<Option<(DidOrDidMethodKey, P)>>,
) -> DispatchResult
where
    P::Signature: Into<SigValue>,
{
    change_participants(
        registry_id,
        participants
            .into_iter()
            .map(|(did, kp)| (did, kp, AddOrRemoveOrModify::Add(()))),
        convener_with_kp,
    )
}

fn set_participant_information<P: sp_core::Pair>(
    payload: SetParticipantInformationRaw<Test>,
    participant: impl Into<Option<(IssuerOrVerifier, P)>>,
    convener: impl Into<Option<(Convener, P)>>,
) -> DispatchResult
where
    P::Signature: Into<SigValue>,
{
    let participant = participant.into();
    let convener = convener.into();

    let sigs = participant
        .into_iter()
        .map(|(participant, key)| (*participant, key))
        .chain(convener.map(|(did, key)| (*did, key)))
        .into_iter()
        .map(|(signer, key)| {
            let nonce = did_nonce::<Test, _>(signer).unwrap();

            let sig = did_sig(
                &WithNonce::new_with_nonce(payload.clone(), nonce),
                &key,
                ConvenerOrIssuerOrVerifier(signer),
                1,
            );

            SignatureWithNonce::new(sig, nonce)
        })
        .collect();

    Mod::set_participant_information(Origin::signed(1u64), payload, sigs)
}

fn build_initial_prices(count: usize, sym_length: usize) -> UnboundedVerificationPrices {
    UnboundedVerificationPrices(
        (0..count)
            .map(|_| {
                (0..sym_length)
                    .map(|_| random::<u8>() as char)
                    .collect::<String>()
            })
            .chain(vec!["A", "B", "C", "D"].into_iter().map(str::to_string))
            .map(|symbol| (symbol, VerificationPrice(random())))
            .collect(),
    )
}

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
                nonce: did_nonce::<Test, _>(convener).unwrap(),
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
                nonce: did_nonce::<Test, _>(Convener(other.into())).unwrap(),
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
                nonce: did_nonce::<Test, _>(Convener(convener.into())).unwrap(),
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

            ActionWithNonceWrapper::<Test, _, _>::new(
                2,
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .modify::<Test, _, _, _, _>(|action, set| {
                action.action.modify_removable(|action, info| {
                    Mod::init_or_update_trust_registry_(
                        action,
                        set,
                        info,
                        Convener(convener.into()),
                    )
                })
            })
            .unwrap();

            let schema_ids_set: BTreeSet<_> = (0..5)
                .map(|_| rand::random())
                .map(TrustRegistrySchemaId)
                .collect();
            let schema_ids: Vec<_> = schema_ids_set.into_iter().collect();

            let schema_issuers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();
            let schema_verifiers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();

            let schemas: BTreeMap<_, _> = schema_ids
                .iter()
                .copied()
                .zip(0..)
                .zip(schema_verifiers.values())
                .zip(schema_issuers.values())
                .map(|(((id, _), verifiers), issuers)| {
                    let issuers = UnboundedIssuersWith(
                        issuers
                            .iter()
                            .map(|(did, _)| Issuer((*did).into()))
                            .map(|issuer| (issuer, build_initial_prices(5, 5)))
                            .collect(),
                    );
                    let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                        verifiers
                            .iter()
                            .map(|(did, _)| Verifier((*did).into()))
                            .collect(),
                    );

                    (
                        id,
                        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers },
                    )
                })
                .collect();

            add_participants(
                init_or_update_trust_registry.registry_id,
                schema_issuers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone())),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();
            add_participants(
                init_or_update_trust_registry.registry_id,
                schema_verifiers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone())),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(
                    schemas
                        .clone()
                        .into_iter()
                        .map(|(schema_id, schema_metadata)| {
                            (
                                schema_id,
                                SetOrAddOrRemoveOrModify::Add(schema_metadata.into()),
                            )
                        })
                        .collect(),
                ),
                nonce: 3,
            };

            add_schema_metadata
                .view(|action, reg| {
                    Mod::set_schemas_metadata_(
                        action,
                        reg,
                        ConvenerOrIssuerOrVerifier(convener.into()),
                    )
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
                nonce: did_nonce::<Test, _>(convener).unwrap(),
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
                nonce: did_nonce::<Test, _>(other).unwrap(),
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
                nonce: did_nonce::<Test, _>(convener).unwrap(),
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

            let (convener, convener_kp) = newdid();
            let (other, other_kp) = newdid();
            let (other_1, other_kp_1) = newdid();
            let other_schemas = (0..5)
                .map(|_| TrustRegistrySchemaId(rand::random()))
                .collect::<BTreeSet<_>>();
            let other_1_schemas = (0..5)
                .map(|_| TrustRegistrySchemaId(rand::random()))
                .collect::<BTreeSet<_>>();

            let raw_delegated: Vec<_> = (0..10).map(|_| newdid()).collect();

            let delegated = UnboundedDelegatedIssuers(
                raw_delegated
                    .iter()
                    .map(|(did, _)| Issuer((*did).into()))
                    .collect(),
            );

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: did_nonce::<Test, _>(convener).unwrap(),
            };
            let alice = 1u64;

            ActionWithNonceWrapper::<Test, _, _>::new(
                init_or_update_trust_registry.nonce(),
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .modify::<Test, _, _, _, _>(|action, set| {
                action.action.modify_removable(|action, info| {
                    Mod::init_or_update_trust_registry_(
                        action,
                        set,
                        info,
                        Convener(convener.into()),
                    )
                })
            })
            .unwrap();

            add_participants(
                init_or_update_trust_registry.registry_id,
                raw_delegated
                    .iter()
                    .map(|(did, pair)| (did.clone(), pair.clone())),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();

            let update_delegated = UpdateDelegatedIssuers {
                delegated: SetOrModify::Set(delegated.clone()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: did_nonce::<Test, _>(other).unwrap(),
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
                    shared_schemas
                        .clone()
                        .into_iter()
                        .chain(other_schemas.clone())
                        .collect::<BTreeSet<_>>()
                        .try_into()
                        .unwrap(),
                ),
            );
            TrustRegistryIssuerSchemas::<Test>::insert(
                init_or_update_trust_registry.registry_id,
                Issuer(other_1.into()),
                IssuerSchemas(
                    shared_schemas
                        .clone()
                        .into_iter()
                        .chain(other_1_schemas.clone())
                        .collect::<BTreeSet<_>>()
                        .try_into()
                        .unwrap(),
                ),
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
                            .collect::<BTreeMap<_, _>>()
                            .try_into()
                            .unwrap()
                    )
                );
            }

            let update_delegated = UpdateDelegatedIssuers {
                delegated: SetOrModify::Set(delegated.clone()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: did_nonce::<Test, _>(other_1).unwrap(),
            };
            let sig = did_sig(&update_delegated, &other_kp_1, other_1, 1u32);

            assert_ok!(Pallet::<Test>::update_delegated_issuers(
                Origin::signed(alice),
                update_delegated.clone(),
                sig.clone()
            ));

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
                            .map(|id| (id, NonZeroU32::new(2).unwrap().into()))
                            .chain(
                                other_schemas
                                    .clone()
                                    .into_iter()
                                    .chain(other_1_schemas.clone())
                                    .map(|id| (id, NonZeroU32::new(1).unwrap().into()))
                            )
                            .collect::<BTreeMap<_, _>>()
                            .try_into()
                            .unwrap()
                    )
                );
            }

            let update_delegated = UpdateDelegatedIssuers::<Test> {
                delegated: SetOrModify::Set(Default::default()),
                registry_id: init_or_update_trust_registry.registry_id,
                nonce: did_nonce::<Test, _>(other).unwrap(),
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

            assert_ok!(Pallet::<Test>::update_delegated_issuers(
                Origin::signed(alice),
                update_delegated.clone(),
                sig.clone()
            ));

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
                            )
                            .collect::<BTreeMap<_, _>>()
                            .try_into()
                            .unwrap()
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
    fn add_and_remove_participants() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();

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

            ActionWithNonceWrapper::<Test, _, _>::new(
                2,
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .modify::<Test, _, _, _, _>(|action, set| {
                action.action.modify_removable(|action, info| {
                    Mod::init_or_update_trust_registry_(
                        action,
                        set,
                        info,
                        Convener(convener.into()),
                    )
                })
            })
            .unwrap();

            let participants: Vec<_> = (0..10).map(|_| newdid()).collect();
            let (invalid_convener, invalid_convener_kp) = newdid();

            assert_noop!(
                Mod::change_participants(
                    Origin::signed(1u64),
                    ChangeParticipantsRaw {
                        registry_id: TrustRegistryIdForParticipants(
                            init_or_update_trust_registry.registry_id
                        ),
                        participants: participants
                            .iter()
                            .map(|(participant, _)| (
                                IssuerOrVerifier((*participant).into()),
                                AddOrRemoveOrModify::Add(())
                            ))
                            .collect(),
                        _marker: PhantomData
                    },
                    vec![]
                ),
                did::Error::<Test>::NotEnoughSignatures
            );
            let random_kp = newdid().1;

            assert_noop!(
                add_participants(
                    init_or_update_trust_registry.registry_id,
                    participants.iter().map(|(p, _)| (*p, random_kp.clone())),
                    (DidOrDidMethodKey::from(convener), convener_kp.clone())
                ),
                did::Error::<Test>::InvalidSignature
            );
            assert_noop!(
                add_participants(
                    init_or_update_trust_registry.registry_id,
                    participants.clone(),
                    (
                        DidOrDidMethodKey::from(invalid_convener),
                        invalid_convener_kp.clone()
                    )
                ),
                did::Error::<Test>::NotEnoughSignatures
            );

            assert_eq!(
                TrustRegistriesParticipants::<Test>::get(TrustRegistryIdForParticipants(
                    init_or_update_trust_registry.registry_id
                )),
                Default::default()
            );

            assert_ok!(add_participants(
                init_or_update_trust_registry.registry_id,
                participants.clone(),
                (DidOrDidMethodKey::from(convener), convener_kp.clone())
            ));
            assert_eq!(
                TrustRegistriesParticipants::<Test>::get(TrustRegistryIdForParticipants(
                    init_or_update_trust_registry.registry_id
                )),
                TrustRegistryStoredParticipants(
                    participants
                        .iter()
                        .map(|(did, _)| IssuerOrVerifier((*did).into()))
                        .collect::<BTreeSet<_>>()
                        .try_into()
                        .unwrap()
                )
            );

            assert_noop!(
                Mod::change_participants(
                    Origin::signed(1u64),
                    ChangeParticipantsRaw {
                        registry_id: TrustRegistryIdForParticipants(
                            init_or_update_trust_registry.registry_id
                        ),
                        participants: participants
                            .iter()
                            .map(|(participant, _)| (
                                IssuerOrVerifier((*participant).into()),
                                AddOrRemoveOrModify::Remove
                            ))
                            .collect(),
                        _marker: PhantomData
                    },
                    vec![]
                ),
                did::Error::<Test>::NotEnoughSignatures
            );
            assert_noop!(
                change_participants(
                    init_or_update_trust_registry.registry_id,
                    participants.iter().map(|(p, _)| (
                        *p,
                        random_kp.clone(),
                        AddOrRemoveOrModify::Remove
                    )),
                    (DidOrDidMethodKey::from(convener), convener_kp.clone())
                ),
                did::Error::<Test>::InvalidSignature
            );

            // Participants can remove themselves without involving the convener
            assert_ok!(change_participants(
                init_or_update_trust_registry.registry_id,
                participants.clone().into_iter().map(|(did, kp)| (
                    did,
                    kp,
                    AddOrRemoveOrModify::Remove
                )),
                None
            ));
            assert_eq!(
                TrustRegistriesParticipants::<Test>::get(TrustRegistryIdForParticipants(
                    init_or_update_trust_registry.registry_id
                )),
                Default::default()
            );
        });
    }

    #[test]
    fn set_participant_information_test() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();

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

            ActionWithNonceWrapper::<Test, _, _>::new(
                2,
                Convener(convener.into()),
                init_or_update_trust_registry.clone(),
            )
            .modify::<Test, _, _, _, _>(|action, set| {
                action.action.modify_removable(|action, info| {
                    Mod::init_or_update_trust_registry_(
                        action,
                        set,
                        info,
                        Convener(convener.into()),
                    )
                })
            })
            .unwrap();

            let participants: Vec<_> = (0..10)
                .map(|_| newdid())
                .map(|(did, key)| (IssuerOrVerifier(did.into()), key))
                .collect();
            let (invalid_convener, invalid_convener_kp) = newdid();
            let registry_id =
                TrustRegistryIdForParticipants(init_or_update_trust_registry.registry_id);

            assert_noop!(
                Mod::change_participants(
                    Origin::signed(1u64),
                    ChangeParticipantsRaw {
                        registry_id,
                        participants: participants
                            .iter()
                            .map(|(participant, _)| (*participant, AddOrRemoveOrModify::Add(())))
                            .collect(),
                        _marker: PhantomData
                    },
                    vec![]
                ),
                did::Error::<Test>::NotEnoughSignatures
            );
            let random_kp = newdid().1;

            let participant_information = UnboundedTrustRegistryParticipantInformation {
                org_name: "ORG NAME".to_string(),
                logo: "LOGO".to_string(),
                description: "DESCRIPTION".to_string(),
            };

            let payload = SetParticipantInformationRaw {
                participant_information: participant_information.clone(),
                participant: participants[0].0,
                registry_id: TrustRegistryIdForParticipants(
                    init_or_update_trust_registry.registry_id,
                ),
                _marker: PhantomData,
            };

            assert_eq!(
                Pallet::<Test>::registry_participant_information(registry_id, participants[0].0),
                None
            );

            assert_noop!(
                set_participant_information(
                    payload.clone(),
                    participants[0].clone(),
                    (Convener(convener.into()), convener_kp.clone())
                ),
                Error::<Test>::NotAParticipant
            );
            assert_ok!(add_participants(
                init_or_update_trust_registry.registry_id,
                participants.clone(),
                (DidOrDidMethodKey::from(convener), convener_kp.clone())
            ));

            assert_noop!(
                set_participant_information(payload.clone(), participants[0].clone(), None),
                did::Error::<Test>::NotEnoughSignatures
            );
            assert_noop!(
                set_participant_information(
                    payload.clone(),
                    None,
                    (Convener(convener.into()), convener_kp.clone())
                ),
                did::Error::<Test>::NotEnoughSignatures
            );
            assert_noop!(
                set_participant_information(
                    payload.clone(),
                    None,
                    (Convener(convener.into()), random_kp)
                ),
                did::Error::<Test>::InvalidSignature
            );

            assert_ok!(set_participant_information(
                payload.clone(),
                participants[0].clone(),
                (Convener(convener.into()), convener_kp)
            ));
            assert_eq!(
                Pallet::<Test>::registry_participant_information(registry_id, participants[0].0),
                Some(participant_information.try_into().unwrap())
            );
        });
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
                nonce: did_nonce::<Test, _>(convener).unwrap(),
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

            let schema_ids_set: BTreeSet<_> = (0..5)
                .map(|_| rand::random())
                .map(TrustRegistrySchemaId)
                .collect();
            let schema_ids: Vec<_> = schema_ids_set.into_iter().collect();

            let schema_issuers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();
            let schema_verifiers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();

            add_participants(
                init_or_update_trust_registry.registry_id,
                schema_issuers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone())),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();
            add_participants(
                init_or_update_trust_registry.registry_id,
                schema_verifiers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone())),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();

            let schemas: BTreeMap<_, _> = schema_ids
                .iter()
                .copied()
                .zip(0..)
                .zip(schema_verifiers.values())
                .zip(schema_issuers.values())
                .map(|(((id, _), verifiers), issuers)| {
                    let issuers = UnboundedIssuersWith(
                        issuers
                            .iter()
                            .map(|(did, _)| Issuer((*did).into()))
                            .map(|issuer| (issuer, build_initial_prices(5, 5)))
                            .collect(),
                    );
                    let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                        verifiers
                            .iter()
                            .map(|(did, _)| Verifier((*did).into()))
                            .collect(),
                    );

                    (
                        id,
                        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers },
                    )
                })
                .collect();

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(
                    schemas
                        .clone()
                        .into_iter()
                        .map(|(schema_id, schema_metadata)| {
                            (
                                schema_id,
                                SetOrAddOrRemoveOrModify::Add(schema_metadata.into()),
                            )
                        })
                        .collect(),
                ),
                nonce: did_nonce::<Test, _>(convener).unwrap(),
            };
            let sig = did_sig(
                &add_schema_metadata,
                &convener_kp,
                Convener(convener.into()),
                1,
            );

            Mod::set_schemas_metadata(Origin::signed(alice), add_schema_metadata.clone(), sig)
                .unwrap();

            assert_eq!(
                TrustRegistrySchemasMetadata::get(
                    add_schema_metadata
                        .schemas
                        .clone()
                        .unwrap_modify()
                        .keys()
                        .next()
                        .unwrap(),
                    init_or_update_trust_registry.registry_id
                ),
                add_schema_metadata
                    .schemas
                    .clone()
                    .unwrap_modify()
                    .values()
                    .map(|value| match value {
                        SetOrAddOrRemoveOrModify::Add(value) =>
                            TrustRegistrySchemaMetadata::<Test>::try_from(value.clone()).unwrap(),
                        _ => unreachable!(),
                    })
                    .next()
            );

            let add_other_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: add_schema_metadata.schemas.clone(),
                nonce: did_nonce::<Test, _>(Convener(other.into())).unwrap(),
            };

            let other_sig = did_sig(
                &add_other_schema_metadata,
                &other_kp,
                Convener(other.into()),
                1,
            );

            assert_noop!(
                Mod::set_schemas_metadata(
                    Origin::signed(alice),
                    add_other_schema_metadata,
                    other_sig
                )
                .map_err(|e| e.error),
                Error::<Test>::SenderCantApplyThisUpdate
            );

            let add_other_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: add_schema_metadata.schemas.clone(),
                nonce: did_nonce::<Test, _>(convener).unwrap(),
            };

            let sig = did_sig(
                &add_other_schema_metadata,
                &convener_kp,
                Convener(convener.into()),
                1,
            );

            assert_noop!(
                Mod::set_schemas_metadata(Origin::signed(alice), add_other_schema_metadata, sig)
                    .map_err(|e| e.error),
                Error::<Test>::EntityAlreadyExists
            );
        })
    }

    #[test]
    fn set_schemas_metadata() {
        ext().execute_with(|| {
            let mut rng = rand::thread_rng();

            let (convener, convener_kp) = newdid();
            let (verifier, verifier_kp) = newdid();
            let (issuer, issuer_kp) = newdid();

            let init_or_update_trust_registry = InitOrUpdateTrustRegistry::<Test> {
                registry_id: TrustRegistryId(rand::random()),
                name: (0..25)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
                    .try_into()
                    .unwrap(),
                gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
                nonce: did_nonce::<Test, _>(Convener(convener.into())).unwrap(),
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

            let schema_ids_set: BTreeSet<_> = (0..5)
                .map(|_| rand::random())
                .map(TrustRegistrySchemaId)
                .collect();
            let schema_ids: Vec<_> = schema_ids_set.into_iter().collect();

            let initial_schemas_issuers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();
            let initial_schemas_verifiers: BTreeMap<_, Vec<_>> = schema_ids
                .iter()
                .copied()
                .map(|schema_id| (schema_id, (0..5).map(|_| newdid()).collect()))
                .collect();

            add_participants(
                init_or_update_trust_registry.registry_id,
                initial_schemas_issuers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone()))
                    .chain(once((issuer, issuer_kp.clone()))),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();
            add_participants(
                init_or_update_trust_registry.registry_id,
                initial_schemas_verifiers
                    .values()
                    .flatten()
                    .map(|(did, pair)| (did.clone(), pair.clone()))
                    .chain(once((verifier, verifier_kp.clone()))),
                (DidOrDidMethodKey::from(convener), convener_kp.clone()),
            )
            .unwrap();

            let mut schemas: BTreeMap<_, _> = schema_ids
                .iter()
                .copied()
                .zip(0..)
                .zip(initial_schemas_verifiers.values())
                .zip(initial_schemas_issuers.values())
                .map(|(((id, idx), verifiers), issuers)| {
                    let issuers = UnboundedIssuersWith(
                        issuers
                            .iter()
                            .map(|(did, _)| Issuer((*did).into()))
                            .chain((idx == 0).then_some(Issuer(issuer.into())))
                            .map(|issuer| (issuer, build_initial_prices(5, 5)))
                            .collect(),
                    );
                    let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                        verifiers
                            .iter()
                            .map(|(did, _)| Verifier((*did).into()))
                            .chain((idx == 0).then_some(Verifier(verifier.into())))
                            .collect(),
                    );

                    (
                        id,
                        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers },
                    )
                })
                .collect();

            let initial_schemas = schemas.clone();
            let second_fourth_schemas = BTreeMap::from_iter([
                (schema_ids[2], schemas.get(&schema_ids[2]).cloned().unwrap()),
                (schema_ids[4], schemas.get(&schema_ids[4]).cloned().unwrap()),
            ]);

            let mut too_large_schemas = schema_ids.iter().copied().zip(0..4).map(|(id, idx)| {
                let issuers = UnboundedIssuersWith(
                    (0..if idx == 0 { 50 } else { 5 })
                        .map(|_| Issuer(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                        .chain((idx == 0).then_some(Issuer(issuer.into())))
                        .map(|issuer| {
                            (
                                issuer,
                                build_initial_prices(
                                    if idx == 2 { 100 } else { 5 },
                                    if idx == 3 { 100 } else { 5 },
                                ),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                );
                let verifiers = UnboundedTrustRegistrySchemaVerifiers(
                    (0..if idx == 1 { 50 } else { 5 })
                        .map(|_| Verifier(did::DidOrDidMethodKey::Did(Did(rand::random()))))
                        .chain((idx == 0).then_some(Verifier(verifier.into())))
                        .collect::<BTreeSet<_>>(),
                );

                (
                    id,
                    UnboundedTrustRegistrySchemaMetadata { issuers, verifiers },
                )
            });

            let add_schema_metadata = SetSchemasMetadata {
                registry_id: init_or_update_trust_registry.registry_id,
                schemas: SetOrModify::Modify(
                    schemas
                        .clone()
                        .into_iter()
                        .map(|(schema_id, schema_metadata)| {
                            (
                                schema_id,
                                SetOrAddOrRemoveOrModify::Add(schema_metadata.into()),
                            )
                        })
                        .collect(),
                ),
                nonce: did_nonce::<Test, _>(convener).unwrap(),
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

            for (_schema_id, issuers) in initial_schemas_issuers {
                for (issuer, kp) in issuers {
                    let raw_delegated: Vec<_> = (0..10).map(|_| newdid()).collect();

                    let delegated = UnboundedDelegatedIssuers(
                        raw_delegated
                            .iter()
                            .map(|(did, _)| Issuer((*did).into()))
                            .collect(),
                    );

                    add_participants(
                        init_or_update_trust_registry.registry_id,
                        raw_delegated
                            .iter()
                            .map(|(did, pair)| (did.clone(), pair.clone())),
                        (DidOrDidMethodKey::from(convener), convener_kp.clone()),
                    )
                    .unwrap();

                    let update_delegated = UpdateDelegatedIssuers {
                        delegated: SetOrModify::Set(delegated.clone()),
                        registry_id: init_or_update_trust_registry.registry_id,
                        nonce: did_nonce::<Test, _>(issuer).unwrap(),
                    };
                    let sig = did_sig(&update_delegated, &kp, issuer, 1u32);

                    assert_ok!(Pallet::<Test>::update_delegated_issuers(
                        Origin::signed(alice),
                        update_delegated,
                        sig
                    ));
                }
            }

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
                                                    SetOrAddOrRemoveOrModify::Add(
                                                        VerificationPrice(100),
                                                    ),
                                                ),
                                                ("A".to_string(), SetOrAddOrRemoveOrModify::Remove),
                                                (
                                                    "C".to_string(),
                                                    SetOrAddOrRemoveOrModify::Set(
                                                        VerificationPrice(400),
                                                    ),
                                                ),
                                                (
                                                    "EF".to_string(),
                                                    SetOrAddOrRemoveOrModify::Set(
                                                        VerificationPrice(500),
                                                    ),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(verifier.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                            issuer.remove(&"A".to_string()).unwrap();
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
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(
                                                    100,
                                                )),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(verifier.into())
                                    ))
                                    .map_err(DispatchError::from),
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
                                            [("W".to_string(), VerificationPrice(100))]
                                                .into_iter()
                                                .collect(),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(verifier.into())
                                    ))
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                        },
                    )
                        as Box<
                            dyn FnOnce(
                                SetSchemasMetadata<Test>,
                                &mut BTreeMap<
                                    TrustRegistrySchemaId,
                                    UnboundedTrustRegistrySchemaMetadata,
                                >,
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
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(
                                                    600,
                                                )),
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
                            assert_ok!(update.view(|action, reg| {
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
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(
                                                    100,
                                                )),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(random_did.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into())
                                    ))
                                    .map_err(DispatchError::from),
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
                                            SetOrAddOrRemoveOrModify::Set(
                                                UnboundedVerificationPrices(
                                                    [("A".to_string(), VerificationPrice(800))]
                                                        .into_iter()
                                                        .collect(),
                                                ),
                                            ),
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
                                                    SetOrAddOrRemoveOrModify::Add(
                                                        VerificationPrice(100),
                                                    ),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            let schema_1 = schemas.get_mut(&schema_ids[1]).unwrap();
                            let issuer_3 = (*schema_1.issuers.keys().nth(3).unwrap()).into();
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer_3),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                            let issuer = schema_0.issuers.get_mut(&Issuer(issuer.into())).unwrap();
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
                                                SetOrAddOrRemoveOrModify::Add(VerificationPrice(
                                                    100,
                                                )),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_noop!(
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(verifier.into())
                                    ))
                                    .map_err(DispatchError::from),
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
                                                    SetOrAddOrRemoveOrModify::Add(
                                                        VerificationPrice(100),
                                                    ),
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
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(issuer.into())
                                    ))
                                    .map_err(DispatchError::from),
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
                                update
                                    .view(|action, reg| Mod::set_schemas_metadata_(
                                        action,
                                        reg,
                                        ConvenerOrIssuerOrVerifier(convener.into())
                                    ))
                                    .map_err(DispatchError::from),
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
                                                    SetOrAddOrRemoveOrModify::Add(
                                                        VerificationPrice(100),
                                                    ),
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
                            assert_ok!(update.view(|action, registry| {
                                Mod::set_schemas_metadata_(
                                    action,
                                    registry,
                                    ConvenerOrIssuerOrVerifier(issuer.into()),
                                )
                            }));

                            let schema_0 = schemas.get_mut(&schema_ids[0]).unwrap();
                            let issuer = schema_0.issuers.get_mut(&Issuer(issuer.into())).unwrap();

                            for (key, price) in
                                (0..19).map(|idx| (idx.to_string(), VerificationPrice(100)))
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.view(|action, reg| {
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(verifier.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.view(|action, reg| {
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
                                verifiers: UnboundedVerifiersUpdate::Set(Default::default()).into(),
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );
                            assert_ok!(update.view(|action, reg| {
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(convener.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
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
                            assert_ok!(update.view(|action, reg| {
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
                    SetOrModify::Modify(MultiTargetUpdate::from_iter(vec![(
                        schema_ids[0],
                        SetOrAddOrRemoveOrModify::Remove,
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.clone().view(|action, reg| {
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
                        SetOrAddOrRemoveOrModify::Add(
                            schemas.get(&schema_ids[2]).cloned().unwrap().into(),
                        ),
                    )])),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(issuer.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::SenderCantApplyThisUpdate
                            );

                            assert_ok!(update.view(|action, reg| {
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
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(
                        too_large_schemas.next(),
                    ))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(convener.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::IssuersSizeExceeded
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(
                        too_large_schemas.next(),
                    ))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(convener.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::VerifiersSizeExceeded
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(
                        too_large_schemas.next(),
                    ))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(convener.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::VerificationPricesSizeExceeded
                            );
                        },
                    ) as _,
                ),
                (
                    line!(),
                    SetOrModify::Set(UnboundedSchemas(FromIterator::from_iter(
                        too_large_schemas.next(),
                    ))),
                    Box::new(
                        |update: SetSchemasMetadata<Test>,
                         _schemas: &mut BTreeMap<
                            TrustRegistrySchemaId,
                            UnboundedTrustRegistrySchemaMetadata,
                        >| {
                            assert_noop!(
                                update
                                    .clone()
                                    .view(|action, reg| {
                                        Mod::set_schemas_metadata_(
                                            action,
                                            reg,
                                            ConvenerOrIssuerOrVerifier(convener.into()),
                                        )
                                    })
                                    .map_err(DispatchError::from),
                                Error::<Test>::PriceCurrencySymbolSizeExceeded
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
                    TrustRegistriesStoredSchemas::<Test>::get(
                        init_or_update_trust_registry.registry_id
                    )
                    .0
                    .into(),
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
                        .flat_map(|(_id, schema)| schema.issuers.keys().copied())
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
                        .flat_map(|(_id, schema)| schema.issuers.keys().copied())
                        .flat_map(|issuer| TrustRegistryIssuerConfigurations::<Test>::get(
                            init_or_update_trust_registry.registry_id,
                            issuer
                        )
                        .delegated
                        .0)
                        .map(|delegated_issuer| (
                            delegated_issuer,
                            TrustRegistryDelegatedIssuerSchemas::<Test>::get(
                                init_or_update_trust_registry.registry_id,
                                delegated_issuer
                            )
                        ))
                        .collect::<BTreeMap<_, _>>(),
                    schemas
                        .iter()
                        .flat_map(|(id, schema)| schema.issuers.keys().copied().flat_map(
                            |issuer| TrustRegistryIssuerConfigurations::<Test>::get(
                                init_or_update_trust_registry.registry_id,
                                issuer
                            )
                            .delegated
                            .0
                            .into_iter()
                            .map(|delegated_issuer| (
                                delegated_issuer,
                                SingleTargetUpdate::new(id.clone(), IncOrDec::Inc(IncOrDec::ONE))
                            ))
                        ))
                        .fold(
                            BTreeMap::<_, DelegatedIssuerSchemas<Test>>::new(),
                            |mut acc, (issuer, update)| {
                                use crate::util::batch_update::ApplyUpdate;

                                update.apply_update(acc.entry(issuer).or_default());

                                acc
                            }
                        ),
                    "Failed test on line {:?}",
                    line
                );
                assert_eq!(
                    schemas
                        .iter()
                        .flat_map(|(_id, schema)| schema.verifiers.keys().copied())
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
