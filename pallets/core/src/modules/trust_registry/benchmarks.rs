use super::*;
use crate::{
    common::state_change::ToStateChange,
    did::{Did, DidSignature, UncheckedDidKey},
    util::{batch_update::*, Action, ActionWrapper, Bytes},
};
use alloc::collections::BTreeMap;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use scale_info::prelude::string::String;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const TRUST_REGISTRY_MAX_NAME: u32 = 30;
const TRUST_REGISTRY_GOV_FRAMEWORK: u32 = 100;
const SCHEMA_ISSUERS: u32 = 50;
const SCHEMA_VERIFIERS: u32 = 50;
const SCHEMA_ISSUER_PRICES: u32 = 20;
const SCHEMA_ISSUER_PRICE_SYMBOL: u32 = 10;
const SCHEMAS_COUNT: u32 = 10;
const DELEGATED_ISSUERS: u32 = 10;

crate::bench_with_all_pairs! {
    with_pairs:
    init_or_update_trust_registry_sr25519 for sr25519, init_or_update_trust_registry_ed25519 for ed25519, init_or_update_trust_registry_secp256k1 for secp256k1 {
        {
            let n in 1 .. TRUST_REGISTRY_MAX_NAME as u32;
            let g in 1 .. TRUST_REGISTRY_GOV_FRAMEWORK as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([0; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let id = [1u8; 32].into();
        let init_or_update_trust_registry = InitOrUpdateTrustRegistry {
            registry_id: TrustRegistryId(id),
            nonce: 1u32.into(),
            gov_framework: Bytes(vec![1; g as usize]).try_into().unwrap(),
            name: (0..n).map(|idx| (98 + idx) as u8 as char).collect::<String>().try_into().unwrap()
        };
        let sig = pair.sign(&init_or_update_trust_registry.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig).into();
    }: init_or_update_trust_registry(RawOrigin::Signed(caller), init_or_update_trust_registry.clone(), signature)
    verify {
        assert_eq!(TrustRegistriesInfo::<T>::get(init_or_update_trust_registry.registry_id).unwrap(), TrustRegistryInfo {
            convener: Convener(did.into()),
            name: init_or_update_trust_registry.name.try_into().unwrap(),
            gov_framework: init_or_update_trust_registry.gov_framework.try_into().unwrap()
        });
    }

    set_schemas_metadata_sr25519 for sr25519, set_schemas_metadata_ed25519 for ed25519, set_schemas_metadata_secp256k1 for secp256k1 {
        {
            let i in 0 .. SCHEMA_ISSUERS as u32;
            let v in 0 .. SCHEMA_VERIFIERS as u32;
            let s in 1 .. SCHEMAS_COUNT as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([0; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let id = [1u8; 32].into();
        let init_or_update_trust_registry = InitOrUpdateTrustRegistry {
            registry_id: TrustRegistryId(id),
            nonce: 1u32.into(),
            gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
            name: (0..10).map(|idx| (98 + idx) as u8 as char).collect::<String>().try_into().unwrap()
        };
        ActionWrapper::<T, _, _>::new(
            1u32.into(),
            Convener(did.into()),
            init_or_update_trust_registry.clone()
        ).execute::<T, _, _, _, _>(
            |action, set| Pallet::<T>::init_or_update_trust_registry_(
                action.action,
                set,
                Convener(did.into())
            )
        ).unwrap();

        let mut schemas: BTreeMap<_, _> = (0..s)
            .map(|idx|
                (
                    TrustRegistrySchemaId([idx as u8; 32]),
                    UnboundedTrustRegistrySchemaMetadata {
                        issuers: UnboundedIssuersWith((0..SCHEMA_ISSUERS - i).map(|idx|
                            (
                                Issuer(Did([255 - idx as u8; 32]).into()),
                                UnboundedVerificationPrices(
                                    (0..SCHEMA_ISSUER_PRICES)
                                        .map(|p_idx| (
                                            (0..SCHEMA_ISSUER_PRICE_SYMBOL)
                                                .map(|idx| (98 + idx + p_idx) as u8 as char)
                                                .collect(),
                                            VerificationPrice(1000)
                                        ))
                                        .collect()
                                    )
                            )
                        ).collect()),
                        verifiers: UnboundedTrustRegistrySchemaVerifiers(
                            (0..SCHEMA_VERIFIERS - v)
                                .map(|idx| Verifier(Did([255 - idx as u8; 32]).into())
                        ).collect())
                    }
                )
            ).collect();

        SetSchemasMetadata {
            registry_id: TrustRegistryId(id),
            schemas: SetOrModify::Modify(schemas.clone().into_iter().map(|(id, schema)| (id, SetOrAddOrRemoveOrModify::Set(schema))).collect()),
            nonce: 2u32.into()
        }.execute_view(|action, set| Pallet::<T>::set_schemas_metadata_(action, set, ConvenerOrIssuerOrVerifier(did.into()))).unwrap();

        let update_issuers = schemas.keys().map(
            |schema_id| {
                UnboundedIssuersUpdate::Modify(
                    MultiTargetUpdate::from_iter((0..i).map(|idx| (Issuer(Did([idx as u8; 32]).into()), SetOrAddOrRemoveOrModify::Set(
                        UnboundedVerificationPrices(
                            (0..SCHEMA_ISSUER_PRICES)
                                .map(|p_idx| (
                                    (0..SCHEMA_ISSUER_PRICE_SYMBOL)
                                        .map(|idx| (98 + idx + p_idx) as u8 as char)
                                        .collect::<String>(),
                                    VerificationPrice(1000)
                                ))
                                .collect()
                        )
                    ))))
                )
            }
        );
        let update_verifiers = schemas.keys().map(
            |schema_id| {
                UnboundedVerifiersUpdate::Modify(MultiTargetUpdate::from_iter(
                    (0..v).map(|idx| (Verifier(Did([idx as u8; 32]).into()), AddOrRemoveOrModify::Add(())))
                ))
            }
        );

        let schemas_updates: MultiTargetUpdate<_, _> =
            update_issuers
                .zip(update_verifiers)
                .zip(schemas.keys())
                .map(|((issuers, verifiers), id)| (id.clone(), SetOrAddOrRemoveOrModify::Modify(OnlyExistent(UnboundedTrustRegistrySchemaMetadataUpdate {
                    verifiers: Some(verifiers),
                    issuers: Some(issuers)
                }))))
                .collect();

        let set_schemas_metadata = SetSchemasMetadata {
            registry_id: TrustRegistryId(id),
            schemas: SetOrModify::Modify(schemas_updates.clone()),
            nonce: 1u32.into()
        };

        for (key, update) in schemas_updates {
            let mut opt = schemas.remove(&key);
            update.apply_update(&mut opt);

            if let Some(schema) = opt {
                schemas.insert(key, schema);
            }
        }

        let sig = pair.sign(&set_schemas_metadata.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig).into();
    }: set_schemas_metadata(RawOrigin::Signed(caller), set_schemas_metadata, signature)
    verify {
        assert_eq!(Schemas::try_from(UnboundedSchemas(schemas)).unwrap(), Schemas(TrustRegistrySchemasMetadata::<T>::iter().map(|(schema_id, _, metadata)| (schema_id, metadata)).collect::<BTreeMap<_, _>>().try_into().unwrap()));
    }

    update_delegated_issuers_sr25519 for sr25519, update_delegated_issuers_ed25519 for ed25519, update_delegated_issuers_secp256k1 for secp256k1 {
        {
            let i in 1 .. DELEGATED_ISSUERS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([0; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let id = [1u8; 32].into();
        let init_or_update_trust_registry = InitOrUpdateTrustRegistry {
            registry_id: TrustRegistryId(id),
            nonce: 1u32.into(),
            gov_framework: Bytes(vec![1; 100]),
            name: (0..10).map(|idx| (98 + idx) as u8 as char).collect::<String>()
        };
        ActionWrapper::<T, _, _>::new(1u32.into(), Convener(did.into()), init_or_update_trust_registry.clone()).execute::<T, _, _, _, _>(|action, set| Pallet::<T>::init_or_update_trust_registry_(action.action, set, Convener(did.into()))).unwrap();

        let delegated = UnboundedDelegatedIssuers((0..i).map(|idx| Issuer(Did([idx as u8 + 90; 32]).into())).collect());

        for issuer in delegated.iter() {
            TrustRegistryIssuerSchemas::<T>::insert(init_or_update_trust_registry.registry_id, Issuer(did.into()), IssuerSchemas(Default::default()));
        }

        let update_delegated_issuers = UpdateDelegatedIssuers {
            registry_id: TrustRegistryId(id),
            delegated: SetOrModify::Set(delegated.clone()),
            nonce: 1u32.into()
        };
        let sig = pair.sign(&update_delegated_issuers.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig).into();
    }: update_delegated_issuers(RawOrigin::Signed(caller), update_delegated_issuers, signature)
    verify {
        assert_eq!(
            TrustRegistryIssuerConfigurations::<T>::get(
                init_or_update_trust_registry.registry_id,
                Issuer(did.into())
            )
            .delegated,
            delegated.try_into().unwrap()
        );
    }

    suspend_issuers_sr25519 for sr25519, suspend_issuers_ed25519 for ed25519, suspend_issuers_secp256k1 for secp256k1 {
        {
            let i in 1 .. SCHEMA_ISSUERS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([0; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let id = [1u8; 32].into();
        let init_or_update_trust_registry = InitOrUpdateTrustRegistry {
            registry_id: TrustRegistryId(id),
            nonce: 1u32.into(),
            gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
            name: (0..10).map(|idx| (98 + idx) as u8 as char).collect::<String>().try_into().unwrap()
        };
        ActionWrapper::<T, _, _>::new(
            1u32.into(),
            Convener(did.into()),
            init_or_update_trust_registry.clone()
        ).execute::<T, _, _, _, _>(
            |action, set|
                Pallet::<T>::init_or_update_trust_registry_(
                    action.action,
                    set,
                    Convener(did.into()))
        ).unwrap();

        let issuers: Vec<_> = (0..i).map(|idx| Issuer(Did([idx as u8; 32]).into())).collect();

        for issuer in &issuers {
            TrustRegistryIssuerSchemas::<T>::insert(init_or_update_trust_registry.registry_id, issuer, IssuerSchemas(Default::default()));
        }

        let suspend_issuers = SuspendIssuers {
            registry_id: TrustRegistryId(id),
            issuers: issuers.into_iter().collect(),
            nonce: 1u32.into()
        };
        let sig = pair.sign(&suspend_issuers.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig).into();
    }: suspend_issuers(RawOrigin::Signed(caller), suspend_issuers.clone(), signature)
    verify {
        assert!(
            TrustRegistryIssuerConfigurations::<T>::iter()
                .filter(|(_, issuer, _)| suspend_issuers.issuers.contains(issuer))
                .all(|(_, _, config)| config.suspended)
            );
    }

    unsuspend_issuers_sr25519 for sr25519, unsuspend_issuers_ed25519 for ed25519, unsuspend_issuers_secp256k1 for secp256k1 {
        {
            let i in 1 .. SCHEMA_ISSUERS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([0; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let id = [1u8; 32].into();
        let init_or_update_trust_registry = InitOrUpdateTrustRegistry {
            registry_id: TrustRegistryId(id),
            nonce: 1u32.into(),
            gov_framework: Bytes(vec![1; 100]).try_into().unwrap(),
            name: (0..10).map(|idx| (98 + idx) as u8 as char).collect::<String>().try_into().unwrap()
        };
        ActionWrapper::<T, _, _>::new(1u32.into(), Convener(did.into()), init_or_update_trust_registry.clone()).execute::<T, _, _, _, _>(|action, set| Pallet::<T>::init_or_update_trust_registry_(action.action, set, Convener(did.into()))).unwrap();

        let issuers: Vec<_> = (0..i).map(|idx| Issuer(Did([idx as u8; 32]).into())).collect();

        for issuer in &issuers {
            TrustRegistryIssuerSchemas::<T>::insert(init_or_update_trust_registry.registry_id, issuer, IssuerSchemas(Default::default()));
        }

        SuspendIssuers {
            registry_id: TrustRegistryId(id),
            issuers: issuers.clone().into_iter().collect(),
            nonce: 1u32.into()
        }.execute_view::<T, _, _, _, _>(|action, reg_info| Pallet::<T>::suspend_issuers_(action, reg_info, Convener(did.into()))).unwrap();

        let unsuspend_issuers = UnsuspendIssuers {
            registry_id: TrustRegistryId(id),
            issuers: issuers.into_iter().collect(),
            nonce: 1u32.into()
        };

        let sig = pair.sign(&unsuspend_issuers.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig).into();
    }: unsuspend_issuers(RawOrigin::Signed(caller), unsuspend_issuers.clone(), signature)
    verify {
        assert!(
            TrustRegistryIssuerConfigurations::<T>::iter()
                .filter(|(_, issuer, _)| unsuspend_issuers.issuers.contains(issuer))
                .all(|(_, _, config)| !config.suspended)
        );
    }
}
