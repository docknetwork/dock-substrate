use super::*;
use crate::{common::state_change::ToStateChange, did::service_endpoints::*};
use alloc::collections::BTreeSet;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_application_crypto::Pair;
use sp_core::{ed25519, U256};
use sp_runtime::traits::TryCollect;
use sp_std::iter::once;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_ENTITY_AMOUNT: u32 = 10;
const MAX_DID_DOC_REF_SIZE: u32 = 100;
const MAX_ORIGINS: u32 = 10;
const MAX_ORIGIN_LENGTH: u32 = 10;
const MAX_SERVICE_ENDPOINT_ID_LENGTH: u32 = 100;

crate::bench_with_all_pairs! {
    with_pairs:
    add_keys_sr25519 for sr25519, add_keys_ed25519 for ed25519, add_keys_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let did_key = UncheckedDidKey::new_with_all_relationships(pair.public());

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![did_key.clone()],
            Default::default(),
        ).unwrap();

        let keys: Vec<_> =
            (0..k)
                .map(|idx| crate::def_test_pair!(secp256k1, &[10 + idx as u8; 32]).public())
                .map(UncheckedDidKey::new_with_all_relationships)
                .collect();

        let key_update = AddKeys {
            did,
            keys: keys.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&key_update.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_keys(RawOrigin::Signed(caller), key_update, signature)
    verify {
        let mut stored_keys = DidKeys::<T>::iter_prefix_values(did).collect::<Vec<_>>();
        stored_keys.sort_by_key(|key| key.public_key().as_slice().to_vec());

        let mut keys = keys.clone();
        keys.push(did_key);
        keys.sort_by_key(|key| key.public_key.as_slice().to_vec());

        assert_eq!(stored_keys, keys.into_iter().map(DidKey::try_from).map(Result::unwrap).collect::<Vec<_>>());
    }

    remove_keys_sr25519 for sr25519, remove_keys_ed25519 for ed25519, remove_keys_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        let keys: Vec<_> =
            once(UncheckedDidKey::new_with_all_relationships(public))
                .chain(
                    (0..k)
                        .map(|i| ed25519::Pair::from_seed(&U256::from(i).into()))
                        .map(|pair| UncheckedDidKey::new_with_all_relationships(pair.public()))
                )
                .map(Into::into)
                .collect();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            keys.clone(),
            Default::default(),
        ).unwrap();

        let key_update = RemoveKeys {
            did,
            keys: (1..=k + 1).map(IncId::from).collect(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&key_update.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_keys(RawOrigin::Signed(caller), key_update, signature)
    verify {
        assert_eq!(DidKeys::<T>::iter_prefix(did).count(), 0);
    }

    add_controllers_sr25519 for sr25519, add_controllers_ed25519 for ed25519, add_controllers_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([2; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let controllers: BTreeSet<_> = (0..k)
            .map(|i| U256::from(i).into())
            .map(Did)
            .map(Controller)
            .collect();

        let new_controllers = AddControllers {
            did,
            controllers: controllers.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&new_controllers.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_controllers(RawOrigin::Signed(caller), new_controllers, signature)
    verify {
        let mut stored_controllers = DidControllers::<T>::iter_prefix(did).map(|(cnt, _)| cnt).collect::<Vec<_>>();
        stored_controllers.sort();

        let mut controllers = controllers.into_iter().collect::<Vec<_>>();
        controllers.push(Controller(did));
        controllers.sort();

        assert_eq!(stored_controllers, controllers);
    }

    remove_controllers_sr25519 for sr25519, remove_controllers_ed25519 for ed25519, remove_controllers_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([3; Did::BYTE_SIZE]);
        let public = pair.public();
        let controllers: BTreeSet<_> = (0..k)
            .map(|i| U256::from(i).into())
            .map(Did)
            .map(Controller)
            .collect();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            controllers.clone(),
        ).unwrap();

        let rem_controllers = RemoveControllers {
            did,
            controllers: controllers.clone().into_iter().chain(once(Controller(did))).collect(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_controllers.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_controllers(RawOrigin::Signed(caller), rem_controllers, signature)
    verify {
        assert_eq!(DidControllers::<T>::iter_prefix(did).count(), 0);
    }

    add_service_endpoint_sr25519 for sr25519, add_service_endpoint_ed25519 for ed25519, add_service_endpoint_secp256k1 for secp256k1 {
        {
            let o in 1 .. MAX_ORIGINS;
            let l in 1 .. MAX_ORIGIN_LENGTH;
            let i in 1 .. MAX_SERVICE_ENDPOINT_ID_LENGTH;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([3; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let add_endpoint = AddServiceEndpoint {
            did,
            id: ServiceEndpointId(vec![1; i as usize].try_into().unwrap()),
            endpoint: ServiceEndpoint {
                origins: (0..o).map(|i| vec![i as u8; l as usize].try_into().unwrap()).map(ServiceEndpointOrigin).try_collect().unwrap(),
                types: crate::did::service_endpoints::ServiceEndpointType::LINKED_DOMAINS
            },
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_endpoint.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_service_endpoint(RawOrigin::Signed(caller), add_endpoint.clone(), signature)
    verify {
        assert_eq!(DidServiceEndpoints::<T>::get(did, ServiceEndpointId(vec![1; i as usize].try_into().unwrap())), Some(add_endpoint.endpoint));
    }

    remove_service_endpoint_sr25519 for sr25519, remove_service_endpoint_ed25519 for ed25519, remove_service_endpoint_secp256k1 for secp256k1 {
        {
            let i in 1 .. MAX_SERVICE_ENDPOINT_ID_LENGTH;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([3; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        crate::did::Pallet::<T>::add_service_endpoint_(
            AddServiceEndpoint {
                did,
                id: ServiceEndpointId(vec![1; i as usize].try_into().unwrap()),
                endpoint: ServiceEndpoint {
                    origins: (0..MAX_ORIGINS as usize).map(|i| vec![i as u8; MAX_ORIGIN_LENGTH as usize].try_into().unwrap()).map(ServiceEndpointOrigin).try_collect().unwrap(),
                    types: crate::did::service_endpoints::ServiceEndpointType::LINKED_DOMAINS
                },
                nonce: 1u8.into()
            },
            &mut Default::default()
        ).unwrap();

        let remove_endpoint = RemoveServiceEndpoint {
            id: ServiceEndpointId(vec![1; i as usize].try_into().unwrap()),
            did,
            nonce: 1u8.into()
        };

        let sig = pair.sign(&remove_endpoint.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_service_endpoint(RawOrigin::Signed(caller), remove_endpoint.clone(), signature)
    verify {
       assert!(DidServiceEndpoints::<T>::get(did, ServiceEndpointId(vec![1; i as usize].try_into().unwrap())).is_none());
    }
    remove_onchain_did_sr25519 for sr25519, remove_onchain_did_ed25519 for ed25519, remove_onchain_did_secp256k1 for secp256k1 {
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([3; Did::BYTE_SIZE]);
        let public = pair.public();

        let keys: Vec<_> = once(UncheckedDidKey::new_with_all_relationships(public)).chain((0..MAX_ENTITY_AMOUNT)
            .map(|i| ed25519::Pair::from_seed(&U256::from(i).into()))
            .map(|pair| UncheckedDidKey::new_with_all_relationships(pair.public())))
            .collect();
        let controllers: BTreeSet<_> = (0..MAX_ENTITY_AMOUNT)
            .map(|i| U256::from(i).into())
            .map(Did)
            .map(Controller)
            .collect();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            keys,
            controllers,
        ).unwrap();

        let remove_did = DidRemoval {
            did,
            nonce: 1u8.into()
        };

        for i in 0..MAX_ENTITY_AMOUNT {
            crate::did::Pallet::<T>::add_service_endpoint_(
                AddServiceEndpoint {
                    did,
                    id: ServiceEndpointId(vec![1; (i + 1) as usize].try_into().unwrap()),
                    endpoint: ServiceEndpoint {
                        origins: (0..MAX_ORIGINS as usize).map(|i| vec![i as u8; MAX_ORIGIN_LENGTH as usize].try_into().unwrap()).map(ServiceEndpointOrigin).try_collect().unwrap(),
                        types: crate::did::service_endpoints::ServiceEndpointType::LINKED_DOMAINS
                    },
                    nonce: 1u8.into()
                },
                &mut Default::default()
            ).unwrap();
        }

        let sig = pair.sign(&remove_did.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_onchain_did(RawOrigin::Signed(caller), remove_did.clone(), signature)
    verify {
       assert!(Dids::<T>::get(did).is_none());
    };

    standard:
    new_onchain {
        let k in 1 .. MAX_ENTITY_AMOUNT => ();
        let c in 1 .. MAX_ENTITY_AMOUNT => ();

        let caller = whitelisted_caller();
        let did = Did([4; Did::BYTE_SIZE]);

        let keys: Vec<_> = (0..k)
            .map(|i| ed25519::Pair::from_seed(&U256::from(i).into()))
            .map(|pair| UncheckedDidKey::new_with_all_relationships(pair.public()))
            .collect();
        let controllers: BTreeSet<_> = (0..c)
            .map(|i| U256::from(i).into())
            .map(Did)
            .map(Controller)
            .collect();

    }: new_onchain(RawOrigin::Signed(caller), did, keys.clone().into_iter().map(Into::into).collect(), controllers.clone())
    verify {
        let keys: Vec<_> = keys.into_iter().map(DidKey::try_from).map(Result::unwrap).collect();
        assert_eq!(Dids::<T>::get(did).unwrap().into_onchain().unwrap(), WithNonce::new(OnChainDidDetails::new((keys.len() as u32).into(), keys.iter().filter(|key| key.can_control() || key.ver_rels().is_empty()).count() as u32, controllers.len() as u32 + 1)));

        let mut stored_keys = DidKeys::<T>::iter_prefix_values(did).collect::<Vec<_>>();
        stored_keys.sort_by_key(|key| key.public_key().as_slice().to_vec());

        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.sort_by_key(|key| key.public_key().as_slice().to_vec());

        assert_eq!(stored_keys, keys);

        let mut stored_controllers = DidControllers::<T>::iter_prefix(did).map(|(cnt, _)| cnt).collect::<Vec<_>>();
        stored_controllers.sort();

        let mut controllers = controllers.into_iter().collect::<Vec<_>>();
        controllers.push(Controller(did));
        controllers.sort();

        assert_eq!(stored_controllers, controllers);
    }

    new_offchain {
        let k in 1 .. MAX_DID_DOC_REF_SIZE => ();

        let caller: T::AccountId = whitelisted_caller();
        let did = Did([4; Did::BYTE_SIZE]);

        let did_doc_ref = OffChainDidDocRef::<T>::CID(BoundedBytes((0..k).map(|k| k as u8).try_collect().unwrap()));

    }: new_offchain(RawOrigin::Signed(caller.clone()), did, did_doc_ref.clone())
    verify {
        assert_eq!(Pallet::<T>::offchain_did_details(&did).unwrap(), OffChainDidDetails::new(caller, did_doc_ref));
    }
    set_offchain_did_doc_ref {
        let k in 1 .. MAX_DID_DOC_REF_SIZE => ();

        let caller: T::AccountId = whitelisted_caller();
        let did = Did([4; Did::BYTE_SIZE]);

        let did_doc_ref = OffChainDidDocRef::<T>::CID(BoundedBytes((0..k).map(|k| k as u8).try_collect().unwrap()));
        super::Pallet::<T>::new_offchain_(caller.clone(), did, OffChainDidDocRef::<T>::URL(Default::default())).unwrap();

    }: set_offchain_did_doc_ref(RawOrigin::Signed(caller.clone()), did, did_doc_ref.clone())
    verify {
        assert_eq!(Pallet::<T>::offchain_did_details(&did).unwrap(), OffChainDidDetails::new(caller, did_doc_ref));
    }
    remove_offchain_did {
        let caller: T::AccountId = whitelisted_caller();
        let did = Did([4; Did::BYTE_SIZE]);

        let did_doc_ref = OffChainDidDocRef::<T>::CID(BoundedBytes((1..MAX_DID_DOC_REF_SIZE).map(|k| k as u8).try_collect().unwrap()));
        super::Pallet::<T>::new_offchain_(caller.clone(), did, OffChainDidDocRef::<T>::URL(Default::default())).unwrap();

    }: remove_offchain_did(RawOrigin::Signed(caller.clone()), did)
    verify {
        assert!(Pallet::<T>::offchain_did_details(&did).is_err());
    }
}
