use super::*;
use crate::keys_and_sigs::*;
use crate::ToStateChange;
use alloc::collections::BTreeSet;
use core::iter::once;
use core::iter::repeat;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use sp_application_crypto::Pair;
use sp_core::U256;
use sp_core::{ecdsa, ed25519, sr25519};
use sp_std::prelude::*;
use system::RawOrigin;

const SEED: u32 = 0;
const MAX_ENTITY_AMOUNT: u32 = 100;
const MAX_DID_DOC_REF_SIZE: u32 = 1024;
const MAX_ORIGINS: u32 = 100;
const MAX_ORIGIN_LENGTH: u32 = 1000;
const MAX_SERVICE_ENDPOINT_ID_LENGTH: u32 = 100;

#[macro_export]
macro_rules! with_pair {
    (let $pair: ident as Pair with idx $idx: expr; $($body: tt)+) => {
        $crate::with_pair!(let $pair as Pair with idx $idx, seed &[1; 32]; $($body)+ )
    };
    (let $pair: ident as Pair with idx $idx: expr, seed $seed: expr; $($body: tt)+) => {
        match $idx {
            0 => {
                let $pair = $crate::def_pair!(sr25519, $seed);
                $($body)+
            },
            1 => {
                let $pair = $crate::def_pair!(ed25519, $seed);
                $($body)+
            },
            2 => {
                let $pair = $crate::def_pair!(secp256k1, $seed);
                $($body)+
            }
            _ => unimplemented!()
        }
    }
}

#[macro_export]
macro_rules! def_pair {
    (sr25519, $seed: expr) => {{
        let pair = sr25519::Pair::from_seed($seed);
        struct TestSr25519Pair {
            pair: sr25519::Pair,
        }

        impl TestSr25519Pair {
            fn sign(&self, msg: &[u8]) -> sr25519::Signature {
                use rand_chacha::rand_core::SeedableRng;
                use schnorrkel::context::attach_rng;
                use schnorrkel::*;
                use sp_std::convert::TryInto;

                let mut transcript = merlin::Transcript::new(b"SigningContext");
                transcript.append_message(b"", b"substrate");
                transcript.append_message(b"sign-bytes", msg);
                let context = attach_rng(transcript, rand_chacha::ChaChaRng::from_seed([10u8; 32]));

                let sk = SecretKey::from_bytes(&self.pair.to_raw_vec()[..]).unwrap();

                sk.sign(
                    context,
                    &PublicKey::from_bytes(&self.pair.public()[..]).unwrap(),
                )
                .into()
            }

            fn public(&self) -> sr25519::Public {
                self.pair.public()
            }
        }

        TestSr25519Pair { pair }
    }};
    (ed25519, $seed: expr) => {
        ed25519::Pair::from_seed($seed)
    };
    (secp256k1, $seed: expr) => {
        get_secp256k1_keypair_1($seed)
    };
}

#[macro_export]
macro_rules! bench_with_all_pairs {
    (
        with_pairs:
            $(
                $bench_name_sr25519: ident for sr25519,
                $bench_name_ed25519: ident for ed25519,
                $bench_name_secp256k1: ident for secp256k1
                {
                    { $($init: tt)* }
                    let $pair: ident as Pair;
                    $($body: tt)+
                }: $call_tt: tt($($call_e: expr),+)
                verify { $($verification: tt)* }
            )+
        $(;
            standard:
                    $($other: tt)*
        )?
    ) => {
        benchmarks! {
            where_clause { where T: core::fmt::Debug }

            $(
                $bench_name_sr25519 {
                    $($init)*
                    let $pair = $crate::def_pair!(sr25519, &[4; 32]);
                    $($body)+;
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_ed25519 {
                    $($init)*
                    let $pair = $crate::def_pair!(ed25519, &[3; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_secp256k1 {
                    $($init)*
                    let $pair = $crate::def_pair!(secp256k1, &[2; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }
            )+

            $($($other)*)?
        }
    };
    ($bench_name: ident for $pair: ident { { $($init: tt)* } $($body: tt)+ } $($rest: tt)*) => {
        $bench_name {
            $($init)*
            let $pair = $crate::def_pair!($pair, &[1; 32]);
            $($body)+
        }
        $($rest)*
    };
}

#[macro_export]
bench_with_all_pairs! {
    with_pairs:
    add_keys_sr25519 for sr25519, add_keys_ed25519 for ed25519, add_keys_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let did_key = DidKey::new_with_all_relationships(pair.public());

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![did_key.clone()],
            Default::default(),
        ).unwrap();

        let keys: Vec<_> =
            (0..k)
                .map(|idx| def_pair!(secp256k1, &[10 + idx as u8; 32]).public())
                .map(DidKey::new_with_all_relationships)
                .collect();

        let key_update = AddKeys {
            did,
            keys: keys.clone(),
            nonce: 1u8.into()
        };

        // frame_support::log::error!("A {:?} {}", PublicKey::from(public), s);
        let sig = pair.sign(&key_update.to_state_change().encode());
        // frame_support::log::error!("B");
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_keys(RawOrigin::Signed(caller), key_update, signature)
    verify {
        let mut stored_keys = DidKeys::iter_prefix_values(did).collect::<Vec<_>>();
        stored_keys.sort_by_key(|key| key.public_key.as_slice().to_vec());

        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.push(did_key);
        keys.sort_by_key(|key| key.public_key.as_slice().to_vec());

        assert_eq!(stored_keys, keys);
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
            (0..k)
                .map(|i| ed25519::Pair::from_seed(&U256::from(i).into()))
                .map(|pair| DidKey::new_with_all_relationships(pair.public()))
                .chain(once(DidKey::new_with_all_relationships(public)))
                .collect();

        crate::did::Module::<T>::new_onchain_(
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
        assert_eq!(DidKeys::iter_prefix(did).count(), 0);
    }

    add_controllers_sr25519 for sr25519, add_controllers_ed25519 for ed25519, add_controllers_secp256k1 for secp256k1 {
        {
            let k in 1 .. MAX_ENTITY_AMOUNT;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([2; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
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
        let mut stored_controllers = DidControllers::iter_prefix(did).map(|(cnt, _)| cnt).collect::<Vec<_>>();
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

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
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
        assert_eq!(DidControllers::iter_prefix(did).count(), 0);
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

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let add_endpoint = AddServiceEndpoint {
            did,
            id: WrappedBytes(vec![1; i as usize]),
            endpoint: ServiceEndpoint {
                origins: (0..o).map(|i| vec![i as u8; l as usize].into()).collect(),
                types: crate::did::service_endpoints::ServiceEndpointType::LINKED_DOMAINS
            },
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_endpoint.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_service_endpoint(RawOrigin::Signed(caller), add_endpoint.clone(), signature)
    verify {
        assert_eq!(DidServiceEndpoints::get(did, WrappedBytes(vec![1; i as usize])).unwrap(), add_endpoint.endpoint);
    }

    remove_service_endpoint_sr25519 for sr25519, remove_service_endpoint_ed25519 for ed25519, remove_service_endpoint_secp256k1 for secp256k1 {
        {
            let o in 1 .. MAX_ORIGINS;
            let l in 1 .. MAX_ORIGIN_LENGTH;
            let i in 1 .. MAX_SERVICE_ENDPOINT_ID_LENGTH;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([3; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        crate::did::Module::<T>::add_service_endpoint_(
            AddServiceEndpoint {
                did,
                id: WrappedBytes(vec![1; i as usize]),
                endpoint: ServiceEndpoint {
                    origins: (0..o).map(|i| vec![i as u8; l as usize].into()).collect(),
                    types: crate::did::service_endpoints::ServiceEndpointType::LINKED_DOMAINS
                },
                nonce: 1u8.into()
            },
            &mut Default::default()
        ).unwrap();

        let remove_endpoint = RemoveServiceEndpoint {
            id: WrappedBytes(vec![1; i as usize]),
            did,
            nonce: 1u8.into()
        };

        let sig = pair.sign(&remove_endpoint.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_service_endpoint(RawOrigin::Signed(caller), remove_endpoint.clone(), signature)
    verify {
       assert!(DidServiceEndpoints::get(did, WrappedBytes(vec![1; i as usize])).is_none());
    };

    standard:
    new_onchain {
        let k in 1 .. MAX_ENTITY_AMOUNT => ();
        let c in 1 .. MAX_ENTITY_AMOUNT => ();

        let caller = whitelisted_caller();
        let did = Did([4; Did::BYTE_SIZE]);

        let keys: Vec<_> = (0..k)
            .map(|i| ed25519::Pair::from_seed(&U256::from(i).into()))
            .map(|pair| DidKey::new_with_all_relationships(pair.public()))
            .collect();
        let controllers: BTreeSet<_> = (0..c)
            .map(|i| U256::from(i).into())
            .map(Did)
            .map(Controller)
            .collect();

    }: new_onchain(RawOrigin::Signed(caller), did, keys.clone(), controllers.clone())
    verify {
        assert_eq!(Dids::<T>::get(did).unwrap().into_onchain().unwrap(), WithNonce::new(OnChainDidDetails::new((keys.len() as u32).into(), keys.iter().filter(|key| key.can_control() || key.ver_rels.is_empty()).count() as u32, controllers.len() as u32 + 1)));

        let mut stored_keys = DidKeys::iter_prefix_values(did).collect::<Vec<_>>();
        stored_keys.sort_by_key(|key| key.public_key.as_slice().to_vec());

        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.sort_by_key(|key| key.public_key.as_slice().to_vec());

        assert_eq!(stored_keys, keys);

        let mut stored_controllers = DidControllers::iter_prefix(did).map(|(cnt, _)| cnt).collect::<Vec<_>>();
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

        let did_doc_ref = OffChainDidDocRef::CID((0..k).map(|k| k as u8).collect::<Vec<_>>().into());

    }: new_offchain(RawOrigin::Signed(caller.clone()), did, did_doc_ref.clone())
    verify {
        assert_eq!(Module::<T>::offchain_did_details(&did).unwrap(), OffChainDidDetails::new(caller, did_doc_ref));
    }
}
