use super::*;
use crate::{
    common::state_change::ToStateChange,
    did::{Did, DidSignature, UncheckedDidKey},
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_core::U256;
use sp_std::iter::once;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_REVOCATIONS: u32 = 1000;
const MAX_CONTROLLERS: u32 = 15;

fn dummy_registry<T: Limits>() -> Registry<T> {
    Registry {
        policy: Policy::one_of(once(Did([3; 32]))).unwrap(),
        add_only: false,
    }
}

crate::bench_with_all_pairs! {
    with_pairs:
    revoke_sr25519 for sr25519, revoke_ed25519 for ed25519, revoke_secp256k1 for secp256k1 {
        {
            let r in 1 .. MAX_REVOCATIONS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let reg_id = RegistryId([1u8; 32]);
        let revoke_ids: BTreeSet<_> = (0..r).map(|i| U256::from(i).into()).map(RevokeId).collect();
        let revoke_raw = RevokeRaw {
             /// The registry on which to operate
            registry_id: reg_id,
            /// Credential ids which will be revoked
            revoke_ids: revoke_ids.clone(),
            _marker: PhantomData
        };

        let revoke = Revoke::new_with_nonce(revoke_raw.clone(), 1u32.into());
        let sig = pair.sign(&revoke.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

        super::Pallet::<T>::new_registry_(AddRegistry { id: reg_id, new_registry: Registry { policy: Policy::one_of(&[did]).unwrap(), add_only: false } }).unwrap();
    }: revoke(RawOrigin::Signed(caller), revoke_raw, vec![DidSignatureWithNonce { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(revoke_ids
            .iter()
            .all(|id| Revocations::<T>::contains_key(reg_id, id)));
    }

    unrevoke_sr25519 for sr25519, unrevoke_ed25519 for ed25519, unrevoke_secp256k1 for secp256k1 {
        {
            let r in 1 .. MAX_REVOCATIONS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let reg_id = RegistryId([2u8; 32]);
        let revoke_ids: BTreeSet<_> = (0..r).map(|i| U256::from(i).into()).map(RevokeId).collect();

        super::Pallet::<T>::new_registry_(AddRegistry { id: reg_id, new_registry: Registry { policy: Policy::one_of(&[did]).unwrap(), add_only: false } }).unwrap();

        crate::revoke::Pallet::<T>::revoke_(
            RevokeRaw {
                /// The registry on which to operate
               registry_id: reg_id,
               /// Credential ids which will be revoked
               revoke_ids: revoke_ids.clone(),
               _marker: PhantomData
            },
            &mut dummy_registry()
        ).unwrap();

        let unrevoke_raw = UnRevokeRaw {
            /// The registry on which to operate
           registry_id: reg_id,
           /// Credential ids which will be revoked
           revoke_ids: revoke_ids.clone(),
           _marker: PhantomData
        };

        let unrevoke = UnRevoke::new_with_nonce(unrevoke_raw.clone(), 1u32.into());
        let sig = pair.sign(&unrevoke.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: unrevoke(RawOrigin::Signed(caller), unrevoke_raw, vec![DidSignatureWithNonce { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(revoke_ids
            .iter()
            .all(|id| !Revocations::<T>::contains_key(reg_id, id)));
    }

    remove_registry_sr25519 for sr25519, remove_registry_ed25519 for ed25519, remove_registry_secp256k1 for secp256k1 {
        let pair as Pair;
        let caller = whitelisted_caller();
        let public = pair.public();
        let did = Did([3 as u8; Did::BYTE_SIZE]);
        let reg_id = RegistryId([4 as u8; 32]);
        let reg = Registry {
            policy: Policy::one_of(once(did).chain((1..MAX_CONTROLLERS).map(U256::from).map(Into::into).map(Did)).collect::<Vec<_>>()).unwrap(),
            add_only: false,
        };
        let add_reg = AddRegistry {
            new_registry: reg.clone(),
            id: reg_id
        };
        let revoke_ids: BTreeSet<_> = (0..100).map(|i| U256::from(i).into()).map(RevokeId).collect();
        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        super::Pallet::<T>::new_registry_(add_reg).unwrap();

        crate::revoke::Pallet::<T>::revoke_(
            RevokeRaw {
                /// The registry on which to operate
               registry_id: reg_id,
               /// Credential ids which will be revoked
               revoke_ids: revoke_ids.clone(),
               _marker: PhantomData
            },
            &mut dummy_registry()
        ).unwrap();

        let rem_reg_raw = RemoveRegistryRaw {
            registry_id: reg_id,
            _marker: PhantomData
        };
        let rem_reg = RemoveRegistry::new_with_nonce(rem_reg_raw.clone(), 1u32.into());
        let sig = pair.sign(&rem_reg.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_registry(RawOrigin::Signed(caller), rem_reg_raw, vec![DidSignatureWithNonce { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(Registries::<T>::get(reg_id).is_none());
    };

    standard:
    new_registry {
        let c in 1 .. MAX_CONTROLLERS;

        let caller = whitelisted_caller();
        let did = Did([3 as u8; Did::BYTE_SIZE]);
        let reg_id = RegistryId([4 as u8; 32]);
        let reg = Registry {
            policy: Policy::one_of(once(did).chain((1..c).map(U256::from).map(Into::into).map(Did)).collect::<Vec<_>>()).unwrap(),
            add_only: false,
        };
        let add_reg = AddRegistry {
            new_registry: reg.clone(),
            id: reg_id
        };

    }: new_registry(RawOrigin::Signed(caller), add_reg)
    verify {
        assert_eq!(Registries::<T>::get(reg_id).unwrap(), reg);
    }
}
