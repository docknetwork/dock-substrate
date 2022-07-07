use super::*;
use crate::did::{Did, DidKey};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use sp_core::U256;
use sp_std::{iter::once, prelude::*};
use system::RawOrigin;

const MAX_REVOCATIONS: u32 = 1000;
const MAX_CONTROLLERS: u32 = 15;

/// create a OneOf policy. Redefining from test as cannot import
pub fn oneof(dids: &[Did]) -> Policy {
    Policy::OneOf(dids.iter().cloned().collect())
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

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let reg_id = [1u8; 32];
        let revoke_ids: BTreeSet<_> = (0..r).map(|i| U256::from(i).into()).collect();
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

        super::Module::<T>::new_registry_(AddRegistry { id: reg_id, registry: Registry {policy: oneof(&[did]), add_only: false}}).unwrap();
    }: revoke(RawOrigin::Signed(caller), revoke_raw, vec![DidSigs { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(revoke_ids
            .iter()
            .all(|id| Revocations::contains_key(reg_id, id)));
    }

    unrevoke_sr25519 for sr25519, unrevoke_ed25519 for ed25519, unrevoke_secp256k1 for secp256k1 {
        {
            let r in 1 .. MAX_REVOCATIONS as u32;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let reg_id = [2u8; 32];
        let revoke_ids: BTreeSet<_> = (0..r).map(|i| U256::from(i).into()).collect();

        super::Module::<T>::new_registry_(AddRegistry { id: reg_id, registry: Registry {policy: oneof(&[did]), add_only: false}}).unwrap();

        crate::revoke::Module::<T>::revoke_(
            RevokeRaw {
                /// The registry on which to operate
               registry_id: reg_id,
               /// Credential ids which will be revoked
               revoke_ids: revoke_ids.clone(),
               _marker: PhantomData
            },
            &mut Default::default(),
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

    }: unrevoke(RawOrigin::Signed(caller), unrevoke_raw, vec![DidSigs { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(revoke_ids
            .iter()
            .all(|id| !Revocations::contains_key(reg_id, id)));
    }

    remove_registry_sr25519 for sr25519, remove_registry_ed25519 for ed25519, remove_registry_secp256k1 for secp256k1 {
        {
            let c in 1 .. MAX_CONTROLLERS;
        }

        let pair as Pair;
        let caller = whitelisted_caller();
        let public = pair.public();
        let did = Did([3 as u8; Did::BYTE_SIZE]);
        let reg_id = [4 as u8; 32];
        let reg = Registry {
            policy: Policy::OneOf(once(did).chain((1..c).map(U256::from).map(Into::into).map(Did)).collect()),
            add_only: false,
        };
        let add_reg = AddRegistry {
            registry: reg.clone(),
            id: reg_id
        };
        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        super::Module::<T>::new_registry_(add_reg).unwrap();
        let rem_reg_raw = RemoveRegistryRaw {
            registry_id: reg_id,
            _marker: PhantomData
        };
        let rem_reg = RemoveRegistry::new_with_nonce(rem_reg_raw.clone(), 1u32.into());
        let sig = pair.sign(&rem_reg.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_registry(RawOrigin::Signed(caller), rem_reg_raw, vec![DidSigs { sig: signature, nonce: 1u32.into() }])
    verify {
        assert!(Registries::get(reg_id).is_none());
    };

    standard:
    new_registry {
        let c in 1 .. MAX_CONTROLLERS;

        let caller = whitelisted_caller();
        let did = Did([3 as u8; Did::BYTE_SIZE]);
        let reg_id = [4 as u8; 32];
        let reg = Registry {
            policy: Policy::OneOf(once(did).chain((1..c).map(U256::from).map(Into::into).map(Did)).collect()),
            add_only: false,
        };
        let add_reg = AddRegistry {
            registry: reg.clone(),
            id: reg_id
        };

    }: new_registry(RawOrigin::Signed(caller), add_reg)
    verify {
        assert_eq!(Registries::get(reg_id).unwrap(), reg);
    }
}
