use super::*;
use crate::did::{Did, DidKey, DidSignature};
use crate::util::IncId;
use crate::ToStateChange;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_std::prelude::*;
use system::RawOrigin;

const MAX_PARAMS: u32 = 512;
const MAX_LABEL: u32 = 128;
const MAX_KEY: u32 = 256;

crate::bench_with_all_pairs! {
    with_pairs:
    add_params_sr25519 for sr25519, add_params_ed25519 for ed25519, add_params_secp256k1 for secp256k1 {
        {
            let b in 0 .. MAX_PARAMS => ();
            let l in 1 .. MAX_LABEL => ();
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

        let params = BbsPlusParameters {
            curve_type: CurveType::Bls12381,
            bytes: vec![0; b as usize],
            label: Some(vec![0; l as usize])
        };
        let new_params = AddBBSPlusParams {
            params: params.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&new_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_params(RawOrigin::Signed(caller), new_params, signature)
    verify {
        assert_eq!(BbsPlusParams::get(BBSPlusParamsOwner(did), IncId::from(1u8)).unwrap(), params.clone());
    }

    remove_params_sr25519 for sr25519, remove_params_ed25519 for ed25519, remove_params_secp256k1 for secp256k1 {

        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        Module::<T>::add_params_(
            AddBBSPlusParams {
                params: BbsPlusParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![0; MAX_PARAMS as usize],
                    label: Some(vec![1; MAX_LABEL as usize])
                },
                nonce: 1u8.into()
            },
            BBSPlusParamsOwner(did)
        ).unwrap();

        let rem_params = RemoveBBSPlusParams {
            params_ref: (BBSPlusParamsOwner(did), 1u8.into()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: remove_params(RawOrigin::Signed(caller), rem_params, signature)
    verify {
        assert!(BbsPlusParams::get(BBSPlusParamsOwner(did), IncId::from(1u8)).is_none());
    }

    add_public_sr25519 for sr25519, add_public_ed25519 for ed25519, add_public_secp256k1 for secp256k1 {
        {
            let b in 0 .. MAX_KEY;
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

        Module::<T>::add_params_(
            AddBBSPlusParams {
                params: BbsPlusParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![0; MAX_PARAMS as usize],
                    label: Some(vec![1; MAX_LABEL as usize])
                },
                nonce: 1u8.into()
            },
            BBSPlusParamsOwner(did)
        ).unwrap();

        let key = BbsPlusPublicKey {
            curve_type: CurveType::Bls12381,
            bytes: vec![0; b as usize],
            /// The params used to generate the public key (`P_tilde` comes from params)
            params_ref: Some((BBSPlusParamsOwner(did), IncId::from(1u8)))
        };
        let add_key = AddBBSPlusPublicKey {
            did: did,
            key: key.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: add_public_key(RawOrigin::Signed(caller), add_key, signature)
    verify {
        assert_eq!(BbsPlusKeys::get(did, IncId::from(2u8)).unwrap(), key);
    }

    remove_public_sr25519 for sr25519, remove_public_ed25519 for ed25519, remove_public_secp256k1 for secp256k1 {

        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Module::<T>::new_onchain_(
            did,
            vec![DidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        Module::<T>::add_params_(
            AddBBSPlusParams {
                params: BbsPlusParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![0; MAX_PARAMS as usize],
                    label: Some(vec![1; MAX_LABEL as usize])
                },
                nonce: 1u8.into()
            },
            BBSPlusParamsOwner(did)
        ).unwrap();

        Module::<T>::add_public_key_(
            AddBBSPlusPublicKey {
                did: did,
                key: BbsPlusPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![0; MAX_KEY as usize],
                    /// The params used to generate the public key (`P_tilde` comes from params)
                    params_ref: Some((BBSPlusParamsOwner(did), IncId::from(1u8)))
                },
                nonce: 2u8.into()
            },
            &mut Default::default()
        ).unwrap();

        let rem_key = RemoveBBSPlusPublicKey {
            did: did,
            key_ref: (did, 1u8.into()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_public_key(RawOrigin::Signed(caller), rem_key, signature)
    verify {
        assert!(BbsPlusKeys::get(did, IncId::from(2u8)).is_none());
    }
}
