use super::*;
use crate::{
    common::{CurveType, ToStateChange},
    did::{Did, DidSignature, UncheckedDidKey},
    util::{BoundedBytes, IncId},
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

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

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let params = BBSPlusParameters::new(
            BoundedBytes::try_from(vec![0; l as usize]).unwrap(),
            BoundedBytes::try_from(vec![0; b as usize]).unwrap(),
            CurveType::Bls12381,
        );
        let new_params = AddOffchainSignatureParams {
            params: params.clone().into(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&new_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_params(RawOrigin::Signed(caller), new_params, signature)
    verify {
        assert_eq!(SignatureParams::<T>::get(SignatureParamsOwner(did), IncId::from(1u8)).unwrap(), params.clone().into());
    }

    remove_params_sr25519 for sr25519, remove_params_ed25519 for ed25519, remove_params_secp256k1 for secp256k1 {
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        Pallet::<T>::add_params_(
            AddOffchainSignatureParams {
                params: BBSPlusParameters::new(
                    BoundedBytes::try_from(vec![1; MAX_LABEL as usize]).unwrap(),
                    BoundedBytes::try_from(vec![0; MAX_PARAMS as usize]).unwrap(),
                    CurveType::Bls12381,
                ).into(),
                nonce: 1u8.into()
            },
            SignatureParamsOwner(did)
        ).unwrap();

        let rem_params = RemoveOffchainSignatureParams {
            params_ref: (SignatureParamsOwner(did), 1u8.into()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: remove_params(RawOrigin::Signed(caller), rem_params, signature)
    verify {
        assert!(SignatureParams::<T>::get(SignatureParamsOwner(did), IncId::from(1u8)).is_none());
    }

    add_public_sr25519 for sr25519, add_public_ed25519 for ed25519, add_public_secp256k1 for secp256k1 {
        {
            let b in 0 .. MAX_KEY;
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

        Pallet::<T>::add_params_(
            AddOffchainSignatureParams {
                params: BBSPlusParameters::new(
                    BoundedBytes::try_from(vec![1; MAX_LABEL as usize]).unwrap(),
                    BoundedBytes::try_from(vec![0; MAX_PARAMS as usize]).unwrap(),
                    CurveType::Bls12381,
                ).into(),
                nonce: 1u8.into()
            },
            SignatureParamsOwner(did)
        ).unwrap();

        let key: OffchainPublicKey<T> = BBSPlusPublicKey::new(
            BoundedBytes::try_from(vec![0; b as usize]).unwrap(),
            (SignatureParamsOwner(did), IncId::from(1u8)),
            CurveType::Bls12381,
        ).into();
        let add_key = AddOffchainSignaturePublicKey {
            did: did,
            key: key.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: add_public_key(RawOrigin::Signed(caller), add_key, signature)
    verify {
        assert_eq!(PublicKeys::get(did, IncId::from(2u8)).unwrap(), key);
    }

    remove_public_sr25519 for sr25519, remove_public_ed25519 for ed25519, remove_public_secp256k1 for secp256k1 {
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        Pallet::<T>::add_params_(
            AddOffchainSignatureParams {
                params: BBSPlusParameters::new(
                    BoundedBytes::try_from(vec![1; MAX_LABEL as usize]).unwrap(),
                    BoundedBytes::try_from(vec![0; MAX_PARAMS as usize]).unwrap(),
                    CurveType::Bls12381,
                ).into(),
                nonce: 1u8.into()
            },
            SignatureParamsOwner(did)
        ).unwrap();

        Pallet::<T>::add_public_key_(
            AddOffchainSignaturePublicKey {
                did: did,
                key: BBSPlusPublicKey::new(
                    BoundedBytes::try_from(vec![0; MAX_KEY as usize]).unwrap(),
                    (SignatureParamsOwner(did), IncId::from(1u8)),
                    CurveType::Bls12381,
                ).into(),
                nonce: 2u8.into()
            },
            &mut Default::default()
        ).unwrap();

        let rem_key = RemoveOffchainSignaturePublicKey {
            did: did,
            key_ref: (did, 1u8.into()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: remove_public_key(RawOrigin::Signed(caller), rem_key, signature)
    verify {
        assert!(PublicKeys::<T>::get(did, IncId::from(2u8)).is_none());
    }
}
