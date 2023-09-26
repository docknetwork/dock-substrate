use super::*;
use crate::{common::state_change::ToStateChange, did::UncheckedDidKey, util::IncId};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_PARAMS: u32 = 512;
const MAX_LABEL: u32 = 128;
const MAX_ACC: u32 = 128;
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

        let params = AccumulatorParameters {
            curve_type: CurveType::Bls12381,
            bytes: vec![3; b as usize].try_into().unwrap(),
            label: Some(vec![0; l as usize].try_into().unwrap())
        };

        let new_params = AddAccumulatorParams {
            params: params.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&new_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: add_params(RawOrigin::Signed(caller), new_params, signature)
    verify {
        assert_eq!(AccumulatorParams::get(AccumulatorOwner(did), IncId::from(1u8)).unwrap(), params);
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
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        let rem_params = RemoveAccumulatorParams {
            params_ref: (AccumulatorOwner(did), 1u8.try_into().unwrap()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_params.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);


    }: remove_params(RawOrigin::Signed(caller), rem_params, signature)
    verify {
        assert!(AccumulatorParams::<T>::get(AccumulatorOwner(did), IncId::from(1u8)).is_none());
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
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        let public_key = AccumulatorPublicKey {
            curve_type: CurveType::Bls12381,
            bytes: vec![3; b as usize].try_into().unwrap(),
            /// The params used to generate the public key (`P_tilde` comes from params)
            params_ref: Some((AccumulatorOwner(did), IncId::from(1u8)))
        };

        let add_key = AddAccumulatorPublicKey {
            public_key: public_key.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: add_public_key(RawOrigin::Signed(caller), add_key, signature)
    verify {
        assert_eq!(AccumulatorKeys::get(AccumulatorOwner(did), IncId::from(1u8)).unwrap(), public_key);
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
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        Pallet::<T>::add_public_key_(
            AddAccumulatorPublicKey {
                public_key: AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_KEY as usize].try_into().unwrap(),
                    /// The params used to generate the public key (`P_tilde` comes from params)
                    params_ref: Some((AccumulatorOwner(did), IncId::from(1u8)))
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        let rem_key = RemoveAccumulatorPublicKey {
            key_ref: (AccumulatorOwner(did), 1u8.try_into().unwrap()),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&rem_key.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);


    }: remove_public_key(RawOrigin::Signed(caller), rem_key, signature)
    verify {
        assert!(AccumulatorKeys::<T>::get(AccumulatorOwner(did), IncId::from(1u8)).is_none());
    }

    add_accumulator_sr25519 for sr25519, add_accumulator_ed25519 for ed25519, add_accumulator_secp256k1 for secp256k1 {
        {
            let b in 0 .. MAX_ACC;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);

        let public = pair.public();
        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![3; b as usize].try_into().unwrap(),
            key_ref: (AccumulatorOwner(did), 1u8.into()),
        });

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let acc_id: AccumulatorId = AccumulatorId([1; 32]);

        Pallet::<T>::add_params_(
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();


        Pallet::<T>::add_public_key_(
            AddAccumulatorPublicKey {
                public_key: AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_KEY as usize].try_into().unwrap(),
                    /// The params used to generate the public key (`P_tilde` comes from params)
                    params_ref: Some((AccumulatorOwner(did), IncId::from(1u8)))
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        let add_acc = AddAccumulator {
            id: acc_id,
            accumulator: accumulator.clone(),
            nonce: 1u8.into()
        };

        let sig = pair.sign(&add_acc.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: add_accumulator(RawOrigin::Signed(caller), add_acc.clone(), signature)
    verify {
        assert_eq!(Accumulators::<T>::get(acc_id).unwrap().accumulator, accumulator);
    }

    update_accumulator_sr25519 for sr25519, update_accumulator_ed25519 for ed25519, update_accumulator_secp256k1 for secp256k1 {
        {
            let a in 0 .. MAX_ACC;
            let b in 0 .. 30;
            let c in 0 .. 100;
            let d in 0 .. 30;
            let e in 0 .. 100;
            let f in 0 .. 100;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);

        let public = pair.public();
        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![3; MAX_ACC as usize].try_into().unwrap(),
            key_ref: (AccumulatorOwner(did), 1u8.try_into().unwrap()),
        });

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let acc_id: AccumulatorId = AccumulatorId([1; 32]);

        Pallet::<T>::add_params_(
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();


        Pallet::<T>::add_public_key_(
            AddAccumulatorPublicKey {
                public_key: AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_KEY as usize].try_into().unwrap(),
                    /// The params used to generate the public key (`P_tilde` comes from params)
                    params_ref: Some((AccumulatorOwner(did), IncId::from(1u8)))
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();
        Pallet::<T>::add_accumulator_(
            AddAccumulator {
                id: acc_id,
                accumulator,
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();


        let new_accumulated = vec![3; a as usize];
        let up_acc = UpdateAccumulator {
            id: acc_id,
            new_accumulated: new_accumulated.clone().into(),
            additions: Some((0..b).map(|i| vec![i as u8; c as usize].into()).collect()),
            removals: Some((0..d).map(|i| vec![i as u8; e as usize].into()).collect()),
            witness_update_info: Some(vec![5; f as usize].try_into().unwrap()),
            nonce: 1u32.into(),
        };

        let sig = pair.sign(&up_acc.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: update_accumulator(RawOrigin::Signed(caller), up_acc, signature)
    verify {
        assert_eq!(Accumulators::<T>::get(acc_id).unwrap().accumulator.accumulated(), new_accumulated);
    }

    remove_accumulator_sr25519 for sr25519, remove_accumulator_ed25519 for ed25519, remove_accumulator_secp256k1 for secp256k1 {
        let pair as Pair;
        let caller = whitelisted_caller();
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        let accumulator = Accumulator::Positive(AccumulatorCommon {
            accumulated: vec![3; MAX_ACC as usize].try_into().unwrap(),
            key_ref: (AccumulatorOwner(did), 1u8.try_into().unwrap()),
        });

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let acc_id: AccumulatorId = AccumulatorId([2; 32]);

        Pallet::<T>::add_params_(
            AddAccumulatorParams {
                params: AccumulatorParameters {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_PARAMS as usize].try_into().unwrap(),
                    label: Some(vec![1; MAX_LABEL as usize].try_into().unwrap()),
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();


        Pallet::<T>::add_public_key_(
            AddAccumulatorPublicKey {
                public_key: AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: vec![3; MAX_KEY as usize].try_into().unwrap(),
                    /// The params used to generate the public key (`P_tilde` comes from params)
                    params_ref: Some((AccumulatorOwner(did), IncId::from(1u8)))
                },
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        Pallet::<T>::add_accumulator_(
            AddAccumulator {
                id: acc_id,
                accumulator,
                nonce: 1u8.into()
            },
            AccumulatorOwner(did)
        ).unwrap();

        let remove_acc = RemoveAccumulator {
            id: acc_id,
            nonce: 1u8.into()
        };

        let sig = pair.sign(&remove_acc.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: remove_accumulator(RawOrigin::Signed(caller), remove_acc, signature)
    verify {
        assert!(Accumulators::<T>::get(acc_id).is_none());
    }
}
