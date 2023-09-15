use super::*;
use crate::{
    common::state_change::ToStateChange,
    did::{Did, DidSignature, UncheckedDidKey},
    util::BoundedBytes,
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_core::U256;
use sp_runtime::traits::TryCollect;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MIN_CREDENTIAL_SIZE: u32 = 100;
const MAX_CREDENTIAL_SIZE: u32 = 10_000;
const MAX_POLICY_CONTROLLERS: u32 = 15;

crate::bench_with_all_pairs! {
    with_pairs:
    update_sr25519 for sr25519, update_ed25519 for ed25519, update_secp256k1 for secp256k1 {
        {
            let r in MIN_CREDENTIAL_SIZE .. MAX_CREDENTIAL_SIZE as u32;
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
        let credential = StatusListCredentialWithPolicy {
            status_list_credential: StatusListCredential::<T>::RevocationList2020Credential(BoundedBytes((0..r).map(|v| v as u8).try_collect().unwrap())),
            policy: Policy::one_of((0..MAX_POLICY_CONTROLLERS).map(|i| U256::from(i).into()).map(Did)).unwrap()
        };
        super::Pallet::<T>::create_(id, credential).unwrap();

        let credential = StatusListCredential::<T>::StatusList2021Credential(BoundedBytes((0..r).map(|v| v as u8).try_collect().unwrap()));
        let update_credential_raw = UpdateStatusListCredentialRaw {
             /// Unique identifier of the underlying `StatusListCredential`
            id,
            /// The `StatusListCredential` itself
            credential,
            _marker: PhantomData
        };
        let update = WithNonce::new_with_nonce(update_credential_raw, 1u32.into());

        let sig = pair.sign(&update.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: update(RawOrigin::Signed(caller), update.into_data(), vec![DidSignatureWithNonce { sig: signature, nonce: 1u32.into() }])
    verify {
        assert_eq!(StatusListCredentials::get(id).unwrap(), StatusListCredentialWithPolicy {
            status_list_credential: StatusListCredential::<T>::StatusList2021Credential(BoundedBytes((0..r).map(|v| v as u8).try_collect().unwrap())),
            policy: Policy::one_of((0..MAX_POLICY_CONTROLLERS).map(|i| U256::from(i).into()).map(Did)).unwrap()
        });
    }

    remove_sr25519 for sr25519, remove_ed25519 for ed25519, remove_secp256k1 for secp256k1 {
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
        let credential = StatusListCredentialWithPolicy {
            status_list_credential: StatusListCredential::<T>::RevocationList2020Credential(BoundedBytes((0..MAX_CREDENTIAL_SIZE).map(|v| v as u8).try_collect().unwrap())),
            policy: Policy::one_of((0..MAX_POLICY_CONTROLLERS).map(|i| U256::from(i).into()).map(Did)).unwrap()
        };
        super::Pallet::<T>::create_(id, credential).unwrap();

        let remove_credential_raw = RemoveStatusListCredentialRaw {
             /// Unique identifier of the underlying `StatusListCredential`
            id,
            _marker: PhantomData
        };
        let remove = WithNonce::new_with_nonce(remove_credential_raw, 1u32.into());

        let sig = pair.sign(&remove.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);

    }: remove(RawOrigin::Signed(caller), remove.into_data(), vec![DidSignatureWithNonce { sig: signature, nonce: 1u32.into() }])
    verify {
        assert_eq!(StatusListCredentials::<T>::get(id), None);
    };

    standard:
    create {
        let r in MIN_CREDENTIAL_SIZE .. MAX_CREDENTIAL_SIZE as u32;
        let c in 1 .. MAX_POLICY_CONTROLLERS as u32;

        let caller = whitelisted_caller();

        let id = [1u8; 32].into();
        let credential = StatusListCredentialWithPolicy {
            status_list_credential: StatusListCredential::<T>::RevocationList2020Credential(BoundedBytes((0..r).map(|v| v as u8).try_collect().unwrap())),
            policy: Policy::one_of((0..c).map(|i| U256::from(i).into()).map(Did)).unwrap()
        };

    }: create(RawOrigin::Signed(caller), id, credential)
    verify {
        assert_eq!(StatusListCredentials::<T>::get(id).unwrap(), StatusListCredentialWithPolicy {
            status_list_credential: StatusListCredential::<T>::RevocationList2020Credential(BoundedBytes((0..r).map(|v| v as u8).try_collect().unwrap())),
            policy: Policy::one_of((0..c).map(|i| U256::from(i).into()).map(Did)).unwrap()
        });
    }
}
