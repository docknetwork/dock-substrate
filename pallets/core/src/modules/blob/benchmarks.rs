use super::*;
use crate::{
    common::state_change::ToStateChange,
    did::{Did, DidSignature, UncheckedDidKey},
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_BLOB: u32 = 100;

crate::bench_with_all_pairs! {
    with_pairs:
    new_sr25519 for sr25519, new_ed25519 for ed25519, new_secp256k1 for secp256k1 {
        {
            let s in 0 .. MAX_BLOB;
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let n = 0;
        let public = pair.public();
        let did = Did([1; Did::BYTE_SIZE]);

        did::Pallet::<T>::new_onchain_(did, vec![UncheckedDidKey::new_with_all_relationships(public)], Default::default()).unwrap();
        let id = BlobId(Default::default());

        let blob = Blob {
            id,
            blob: Bytes((0..s).map(|i| i as u8).collect()),
        };
        let add_blob = AddBlob {
            blob,
            nonce: 1u8.into()
        };
        let sig = pair.sign(&add_blob.to_state_change().encode());
        let signature = DidSignature::new(did.clone(), 1u32, sig).into();
    }: new(RawOrigin::Signed(caller), add_blob, signature)
    verify {
        let value = Blobs::<T>::get(id);
        assert!(value.is_some());
    }
}
