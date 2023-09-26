use super::*;
use crate::{
    common::state_change::ToStateChange,
    did::{Did, DidSignature, UncheckedDidKey},
};
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_LEN: u32 = 10_000;

crate::bench_with_all_pairs! {
    with_pairs:
    set_claim_sr25519 for sr25519, set_claim_ed25519 for ed25519, set_claim_secp256k1 for secp256k1 {
        {
            let l in 0 .. MAX_LEN => ();
        }
        let pair as Pair;
        let caller = whitelisted_caller();
        let data = vec![0; l as usize];
        let did = Did([1; Did::BYTE_SIZE]);
        let public = pair.public();

        let attest = Attestation {
            priority: 1,
            iri: Some(vec![12; l as usize].try_into().unwrap())
        };

        let set_attest = SetAttestationClaim {
            attest,
            nonce: 1u8.into()
        };

        crate::did::Pallet::<T>::new_onchain_(
            did,
            vec![UncheckedDidKey::new_with_all_relationships(public)],
            Default::default(),
        ).unwrap();

        let sig = pair.sign(&set_attest.to_state_change().encode());
        let signature = DidSignature::new(did, 1u32, sig);
    }: set_claim(RawOrigin::Signed(caller), set_attest.clone(), signature)
    verify {
        assert_eq!(Attestations::get(Attester(did)), set_attest.attest);
    }
}
