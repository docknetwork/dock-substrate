use super::*;
use crate::did::{Did, DidKey, DidSignature};
use crate::keys_and_sigs::*;
use crate::util::IncId;
use crate::ToStateChange;
use alloc::collections::BTreeSet;
use core::iter::repeat;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use sp_application_crypto::Pair;
use sp_core::{ecdsa, ed25519, sr25519};
use sp_std::prelude::*;
use system::RawOrigin;

const MAX_LEN: u32 = 10_000;

benchmarks! {
    where_clause { where T: core::fmt::Debug }

    deploy {
        let l in 0 .. MAX_LEN => ();

        let caller = whitelisted_caller();
        let data = vec![0; l as usize];

    }: deploy(RawOrigin::Signed(caller), data.clone())
    verify {
        let hash = <T as system::Config>::Hashing::hash(&data);
        assert_eq!(Anchors::<T>::get(&hash).unwrap(), <system::Module<T>>::block_number());
    }
}
