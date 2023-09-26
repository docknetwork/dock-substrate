use super::*;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_runtime::traits::Hash;
#[cfg(not(feature = "std"))]
use sp_std::prelude::*;

const MAX_LEN: u32 = 10_000;

benchmarks! {
    where_clause { where T: sp_std::fmt::Debug }

    deploy {
        let l in 0 .. MAX_LEN => ();

        let caller = whitelisted_caller();
        let data = vec![0; l as usize];

    }: deploy(RawOrigin::Signed(caller), data.clone())
    verify {
        let hash = <<T as frame_system::Config>::Hashing as Hash>::hash(&data);
        assert_eq!(Anchors::<T>::get(&hash).unwrap(), <frame_system::Pallet<T>>::block_number());
    }
}
