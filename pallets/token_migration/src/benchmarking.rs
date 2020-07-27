#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::{benchmarks, account};
use system::RawOrigin;
use sp_std::prelude::*;

const SEED: u32 = 0;
const MAX_USER_INDEX: u32 = 1000;

benchmarks! {
        _ {
            // Migrator
            let u in 1 .. MAX_USER_INDEX => ();
            // No of migrations
            let n in 0 .. 15000 => ();
        }

        add_migrator {
            let u in ...;
            let n in ...;

            let migrator: T::AccountId = account("caller", u, SEED);
            // TODO:
        }: _(RawOrigin::Root, migrator.clone(), n as u16)
        verify {
			let value = Migrators::<T>::get(migrator.clone());
			assert!(value.is_some());
			assert_eq!(value.unwrap(), n as u16);
		}
}