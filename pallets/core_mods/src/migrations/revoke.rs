#![cfg_attr(not(feature = "std"), no_std)]

pub mod single_key {
    use crate::revoke::*;
    use core::fmt::Debug;
    use frame_support::*;
    use frame_support::{log, pallet_prelude::*};

    pub fn migrate_to_multi_key<T: crate::revoke::Config + Debug>() -> Weight {
        let mut records = 0;

        Registries::translate_values(|(registry, _): (Registry, T::BlockNumber)| {
            records += 1;
            Some(registry)
        });
        log::info!("Migrated {} registries", records);

        T::DbWeight::get().reads_writes(records, records)
    }
}
