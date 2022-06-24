#![cfg_attr(not(feature = "std"), no_std)]

pub mod single_key {
    use crate::bbs_plus::*;
    use crate::did::Did;
    use crate::util::*;
    use core::fmt::Debug;
    use frame_support::{decl_module, decl_storage, log, pallet_prelude::*};
    use sp_std::prelude::*;

    decl_storage! {
        trait Store for Module<T: Config> as BBSPlusModule {
            /// Pair of counters where each is used to assign unique id to parameters and public keys
            /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
            /// the counters don't decrease on removal
            pub DidCounters get(fn did_counters):
                map hasher(blake2_128_concat) Did => (u32, u32);
        }
    }

    decl_module! {
        pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {}
    }

    pub fn migrate_to_multi_key<T: crate::bbs_plus::Config + Debug>() -> Weight {
        let records = DidCounters::drain()
            .map(|(did, (params, _))| {
                crate::bbs_plus::ParamsCounter::insert(
                    BBSPlusParamsOwner(did),
                    IncId::from(params),
                );
            })
            .count() as u64;
        log::info!("Migrated {} params counters", records);

        T::DbWeight::get().reads_writes(records, records * 2)
    }
}
