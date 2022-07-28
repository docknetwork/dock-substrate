#![cfg_attr(not(feature = "std"), no_std)]

pub mod single_key {
    use crate::{bbs_plus, bbs_plus::Config, did::Did, util::*};
    use core::fmt::Debug;
    use frame_support::{decl_module, decl_storage, log, pallet_prelude::*};
    use sp_std::{collections::btree_map::BTreeMap, prelude::*};

    decl_storage! {
        trait Store for Module<T: Config> as BBSPlusModule {
            /// Pair of counters where each is used to assign unique id to parameters and public keys
            /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
            /// the counters don't decrease on removal
            pub DidCounters get(fn did_counters):
                map hasher(blake2_128_concat) Did => (u32, u32);

            /// Public keys are stored as key value (did, counter) -> public key
            /// Its assumed that the public keys are always members of G2. It does impact any logic on the
            /// chain but makes up for one less storage value
            pub BbsPlusKeys get(fn get_key):
                double_map hasher(blake2_128_concat) Did, hasher(identity) u32 => Option<bbs_plus::BBSPlusPublicKey>;
        }
    }

    decl_module! {
        pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {}
    }

    pub fn migrate_to_multi_key<T: crate::bbs_plus::Config + Debug>() -> Weight {
        let records = DidCounters::drain()
            .map(|(did, (params, _))| {
                crate::bbs_plus::ParamsCounter::insert(
                    bbs_plus::BBSPlusParamsOwner(did),
                    IncId::from(params),
                );
            })
            .count() as u64;
        log::info!("Migrated {} params counters", records);

        // Need to update the keys of the double map `BbsPlusKeys`. But cannot drain and update the map
        // at the same time so creating a temporary location to hold the drained data first.
        let mut temp = BTreeMap::new();
        for (did, key_id, k) in BbsPlusKeys::drain() {
            temp.insert((did, key_id + 1), k);
        }
        let count_keys = temp.len() as u64;
        for ((did, key_id), k) in temp.into_iter() {
            bbs_plus::BbsPlusKeys::insert(did, IncId::from(key_id as u32), k);
        }

        log::info!("Migrated {} BBS+ keys", count_keys);
        T::DbWeight::get().reads_writes(records + count_keys, (records + count_keys) * 2)
    }
}
