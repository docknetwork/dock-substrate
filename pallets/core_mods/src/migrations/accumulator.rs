#![cfg_attr(not(feature = "std"), no_std)]

pub mod single_key {
    use crate::accumulator::*;
    use crate::did::Did;
    use crate::util::*;
    use core::fmt::Debug;
    use frame_support::{decl_module, decl_storage, log, pallet_prelude::*};
    use sp_std::prelude::*;

    decl_storage! {
        trait Store for Module<T: Config> as AccumulatorModule {
            pub DidCounters get(fn did_counters): map hasher(blake2_128_concat) Did => (u32, u32);

            /// Stores latest accumulator as key value: accumulator id -> (created_at, last_updated_at, nonce, Accumulator)
            /// `created_at` is the block number when the accumulator was created and is intended to serve as a starting
            /// point for anyone looking for all updates to the accumulator. `last_updated_at` is the block number when
            /// the last update was sent. `created_at` and `last_updated_at` together indicate which blocks should be
            /// considered for finding accumulator updates.
            /// `nonce` is the an always incrementing number starting at 0 to help with replay protection. Each new
            /// update is supposed to have 1 higher nonce than the current one.
            /// Historical values and updates are persisted as events indexed with the accumulator id. The reason for
            /// not storing past values is to save storage in chain state. Another option could have been to store
            /// block numbers for the updates so that each block from `created_at` doesn't need to be scanned but
            /// even that requires large storage as we expect millions of updates.
            /// Just keeping the latest accumulated value allows for any potential on chain verification as well.
            pub Accumulators get(fn get_accumulator):
                map hasher(blake2_128_concat) AccumulatorId => Option<(T::BlockNumber, T::BlockNumber, u32, Accumulator)>;
        }
    }

    decl_module! {
        pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {}
    }

    pub fn migrate_to_multi_key<T: crate::accumulator::Config + Debug>() -> Weight {
        let did_counters = DidCounters::drain()
            .map(|(did, (params_counter, keys_counter))| {
                crate::accumulator::AccumulatorOwnerCounters::insert(
                    AccumulatorOwner(did),
                    crate::accumulator::StoredAccumulatorOwnerCounters {
                        params_counter: IncId::from(params_counter),
                        key_counter: IncId::from(keys_counter),
                    },
                );
            })
            .count() as u64;
        log::info!("Migrated {} did counters", did_counters);

        let mut accumulators = 0;
        crate::accumulator::Accumulators::<T>::translate_values(
            |(created_at, last_updated_at, _, accumulator): (
                T::BlockNumber,
                T::BlockNumber,
                u32,
                Accumulator,
            )| {
                accumulators += 1;
                let acc = AccumulatorWithUpdateInfo {
                    created_at,
                    last_updated_at,
                    accumulator,
                };

                Some(acc)
            },
        );
        log::info!("Migrated {} accumulators", accumulators);

        T::DbWeight::get()
            .reads_writes(did_counters + accumulators, did_counters * 2 + accumulators)
    }
}
