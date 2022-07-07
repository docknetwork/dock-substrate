#![cfg_attr(not(feature = "std"), no_std)]

pub mod single_key {
    use crate::{did::*, keys_and_sigs::PublicKey, util::*, StorageVersion};
    use codec::{Decode, Encode};
    use core::fmt::Debug;
    use frame_support::{log, traits::Get, weights::Weight, *};
    use sp_std::prelude::*;

    #[derive(Encode, Decode, Clone, PartialEq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct KeyDetail {
        pub controller: Did,
        pub public_key: PublicKey,
    }

    pub fn migrate_to_multi_key<T: Config + Debug>() -> Weight {
        let mut records = 0;
        let single_key_bbs = crate::bbs_plus::Version::get() == StorageVersion::SingleKey;

        Dids::<T>::translate(|did: Did, record| {
            records += 1;
            let (
                KeyDetail {
                    public_key,
                    controller,
                },
                nonce,
            ) = record;

            let mut key_counter = single_key_bbs
                .then(|| IncId::from(super::super::bbs_plus::single_key::DidCounters::get(did).1))
                .unwrap_or_default();

            DidKeys::insert(
                did,
                key_counter.inc(),
                DidKey::new_with_all_relationships(public_key),
            );
            DidControllers::insert(did, Controller(controller), ());
            let did_details: StoredDidDetails<T> =
                WithNonce::new_with_nonce(OnChainDidDetails::new(key_counter, 1u32, 1u32), nonce)
                    .into();

            Some(did_details)
        });
        log::info!("Migrated {} DIDs", records);

        T::DbWeight::get().reads_writes(1 + records * 2, records * 3 + 1)
    }
}
