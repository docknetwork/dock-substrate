#![cfg_attr(not(feature = "std"), no_std)]

use super::*;

pub mod single_key {
    use super::*;
    use codec::{Decode, Encode};
    use frame_support::log;
    use frame_support::weights::Weight;
    use sp_std::prelude::*;

    #[derive(Encode, Decode, Clone, PartialEq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct KeyDetail {
        pub controller: Did,
        pub public_key: PublicKey,
    }

    decl_storage! {
        trait Store for Module<T: Config> as DIDModule {
            pub Dids get(fn did): map hasher(blake2_128_concat) Did => Option<(KeyDetail, T::BlockNumber)>;
        }
    }

    decl_module! {
        pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {}
    }

    pub fn migrate_to_multi_key<T: super::Config + Debug>() -> Weight {
        let mut records = 0;

        for (did, value) in Dids::<T>::drain() {
            records += 1;
            let (
                KeyDetail {
                    public_key,
                    controller,
                },
                nonce,
            ) = value;

            let mut last_key_id = super::IncId::new();
            super::DidKeys::insert(
                did,
                last_key_id.inc(),
                super::keys::DidKey::new_with_all_relationships(public_key),
            );
            super::DidControllers::insert(did, Controller(controller), ());
            let did_details: super::StoredDidDetails<T> = WithNonce {
                data: OnChainDidDetails::new(last_key_id, 1u8, 1u8),
                nonce,
            }
            .into();

            super::Dids::insert(did, did_details);
        }
        log::info!("Migrated {} DIDs", records);

        T::DbWeight::get().reads_writes(records, records * 3 + 1)
    }
}
