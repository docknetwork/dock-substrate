#![cfg_attr(not(feature = "std"), no_std)]

pub mod multi_key {
    use crate::{
        did::{keys::*, *},
        keys_and_sigs::PublicKey, util::*,
    };
    use core::{convert::identity, fmt::Debug};
    use frame_support::{traits::Get, weights::Weight, *};
    use sp_runtime::DispatchError;
    use sp_std::{convert::TryInto, prelude::*};

    pub fn migrate_unchecked_keys<T: Config + Debug>() -> Weight {
        let mut keys_read = 0;
        let mut keys_written = 0;
        let mut dids_overriden = 0;
        let mut did_controllers_removed = 0;

        DidKeys::translate(|did, _: IncId, key: (PublicKey, u16)| {
            keys_read += 1;
            let key = UncheckedDidKey::new(key.0, VerRelType::try_from(key.1 & 0b1111).unwrap());
            if let Ok(did_key) = key.clone().try_into() {
                Some(did_key)
            } else {
                keys_written += 1;

                if key.ver_rels.intersects(VerRelType::CAPABILITY_INVOCATION) {
                    let _ = Dids::<T>::try_mutate(did, |details| {
                        WithNonce::try_update_opt_without_increasing_nonce_with(
                            details,
                            |did_details| {
                                if let Some(mut did_details) = did_details.as_mut() {
                                    dids_overriden += 1;

                                    did_details.active_controller_keys -= 1;
                                    if did_details.active_controller_keys == 0 {
                                        did_details.active_controllers -= 1;
                                        DidControllers::remove(did, Controller(did));
                                        did_controllers_removed += 1;
                                    }

                                    Ok(())
                                } else {
                                    Err(DispatchError::Other("Invalid DID type"))
                                }
                            },
                        )
                        .ok_or(DispatchError::Other("Invalid DID type"))
                        .and_then(identity)
                    });
                }

                DidKey::new(key.public_key, VerRelType::KEY_AGREEMENT).ok()
            }
        });

        let mut service_endpoints_overriden = 0;
        DidServiceEndpoints::translate_values(|(types, origins): (u16, Vec<WrappedBytes>)| {
            service_endpoints_overriden += 1;

            Some(ServiceEndpoint {
                types: TryFrom::try_from(types & 1).ok()?,
                origins,
            })
        });

        T::DbWeight::get().reads_writes(
            keys_read + dids_overriden + service_endpoints_overriden,
            keys_written + dids_overriden + service_endpoints_overriden + did_controllers_removed,
        )
    }
}
