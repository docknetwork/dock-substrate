#![cfg_attr(not(feature = "std"), no_std)]

pub mod multi_key {
    use crate::{
        bbs_plus::BbsPlusKeys,
        did::{keys::*, *},
        keys_and_sigs::PublicKey,
        util::*,
    };
    use alloc::collections::BTreeSet;
    use core::{convert::identity, fmt::Debug};
    use frame_support::{log, traits::Get, weights::Weight, *};
    use sp_runtime::DispatchError;
    use sp_std::{convert::TryInto, prelude::*};

    pub fn migrate_unchecked_keys<T: Config + Debug>() -> Weight {
        let mut did_keys_overridden = 0;
        let mut dids_read = 0;
        let mut dids_written = 0;
        let mut did_controllers_removed = 0;

        DidKeys::translate(|did, _: IncId, key: (PublicKey, u16)| {
            did_keys_overridden += 1;
            // Migrate verification relationships to use only significant bits
            let key = UncheckedDidKey::new(key.0, VerRelType::try_from(key.1 & 0b1111).ok()?);

            if let Ok(did_key) = key.clone().try_into() {
                Some(did_key)
            } else {
                // Remove inappropriate controller keys and controllers which use them
                if key.ver_rels.intersects(VerRelType::CAPABILITY_INVOCATION) {
                    let _ = Dids::<T>::try_mutate(did, |details| {
                        dids_read += 1;

                        WithNonce::try_update_opt_without_increasing_nonce_with(
                            details,
                            |did_details| {
                                if let Some(mut did_details) = did_details.as_mut() {
                                    dids_written += 1;

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

        let mut service_endpoints_overridden = 0;
        // Migrate service endpoint types to use only significant bits
        DidServiceEndpoints::translate_values(|(types, origins): (u16, Vec<WrappedBytes>)| {
            service_endpoints_overridden += 1;

            Some(ServiceEndpoint {
                types: TryFrom::try_from(types & 1).ok()?,
                origins,
            })
        });

        // Remove outdated BBS+ keys
        let mut bbs_keys_read = 0;
        let mut removed_dids = BTreeSet::new();
        for (did, _) in BbsPlusKeys::iter_keys() {
            bbs_keys_read += 1;
            if !removed_dids.contains(&did)
                && !{
                    dids_read += 1;
                    Dids::<T>::contains_key(did)
                }
            {
                removed_dids.insert(did);
            }
        }
        let mut bbs_keys_removed = 0;
        for did in removed_dids.into_iter() {
            bbs_keys_removed += BbsPlusKeys::clear_prefix(did, u32::MAX, None).unique as u64;
        }

        log::info!(
            "Did keys overridden: {}, dids read/written: {}/{}, service endpoints overridden: {}, did controllers removed: {}, bbs+ keys read/removed: {}/{}", 
            did_keys_overridden,
            dids_read,
            dids_written,
            service_endpoints_overridden,
            did_controllers_removed,
            bbs_keys_read,
            bbs_keys_removed
        );

        T::DbWeight::get().reads_writes(
            did_keys_overridden
                + dids_read
                + service_endpoints_overridden
                + bbs_keys_read
                + bbs_keys_removed,
            did_keys_overridden
                + dids_written
                + service_endpoints_overridden
                + did_controllers_removed
                + bbs_keys_removed,
        )
    }
}
