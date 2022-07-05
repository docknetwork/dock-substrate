//! Minimal proof of existence registry.
//!
//! Anchors are hashed once before being added to storage. To check whether an anchor exists
//! query the "Anchors" map for the hash of the anchor. If a corresponding value exists, then the
//! anchor exists and the value represents the block number when it was first published.

use alloc::vec::Vec;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;

pub trait Config: system::Config {
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;
}

decl_error! {
    pub enum Error for Module<T: Config> {
        /// The anchor being posted was already created in a previous block.
        AnchorExists,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Anchor {
        // Hasher can be the identity here becuse we perform a hash ourself which has the same
        // merkle-trie balancing effect as using a hash-prefix map.
        Anchors: map hasher(identity) <T as system::Config>::Hash =>
            Option<<T as system::Config>::BlockNumber>;
    }
}

decl_event! {
    pub enum Event<T>
    where
        AccountId = <T as system::Config>::AccountId,
        BlockNumber = <T as system::Config>::BlockNumber,
        Hash = <T as system::Config>::Hash,
    {
        /// A new permanent anchor was posted.
        AnchorDeployed(Hash, AccountId, BlockNumber),
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        /// Drop a permanent anchor.
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn deploy(
            origin,
            data: Vec<u8>,
        ) -> DispatchResult {
            let account = ensure_signed(origin)?;

            Module::<T>::deploy_(data, account)
        }
    }
}

impl<T: Config> Module<T> {
    fn deploy_(data: Vec<u8>, account: T::AccountId) -> DispatchResult {
        // check
        let hash = <T as system::Config>::Hashing::hash(&data);
        ensure!(Anchors::<T>::get(&hash).is_none(), Error::<T>::AnchorExists);

        // execute
        let last_block = <system::Module<T>>::block_number();
        Anchors::<T>::insert(&hash, &last_block);
        Self::deposit_event(Event::<T>::AnchorDeployed(hash, account, last_block));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Anchors, Error, Event};
    use frame_support::StorageMap;
    use frame_system as system;
    use sp_runtime::traits::Hash;

    use crate::test_common::*;
    use sp_core::H256;

    #[test]
    fn deploy_and_check() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            let h = <Test as system::Config>::Hashing::hash(&bs);
            assert!(Anchors::<Test>::get(h).is_none());
            AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap();
            assert!(Anchors::<Test>::get(h).is_some());
        });
    }

    #[test]
    fn deploy_twice_error() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            AnchorMod::deploy(Origin::signed(ABBA), bs.clone()).unwrap();
            let err = AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap_err();
            assert_eq!(err, Error::<Test>::AnchorExists.into());
        });
    }

    #[test]
    fn deploy_and_observe_event() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            let h = <Test as system::Config>::Hashing::hash(&bs);
            AnchorMod::deploy(Origin::signed(ABBA), bs).unwrap();
            assert_eq!(
                &anchor_events(),
                &[Event::<Test>::AnchorDeployed(
                    h,
                    ABBA,
                    System::block_number()
                )]
            );
        });
    }

    fn anchor_events() -> Vec<Event<Test>> {
        System::events()
            .iter()
            .filter_map(|event_record| {
                let system::EventRecord::<TestEvent, H256> {
                    phase,
                    event,
                    topics,
                } = event_record;
                assert_eq!(phase, &system::Phase::Initialization);
                assert_eq!(topics, &vec![]);
                match event {
                    TestEvent::Anchor(e) => Some(e.clone()),
                    _ => None,
                }
            })
            .collect()
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks {
    use super::*;
    use crate::did::{Did, DidKey, DidSignature};
    use crate::keys_and_sigs::*;
    use crate::util::IncId;
    use crate::ToStateChange;
    use alloc::collections::BTreeSet;
    use core::iter::repeat;
    use frame_benchmarking::{benchmarks, whitelisted_caller};
    use sp_application_crypto::Pair;
    use sp_core::{ecdsa, ed25519, sr25519};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const MAX_ENTITY_AMOUNT: u32 = 1000;
    const MAX_LEN: u32 = 10_000;
    const SEED: u32 = 0;

    benchmarks! {
        where_clause { where T: core::fmt::Debug }

        deploy {
            let l in 0 .. MAX_LEN => ();

            let caller = whitelisted_caller();
            let data = vec![0; l as usize];

        }: deploy(RawOrigin::Signed(caller), data.clone())
        verify {
            let hash = <T as system::Config>::Hashing::hash(&data);
            assert_eq!(Anchors::<T>::get(&hash).unwrap(), <system::Module<T>>::block_number());
        }
    }
}
