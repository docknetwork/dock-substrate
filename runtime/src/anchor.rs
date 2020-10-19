//! Minimal proof of existence registry.

use alloc::vec::Vec;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;

pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// The anchor being posted was already created in a previous block.
        AnchorExists,
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Blob {
        // Hasher can be the identity here becuse we perform a hash ourself which has the same
        // merkle-trie balancing effect as using a hash-prefix map.
        Anchors: map hasher(identity) <T as system::Trait>::Hash =>
            Option<<T as system::Trait>::BlockNumber>;
    }
}

decl_event! {
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
        BlockNumber = <T as system::Trait>::BlockNumber,
        Hash = <T as system::Trait>::Hash,
    {
        /// A new permanent anchor was posted.
        AnchorDeployed(Hash, AccountId, BlockNumber),
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        /// Drop a permanent anchor.
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn deploy(
            origin,
            dat: Vec<u8>,
        ) -> DispatchResult {
            Module::<T>::deploy_(origin, dat)
        }
    }
}

impl<T: Trait> Module<T> {
    fn deploy_(origin: <T as system::Trait>::Origin, dat: Vec<u8>) -> DispatchResult {
        let acct = ensure_signed(origin)?;

        // check
        let h = <T as system::Trait>::Hashing::hash(&dat);
        ensure!(Anchors::<T>::get(&h).is_none(), Error::<T>::AnchorExists);

        // execute
        let bn = <system::Module<T>>::block_number();
        Anchors::<T>::insert(&h, &bn);
        Self::deposit_event(Event::<T>::AnchorDeployed(h, acct, bn));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_common::*;
    type Mod = crate::anchor::Module<Test>;
    use sp_core::H256;

    #[test]
    fn deploy_and_check() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            let h = <Test as system::Trait>::Hashing::hash(&bs);
            assert!(Anchors::<Test>::get(h).is_none());
            Mod::deploy(Origin::signed(ABBA), bs).unwrap();
            assert!(Anchors::<Test>::get(h).is_some());
        });
    }

    #[test]
    fn deploy_twice_error() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            Mod::deploy(Origin::signed(ABBA), bs.clone()).unwrap();
            let err = Mod::deploy(Origin::signed(ABBA), bs).unwrap_err();
            assert_eq!(err, Error::<Test>::AnchorExists.into());
        });
    }

    #[test]
    fn deploy_and_observe_event() {
        ext().execute_with(|| {
            let bs = random_bytes(32);
            let h = <Test as system::Trait>::Hashing::hash(&bs);
            Mod::deploy(Origin::signed(ABBA), bs).unwrap();
            assert_eq!(
                &anchor_events(),
                &[Event::<Test>::AnchorDeployed(
                    h,
                    ABBA,
                    <system::Module<Test>>::block_number()
                )]
            );
        });
    }

    fn anchor_events() -> Vec<Event<Test>> {
        system::Module::<Test>::events()
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
