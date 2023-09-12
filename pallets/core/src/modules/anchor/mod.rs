//! Minimal proof of existence registry.
//!
//! Anchors are hashed once before being added to storage. To check whether an anchor exists
//! query the "Anchors" map for the hash of the anchor. If a corresponding value exists, then the
//! anchor exists and the value represents the block number when it was first published.

use alloc::vec::Vec;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;
use sp_std::prelude::*;
use weights::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

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
        #[weight = SubstrateWeight::<T>::deploy(data.len() as u32)]
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
        ensure!(Anchors::<T>::get(hash).is_none(), Error::<T>::AnchorExists);

        // execute
        let last_block = <system::Pallet<T>>::block_number();
        Anchors::<T>::insert(hash, last_block);
        Self::deposit_event(Event::<T>::AnchorDeployed(hash, account, last_block));

        Ok(())
    }
}
