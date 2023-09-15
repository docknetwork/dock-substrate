//! Minimal proof of existence registry.
//!
//! Anchors are hashed once before being added to storage. To check whether an anchor exists
//! query the "Anchors" map for the hash of the anchor. If a corresponding value exists, then the
//! anchor exists and the value represents the block number when it was first published.

use alloc::vec::Vec;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;
use weights::*;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_core::Hasher;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The anchor being posted was already created in a previous block.
        AnchorExists,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new permanent anchor was posted.
        AnchorDeployed(T::Hash, T::AccountId, T::BlockNumber),
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Anchors<T: Config> = StorageMap<_, Identity, T::Hash, T::BlockNumber>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Drop a permanent anchor.
        #[pallet::weight(SubstrateWeight::<T>::deploy(data.len() as u32))]
        pub fn deploy(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
            let account = ensure_signed(origin)?;

            Pallet::<T>::deploy_(data, account)
        }
    }

    impl<T: Config> Pallet<T> {
        fn deploy_(data: Vec<u8>, account: T::AccountId) -> DispatchResult {
            // check
            let hash = <T as frame_system::Config>::Hashing::hash(&data);
            ensure!(Anchors::<T>::get(hash).is_none(), Error::<T>::AnchorExists);

            // execute
            let last_block = <frame_system::Pallet<T>>::block_number();
            Anchors::<T>::insert(hash, last_block);
            Self::deposit_event(Event::<T>::AnchorDeployed(hash, account, last_block));

            Ok(())
        }
    }
}
