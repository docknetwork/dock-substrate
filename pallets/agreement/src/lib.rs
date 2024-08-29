//! Provides the functionality to notify about the agreement concluded by majority of system participants.

#![cfg_attr(not(feature = "std"), no_std)]

use scale_info::prelude::string::String;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type Event: From<Event> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Attempting to emit an empty agreement.
        Empty,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Declares an agreement recognized by the majority of system participants.
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn agree(origin: OriginFor<T>, on: String, url: Option<String>) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                !on.is_empty() && !url.as_ref().map_or(false, String::is_empty),
                Error::<T>::Empty
            );

            Self::deposit_event(Event::Agreed { on, url });
            Ok(())
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        /// Defines an agreement concluded by majority of system participants.
        Agreed { on: String, url: Option<String> },
    }
}
