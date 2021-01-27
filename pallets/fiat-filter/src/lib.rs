#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch};
use frame_system::ensure_signed;
use frame_support::{
	// dispatch::{DispatchResultWithPostInfo,PostDispatchInfo},
	weights::{GetDispatchInfo},
	traits::{Get,UnfilteredDispatchable},
	Parameter,
	sp_runtime::Perbill,
};



#[cfg(test)]
mod tests;

/// Handler for updating the DockUsdRate
// #[impl_for_tuples(30)]
pub trait UpdaterDockFiatRate {
    // fn update_dock_usd_rate(who: &AccountId);
	/// Handler for updating the DockUsdRate
	fn update_dock_fiat_rate();
}

/// The pallet's configuration trait
/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Trait: frame_system::Trait {
	/// Because this pallet emits events, it depends on the runtime's definition of an event.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	// type Call: Parameter + UnfilteredDispatchable<Origin = Self::Origin> + GetDispatchInfo;
	type UpdaterDockFiatRate: UpdaterDockFiatRate;
}


pub fn INIT_DOCK_FIAT_RATE() -> Perbill { Perbill::from_fraction(0.02251112) }
// pub const INIT_UPDATE_EVERY_N_BLOCKS: <Trait as frame_system::Trait>::BlockNumber = 10;
pub const INIT_UPDATE_EVERY_N_BLOCKS: u8 = 10;

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
	// A unique name is used to ensure that the pallet's storage items are isolated.
	// This name may be updated, but each pallet in the runtime must use a unique name.
	// ---------------------------------vvvvvvvvvvvvvv
	trait Store for Module<T: Trait> as FiatFilterModule {
		// Learn more about declaring storage items:
		// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
		Something get(fn something): Option<u32>;

		/// price of one DOCK in fiat (for now, only USD)
		pub DockFiatRate get(fn dock_fiat_rate) config(): Perbill = INIT_DOCK_FIAT_RATE();
		// /// price update frequency (in number of blocks)
		// pub UpdateFreq get(fn update_freq) config(): BlockNumber = INIT_UPDATE_EVERY_N_BLOCKS;
		// /// block number of last DockUsdRate update
		// pub LastUpdatedAt get(fn last_updated_at): BlockNumber;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event! {
	pub enum Event<T> where 
		AccountId = <T as frame_system::Trait>::AccountId, // TODO remove bound
		<T as frame_system::Trait>::BlockNumber,
	{
		/// Event documentation should end with an array that provides descriptive names for event
		/// parameters. [something, who]
		SomethingStored(u32, AccountId), // TODO rm

		/// on set_dock_usd_rate executed
		/// event parameters: [new_dock_usd_rate]
        DockUsdRateSet(Perbill),
		/// on root_set_update_freq executed
		/// event parameters: [new_update_frequency_blocks]
        UpdateFreqStored(BlockNumber),
    }
}

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		// type Error = Error<T>;
		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn do_something(origin, something: u32) -> dispatch::DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let who = ensure_signed(origin)?;

			// Update storage.
			Something::put(something);

			// Emit an event.
			Self::deposit_event(RawEvent::SomethingStored(something, who));
			// Return a successful DispatchResult
			Ok(())
		}

		/// An example dispatchable that may throw a custom error.
		#[weight = 10_000 + T::DbWeight::get().reads_writes(1,1)]
		pub fn cause_error(origin) -> dispatch::DispatchResult {
			let _who = ensure_signed(origin)?;

			// Read a value from storage.
			match Something::get() {
				// Return an error if the value has not been set.
				None => Err(Error::<T>::NoneValue)?,
				Some(old) => {
					// Increment the value read from storage; will error in the event of overflow.
					let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
					// Update the value in storage with the incremented result.
					Something::put(new);
					Ok(())
				},
			}
		}
	}
}
