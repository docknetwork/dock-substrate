#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch};
use frame_system::{self as system, ensure_signed, ensure_root};
use frame_support::{
	ensure,
	// dispatch::{DispatchResultWithPostInfo,PostDispatchInfo},
	weights::{GetDispatchInfo},
	traits::{Get,UnfilteredDispatchable},
	Parameter,
	sp_runtime::{Perbill, DispatchError},
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
	// type BlockNumber: Get<<Self as frame_system::Trait>::BlockNumber>;
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
		// Something get(fn something): Option<u32>;

		/// price of one DOCK in fiat (for now, only USD)
		pub DockFiatRate get(fn dock_fiat_rate) config(): Perbill = INIT_DOCK_FIAT_RATE();
		/// price update frequency (in number of blocks)
		pub UpdateFreq get(fn update_freq) config(): <T as system::Trait>::BlockNumber = 10.into();
		/// block number of last DockUsdRate update
		pub LastUpdatedAt get(fn last_updated_at): <T as system::Trait>::BlockNumber;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event! {
	pub enum Event<T> where 
		// AccountId = <T as frame_system::Trait>::AccountId, // TODO remove bound
		<T as frame_system::Trait>::BlockNumber,
	{
		// /// Event documentation should end with an array that provides descriptive names for event
		// /// parameters. [something, who]
		// SomethingStored(u32, AccountId), // TODO rm

		/// on set_dock_usd_rate executed
		/// event parameters: [new_dock_usd_rate]
        DockFiatRateUpdated(Perbill),
		/// on root_set_update_freq executed
		/// event parameters: [new_update_frequency_blocks]
        UpdateFreqUpdated(BlockNumber),
    }
}

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		// /// UnexpectedOrigin: for instance, dispatchable expects root, finds account
		// BadOrigin,
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

		// /// Set update frequency through Root
        // pub fn root_set_update_freq(origin, next_update_freq: T::BlockNumber) {
        //     let sender= ensure_signed(origin)?; 
        //     ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the update frequency");

        //     UpdateFreq::put(next_update_freq);
        //     Self::deposit_event(RawEvent::UpdateFreqSet(next_update_freq));
        // }

		// /// An example dispatchable that takes a singles value as a parameter, writes the value to
		// /// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn root_set_update_freq(origin, new_update_freq: T::BlockNumber) -> dispatch::DispatchResult {
			// let sender = ensure_signed(origin)?;
			// ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the update frequency");
			ensure_root(origin)?;

			// Update storage.
			UpdateFreq::<T>::put(new_update_freq);

			// Emit an event.
			Self::deposit_event(RawEvent::UpdateFreqUpdated(new_update_freq));
			// Return a successful DispatchResult
			Ok(())
		}

		// /// An example dispatchable that may throw a custom error.
		// #[weight = 10_000 + T::DbWeight::get().reads_writes(1,1)]
		// pub fn cause_error(origin) -> dispatch::DispatchResult {
		// 	let _who = ensure_signed(origin)?;

		// 	// Read a value from storage.
		// 	match Something::get() {
		// 		// Return an error if the value has not been set.
		// 		None => Err(Error::<T>::NoneValue)?,
		// 		Some(old) => {
		// 			// Increment the value read from storage; will error in the event of overflow.
		// 			let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
		// 			// Update the value in storage with the incremented result.
		// 			Something::put(new);
		// 			Ok(())
		// 		},
		// 	}
		// }
	}
}


// private helper functions
impl <T: Trait> Module<T> {
    // fn compute_call_fee_(call: &Box<<T as Trait>::Call>) -> Result<u64, &'static str> {
    //     // TODO get type of call



    //     // match type: get USD price
    //     let fee_usdcent = match call_type {
    //         _ => 50,
    //     };
    //     // convert to DOCKs
    //     // TODO check conversion to f64 and division
    //     let fee_dock: InsertMinimumUnitType = fee_usdcent as f64.checked_div(Self::dock_usd_rate as f64) // TODO safe math and type conversion
    //     // TODO what is minimum unit for DOCKs
    //     .ok_or("checked_div err: Dock usd rate is zero")?;

    //     Ok(fee_dock)
    // }

    // fn charge_fees_(sender: T::AccountId, amount: T::Balance) -> Result {
    //     let _ = <balances::Module<T> as Currency<_>>::withdraw(
    //       &who,
    //       amount,
    //       WithdrawReason::Fee,
    //       ExistenceRequirement::KeepAlive
    //     )?;
    //     Ok(())
    // }

    // fn execute_call_(origin: T::Origin, call: Box<<T as Trait>::Call>) -> DispatchWithCallResult{
    //     let sender = ensure_signed(origin)?;

    //     let dispatch_result = call.clone().dipatch(sender);

    //     // Log event for success or failure of execution
    //     match dispatch_result {
    //         Ok(post_dispatch_info) => {
    //             Self::deposit_event(RawEvent::Executed(authors, proposal));
    //             Ok(PostDispatchInfo {
    //                 actual_weight: actual_weight(post_dispatch_info),
    //                 pays_fee: post_dispatch_info.pays_fee, // TODO pay no fee, already withdrawn
    //             })
    //         }
    //         Err(e) => {
    //             Self::deposit_event(RawEvent::ExecutionFailed(authors, proposal, e.error));
    //             Err(DispatchErrorWithPostInfo {
    //                 post_info: PostDispatchInfo {
    //                     actual_weight: actual_weight(e.post_info),
    //                     pays_fee: e.post_info.pays_fee,
    //                 },
    //                 error: e.error,
    //             })
    //         }
    //     }
    // }

    // /// update the dock_usd_rate
    // pub fn set_dock_usd_rate(origin, value: u64) -> DispatchResultWithPostInfo {
    //     let sender= ensure_signed(origin)?;   

    //     ////////////////
    //     // TODO check that it's the price fedd contract that is updating the value

    //     DockUsdRate::put(value);
    //     Self::deposit_event(RawEvent::DockUsdRateSet(value));
    // }
}
