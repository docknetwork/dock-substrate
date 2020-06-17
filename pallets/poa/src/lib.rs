#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch,
                    ensure, fail, traits::Get, sp_runtime::{print, SaturatedConversion} };
use frame_system::{self as system, ensure_signed, ensure_root};
use sp_std::prelude::Vec;


/// The pallet's configuration trait.
pub trait Trait: system::Trait + pallet_session::Trait {
    // Add other types and constants required to configure this pallet.

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    type MinSessionLength: Get<u32>;

    type MaxActiveValidators: Get<u8>;
}

// This pallet's storage items.
decl_storage! {
	// It is important to update your storage name so that your pallet's
	// storage items are isolated from other pallets.
	trait Store for Module<T: Trait> as PoAModule {
		CurrentValidators get(fn current_validators) config(): Vec<T::AccountId>;

		//NextSessionChangeAt get(fn next_session_change_at) config(): u32;
		NextSessionChangeAt get(fn next_session_change_at) config(): T::BlockNumber;

        ForceSessionChange get(fn force_session_change) config(): bool;

		QueuedValidators get(fn validators_to_add): Vec<T::AccountId>;

		RemoveValidators get(fn validators_to_remove): Vec<T::AccountId>;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		// New validator added in front of queue.
		ValidatorQueuedInFront(AccountId),

		// New validator added at back of queue.
		ValidatorQueued(AccountId),

		// Validator removed.
		ValidatorRemoved(AccountId),
	}
);

// The pallet's errors
decl_error! {
	/// Errors for the module.
	pub enum Error for Module<T: Trait> {
	    MaxValidators,
	    AlreadyQueuedForAddition,
	    AlreadyQueuedForRemoval,
		NoValidators,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Initializing errors
		// this includes information about your errors in the node's metadata.
		// it is needed only if you are using errors in your pallet
		type Error = Error<T>;

		// Initializing events
		// this is needed only if you are using events in your pallet
		fn deposit_event() = default;

        // Weight can be 0 as its called by Master
        // TODO: Use signed extension to make it free
		#[weight = 0]
		pub fn add_validator(origin, validator_id: T::AccountId, force: bool) -> dispatch::DispatchResult {
		    // TODO: Check the origin is Master
			ensure_root(origin)?;
            print("add_validator called");

            if force {
                if (Self::current_validators().len() - Self::validators_to_remove().len()) >= T::MaxActiveValidators::get().into() {
                    fail!(Error::<T>::MaxValidators)
                } else {
                    let mut validators = Self::validators_to_add();
                    // Remove all occurences of validator_id from queue
                    Self::remove_validator_id(&validator_id, &mut validators);
                    print("Adding a new validator at front");
                    // The new validator should be in front of the queue
			        validators.insert(0, validator_id.clone());
			        <QueuedValidators<T>>::put(validators);
			        Self::deposit_event(RawEvent::ValidatorQueuedInFront(validator_id));
			        // <pallet_session::Module<T>>::rotate_session();
			        ForceSessionChange::put(true);
                }
            } else {
                let mut validators = Self::validators_to_remove();
                for v in validators.iter() {
                    if *v == validator_id {
                        fail!(Error::<T>::AlreadyQueuedForAddition)
                    }
                }
                print("Adding a new validator at back");
                // The new validator should be at the back of the queue
                validators.push(validator_id.clone());
                <QueuedValidators<T>>::put(validators);
                Self::deposit_event(RawEvent::ValidatorQueued(validator_id));
            }
			Ok(())
		}

        // Weight can be 0 as its called by Master
        // TODO: Use signed extension to make it free
		#[weight = 0]
		pub fn remove_validator(origin, validator_id: T::AccountId, force: bool) -> dispatch::DispatchResult {
		    // TODO: Check the origin is Master
			ensure_root(origin)?;

            let mut already_queued_for_rem = false;
            let mut validators = Self::validators_to_remove();
            for v in validators.iter() {
                if *v == validator_id {
                    if force {
                        already_queued_for_rem = true
                    } else {
                        fail!(Error::<T>::AlreadyQueuedForRemoval)
                    }
                }
            }

            if !already_queued_for_rem {
                validators.push(validator_id.clone());
                <RemoveValidators<T>>::put(validators);
            }

            if force {
                ForceSessionChange::put(true);
            }
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
    /// Returns number of removed occurences
    fn remove_validator_id(id: &T::AccountId, validators: &mut Vec<T::AccountId>) -> usize {
        // Collect indices to remove in decreasing order
        let mut indices = Vec::new();
        for (i, v) in validators.iter().enumerate() {
            if v == id {
                indices.insert(0, i);
            }
        }
        for i in &indices {
            validators.remove(*i);
        }
        indices.len()
    }
}

/// Indicates to the session module if the session should be rotated.
/// We set this flag to true when we add/remove a validator.
impl<T: Trait> pallet_session::ShouldEndSession<T::BlockNumber> for Module<T> {
    fn should_end_session(_now: T::BlockNumber) -> bool {
        print("Called should_end_session");

        let current_block_no = <system::Module<T>>::block_number().saturated_into::<u32>();
        let session_ends_at = Self::next_session_change_at().saturated_into::<u32>();
        print("current_block_no");
        print(current_block_no.saturated_into::<u32>());
        print("session_ends_at");
        print(session_ends_at);

        // TODO: Remove once sure the following panic is never triggered
        if current_block_no > session_ends_at {
            panic!("Current block number > session_ends_at");
        }
        if Self::force_session_change() || (current_block_no == session_ends_at) {
            let mut current_validators = Self::current_validators();
            let mut validators_to_add = Self::validators_to_add();

            let mut current_validators_changed = false;

            if (current_validators.len() + validators_to_add.len()) > 0 {
                // The size of the 3 vectors is ~15 so multiple iterations are ok.
                // If they were bigger, `validators_to_remove` should be turned into a set and then
                // iterate over `validators_to_add` and `current_validators` only once removing any id
                // present in the set.
                let validators_to_remove = <RemoveValidators<T>>::take();
                for v in validators_to_remove {
                    Self::remove_validator_id(&v, &mut validators_to_add);
                    let removed_active = Self::remove_validator_id(&v, &mut current_validators);
                    if removed_active > 0 {
                        current_validators_changed = true;
                    }
                }

                let max_validators = T::MaxActiveValidators::get() as usize;
                while (current_validators.len() < max_validators) && (validators_to_add.len() > 0) {
                    current_validators_changed = true;
                    current_validators.push(validators_to_add.remove(0));
                }

                <QueuedValidators<T>>::put(validators_to_add);
                <CurrentValidators<T>>::put(current_validators.clone());
                if current_validators_changed {
                    print("Active validator set changed, rotating session");
                    <pallet_session::Module<T>>::rotate_session();
                }
            }

            let min_session_len = T::MinSessionLength::get();
            let rem = min_session_len % current_validators.len() as u32;
            let session_len = if rem == 0 {
                min_session_len
            } else {
                min_session_len + current_validators.len() as u32 - rem
            };
            let next_session_at = current_block_no + session_len;
            print("next session at");
            print(next_session_at);
            <NextSessionChangeAt<T>>::put(T::BlockNumber::from(next_session_at));
            ForceSessionChange::put(false);
            true
        } else {
            false
        }
    }
}

/// Provides the new set of validators to the session module when session is being rotated.
impl<T: Trait> pallet_session::SessionManager<T::AccountId> for Module<T> {
    // SessionIndex is u32 but comes from sp_staking pallet. Since staking is not needed for now, not
    // importing the pallet.

    fn new_session(_: u32) -> Option<Vec<T::AccountId>> {
        // Flag is set to false so that the session doesn't keep rotating.
        //Flag::put(false);
        print("Called new_session");
        let validators = Self::current_validators();
        // Check for error on empty validator set
        if validators.len() == 0 { None } else { Some(validators) }
    }

    fn end_session(_: u32) {}
    fn start_session(_: u32) {}
}
