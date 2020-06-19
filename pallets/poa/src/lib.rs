#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch,
                    ensure, fail, traits::Get, sp_runtime::{print, SaturatedConversion} };
use frame_system::{self as system, ensure_root};
use sp_std::prelude::Vec;

extern crate alloc;
use alloc::collections::BTreeSet;

/// The pallet's configuration trait.
pub trait Trait: system::Trait + pallet_session::Trait {
    // Add other types and constants required to configure this pallet.

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    type MinEpochLength: Get<u32>;

    type MaxActiveValidators: Get<u8>;
}

// This pallet's storage items.
decl_storage! {
	// It is important to update your storage name so that your pallet's
	// storage items are isolated from other pallets.
	trait Store for Module<T: Trait> as PoAModule {
		ActiveValidators get(fn active_validators) config(): Vec<T::AccountId>;

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
	    AlreadyActiveValidator,
	    AlreadyQueuedForAddition,
	    AlreadyQueuedForRemoval,
		NoValidators,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
	    // Do maximum of the work in functions to `add_validator` or `remove_validator` and minimize the work in
	    // `should_end_session` since that it called more frequentily.

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

            // Check if the validator is not already present as an active one
            let active_validators = Self::active_validators();
            for v in active_validators.iter() {
                if *v == validator_id {
                    fail!(Error::<T>::AlreadyActiveValidator)
                }
            }
            if force {
                // The new validator should be added in front of the queue if its not present
                // in the queue else move it front of the queue
                let mut validators = Self::validators_to_add();
                // Remove all occurences of validator_id from queue
                Self::remove_validator_id(&validator_id, &mut validators);
                print("Adding a new validator at front");
                // The new validator should be in front of the queue
                validators.insert(0, validator_id.clone());
                <QueuedValidators<T>>::put(validators);
                Self::deposit_event(RawEvent::ValidatorQueuedInFront(validator_id));
                ForceSessionChange::put(true);
            } else {
                let mut validators = Self::validators_to_add();
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

            let mut validators_to_remove: Vec<T::AccountId> = Self::validators_to_remove();
            let mut removals = BTreeSet::new();
            for v in validators_to_remove.iter() {
                removals.insert(v);
            }

            let already_queued_for_rem = if removals.contains(&validator_id) {
                if force {
                    true
                } else {
                    // throw error since validator is already queued for removal
                    fail!(Error::<T>::AlreadyQueuedForRemoval)
                }
            } else {
                removals.insert(&validator_id);
                false
            };

            let active_validators: Vec<T::AccountId> = Self::active_validators().into();
            let validators_to_add: Vec<T::AccountId> = Self::validators_to_add().into();

            // Construct a set of potential validators and don't allow all the potential validators
            // to be removed as that will prevent the node from starting.
            // This takes away the ability of do a remove before an add but should not matter.
            let mut potential_new_vals = BTreeSet::new();
            for v in active_validators.iter() {
                potential_new_vals.insert(v);
            }
            for v in validators_to_add.iter() {
                potential_new_vals.insert(v);
            }

            // There should be at least 1 id in potential_new_vals that is not in removals
            let diff: Vec<_> = potential_new_vals.difference(&removals).collect();
            if diff.is_empty() {
                print("Cannot remove. Need at least 1 active validator");
                fail!(Error::<T>::NoValidators)
            }

            // Add validator
            if !already_queued_for_rem {
                validators_to_remove.push(validator_id.clone());
                <RemoveValidators<T>>::put(validators_to_remove);
                Self::deposit_event(RawEvent::ValidatorRemoved(validator_id));
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
            let mut active_validators = Self::active_validators();
            let mut validators_to_add = Self::validators_to_add();
            // Remove any validators that need to be removed.
            let validators_to_remove = <RemoveValidators<T>>::take();

            let mut active_validator_set_changed = false;

            // If any validator is to be added or removed
            if (validators_to_remove.len() > 0 ) || (validators_to_add.len() > 0) {
                // The size of the 3 vectors is ~15 so multiple iterations are ok.
                // If they were bigger, `validators_to_remove` should be turned into a set and then
                // iterate over `validators_to_add` and `active_validators` only once removing any id
                // present in the set.
                for v in validators_to_remove {
                    let removed_active = Self::remove_validator_id(&v, &mut active_validators);
                    if removed_active > 0 {
                        active_validator_set_changed = true;
                    } else {
                        // The `add_validator` ensures that a validator id cannot be part of both active
                        // validator set and queued validators
                        Self::remove_validator_id(&v, &mut validators_to_add);
                    }
                }

                let max_validators = T::MaxActiveValidators::get() as usize;

                // TODO: Remove debugging variable below
                let mut count_added = 0u32;

                while (active_validators.len() < max_validators) && (validators_to_add.len() > 0) {
                    active_validator_set_changed = true;
                    active_validators.push(validators_to_add.remove(0));
                    count_added += 1;
                }

                <QueuedValidators<T>>::put(validators_to_add);
                if active_validator_set_changed {
                    print("Active validator set changed, rotating session");
                    print(count_added);
                    <ActiveValidators<T>>::put(active_validators.clone());
                    <pallet_session::Module<T>>::rotate_session();
                }
            }

            let min_session_len = T::MinEpochLength::get();
            let rem = min_session_len % active_validators.len() as u32;
            let session_len = if rem == 0 {
                min_session_len
            } else {
                min_session_len + active_validators.len() as u32 - rem
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
        print("Called new_session");
        let validators = Self::active_validators();
        // Check for error on empty validator set. On returning None, it loads validator set from genesis
        if validators.len() == 0 { None } else { Some(validators) }
    }

    fn end_session(_: u32) {}
    fn start_session(_: u32) {}
}
