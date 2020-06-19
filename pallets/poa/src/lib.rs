#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch,
                    fail, traits::Get, sp_runtime::{print, SaturatedConversion} };
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

	trait Store for Module<T: Trait> as PoAModule {
	    /// List of active validators. Maximum allowed are `MaxActiveValidators`
		ActiveValidators get(fn active_validators) config(): Vec<T::AccountId>;

        /// Next epoch will begin after this block number, i.e. this block number will be the last
        /// block of the current epoch
		NextEpochChangeAfter get(fn next_epoch_begins_after) config(): T::BlockNumber;

        /// Boolean flag to force session change. This will disregard block number in NextEpochChangeAfter
        ForceSessionChange get(fn force_session_change) config(): bool;

        /// Queue of validators to become part of the active validators. Validators can be added either
        /// to the back of the queue or front by passing a flag in the add method.
        /// On epoch end or immediately if forced, validators from the queue are taken out in FIFO order
        /// and added to the active validators unless the number of active validators reaches the max allowed.
		QueuedValidators get(fn validators_to_add): Vec<T::AccountId>;

        /// List to hold validators to remove either on the end of epoch or immediately. If a candidate validator
        /// is queued for becoming an active validator but also present in the removal list, it will
        /// not become active as this list takes precedence of queued validators. It is emptied on each
        /// epoch end
		RemoveValidators get(fn validators_to_remove): Vec<T::AccountId>;

        /// Set when a hot swap is to be performed, replacing validator id as 1st element of tuple
        /// with the 2nd one.
		HotSwap get(fn hot_swap): Option<(T::AccountId, T::AccountId)>
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
		NeedAtLeast1Validator,
		SwapOutFailed,
		SwapInFailed,
	}
}

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

        /// Add a new validator to active validator set unless already a validator and the total number
        /// of validators don't exceed the max allowed count. The validator is considered for adding at
        /// the end of this epoch unless `add_now` is true. If a validator is already added to the queue
        /// an error will be thrown unless `add_now` is true, in which case it swallows the error.
        // Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
		#[weight = 0]
		pub fn add_validator(origin, validator_id: T::AccountId, add_now: bool) -> dispatch::DispatchResult {
		    // TODO: Check the origin is Master
			ensure_root(origin)?;

            // Check if the validator is not already present as an active one
            let active_validators = Self::active_validators();
            for v in active_validators.iter() {
                if *v == validator_id {
                    fail!(Error::<T>::AlreadyActiveValidator)
                }
            }
            if add_now {
                // The new validator should be added in front of the queue if its not present
                // in the queue else move it front of the queue
                let mut validators = Self::validators_to_add();
                // Remove all occurences of validator_id from queue
                Self::remove_validator_id(&validator_id, &mut validators);
                print("Adding a new validator at front");

                // The new validator should be in front of the queue so that it definitely
                // gets added to the active validator set (unless already maximum validators present
                // or the same validator is added for removal)
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

        /// Remove the given validator from active validator set and the queued validators at the end
        /// of epoch unless `remove_now` is true. If validator is already queued for removal, an error
        /// will be thrown unless `remove_now` is true, in which case it swallows the error.
        /// It will not remove the validator if the removal will cause the active validator set to
        /// be empty even after considering the queued validators.
        // Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
		#[weight = 0]
		pub fn remove_validator(origin, validator_id: T::AccountId, remove_now: bool) -> dispatch::DispatchResult {
		    // TODO: Check the origin is Master
			ensure_root(origin)?;

            let mut validators_to_remove: Vec<T::AccountId> = Self::validators_to_remove();
            // Form a set of validators to remove
            let mut removals = BTreeSet::new();
            for v in validators_to_remove.iter() {
                removals.insert(v);
            }

            // Check if already queued for removal
            let already_queued_for_rem = if removals.contains(&validator_id) {
                if remove_now {
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
                fail!(Error::<T>::NeedAtLeast1Validator)
            }

            // Add validator
            if !already_queued_for_rem {
                validators_to_remove.push(validator_id.clone());
                <RemoveValidators<T>>::put(validators_to_remove);
                Self::deposit_event(RawEvent::ValidatorRemoved(validator_id));
            }

            if remove_now {
                ForceSessionChange::put(true);
            }
			Ok(())
		}

        /// Replace an active validator (`old_validator_id`) with a new validator (`new_validator_id`)
        /// without waiting for epoch to end. Throws error if `old_validator_id` is not active or
        /// `new_validator_id` is already active. Also useful when a validator wants to rotate his account.
		// Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
		#[weight = 0]
		pub fn swap_validator(origin, old_validator_id: T::AccountId, new_validator_id: T::AccountId) -> dispatch::DispatchResult {
		    // TODO: Check the origin is Master
			ensure_root(origin)?;

            let active_validators: Vec<T::AccountId> = Self::active_validators().into();

            let mut found = false;
            for v in active_validators.iter() {
                if *v == new_validator_id {
                    print("New validator to swap in already present");
                    fail!(Error::<T>::SwapInFailed)
                }
                if *v == old_validator_id {
                    found = true;
                    break;
                }
            }

            if !found {
                print("Validator to swap out not present");
                fail!(Error::<T>::SwapOutFailed)
            }

            <HotSwap<T>>::put((old_validator_id, new_validator_id));
            Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
    /// Takes a validator id and a mutable vector of validator ids and remove any occurrence from
    /// the mutable vector. Returns number of removed occurrences
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

    /// Update active validator set if needed and return if the active validator set changed and the
    /// count of the new active validators.
    fn update_active_validators_if_needed() -> (bool, u32) {
        let mut active_validators = Self::active_validators();
        let mut validators_to_add = Self::validators_to_add();
        // Remove any validators that need to be removed.
        let validators_to_remove = <RemoveValidators<T>>::take();

        let mut active_validator_set_changed = false;
        let mut queued_validator_set_changed = false;

        // If any validator is to be added or removed
        if (validators_to_remove.len() > 0 ) || (validators_to_add.len() > 0) {
            // TODO: Remove debugging variable below
            let mut count_removed = 0u32;

            // Remove the validators from active validator set or the queue.
            // The size of the 3 vectors is ~15 so multiple iterations are ok.
            // If they were bigger, `validators_to_remove` should be turned into a set and then
            // iterate over `validators_to_add` and `active_validators` only once removing any id
            // present in the set.
            for v in validators_to_remove {
                let removed_active = Self::remove_validator_id(&v, &mut active_validators);
                if removed_active > 0 {
                    active_validator_set_changed = true;
                    count_removed += 1;
                } else {
                    // The `add_validator` ensures that a validator id cannot be part of both active
                    // validator set and queued validators
                    let removed_queued = Self::remove_validator_id(&v, &mut validators_to_add);
                    if removed_queued > 0 {
                        queued_validator_set_changed = true;
                    }
                }
            }

            let max_validators = T::MaxActiveValidators::get() as usize;

            // TODO: Remove debugging variable below
            let mut count_added = 0u32;

            // Make any queued validators active.
            while (active_validators.len() < max_validators) && (validators_to_add.len() > 0) {
                active_validator_set_changed = true;
                queued_validator_set_changed = true;
                active_validators.push(validators_to_add.remove(0));
                count_added += 1;
            }

            // Only write if queued_validator_set_changed
            if queued_validator_set_changed {
                <QueuedValidators<T>>::put(validators_to_add);
            }

            ForceSessionChange::put(false);

            let active_validator_count = active_validators.len() as u32;
            if active_validator_set_changed {
                print("Active validator set changed, rotating session");
                print(count_added);
                print(count_removed);
                <ActiveValidators<T>>::put(active_validators);
            }
            (active_validator_set_changed, active_validator_count)
        } else {
            (false, active_validators.len() as u32)
        }
    }

    /// Set next epoch duration such that it is >= `MinEpochLength` and also a multiple of the
    /// number of active validators
    fn set_next_epoch_change(current_block_no: u32, active_validator_count: u32) {
        let min_session_len = T::MinEpochLength::get();
        let rem = min_session_len % active_validator_count;
        let session_len = if rem == 0 {
            min_session_len
        } else {
            min_session_len + active_validator_count - rem
        };
        let next_session_at = current_block_no + session_len;
        print("next session at");
        print(next_session_at);
        <NextEpochChangeAfter<T>>::put(T::BlockNumber::from(next_session_at));
    }

    fn swap(old_validator_id: T::AccountId, new_validator_id: T::AccountId) -> u32 {
        let mut active_validators = Self::active_validators();
        let count = active_validators.len() as u32;
        for (i, v) in active_validators.iter().enumerate() {
            if *v == old_validator_id {
                active_validators[i] = new_validator_id;
                break;
            }
        }
        <ActiveValidators<T>>::put(active_validators);
        count
    }
}

/// Indicates to the session module if the session should be rotated.
impl<T: Trait> pallet_session::ShouldEndSession<T::BlockNumber> for Module<T> {
    fn should_end_session(_now: T::BlockNumber) -> bool {
        print("Called should_end_session");

        let current_block_no = <system::Module<T>>::block_number().saturated_into::<u32>();
        let next_epoch_begins_after = Self::next_epoch_begins_after().saturated_into::<u32>();
        print("current_block_no");
        print(current_block_no.saturated_into::<u32>());
        print("current_block_no");
        print(next_epoch_begins_after);

        // TODO: Remove once sure the following panic is never triggered
        if current_block_no > next_epoch_begins_after {
            panic!("Current block number > current_block_no");
        }

        // Unless the session is being forcefully ended or epoch has had the required number of blocks,
        // or hot swap is triggered, continue the session.
        // TODO: Reduce reads from 2 to 1 by changing the boolean flag to be integer (u8) for different conditions.
        let force_session_change = Self::force_session_change();
        let hot_swap = <HotSwap<T>>::take();
        if force_session_change || (current_block_no == next_epoch_begins_after) || hot_swap.is_some() {

            let (active_validator_set_changed, active_validator_count) = if hot_swap.is_some() {
                let (old_validator, new_validator) = hot_swap.unwrap();
                (true, Self::swap(old_validator, new_validator))
            } else {
                Self::update_active_validators_if_needed()
            };

            if active_validator_set_changed {
                <pallet_session::Module<T>>::rotate_session();
            }

            Self::set_next_epoch_change(current_block_no, active_validator_count);
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

// TODO: Tested with SDK script Write runtime tests if time permits.
