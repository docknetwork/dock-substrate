#![cfg_attr(not(feature = "std"), no_std)]

use codec::Decode;
/// Pallet to add and remove validators.
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, ensure, fail,
    sp_runtime::{print, SaturatedConversion},
    traits::{Currency, Get, Imbalance, OnUnbalanced},
};
use frame_system::{self as system, ensure_root};
use log::{debug, warn};
use sp_std::prelude::Vec;

extern crate alloc;
use alloc::collections::BTreeSet;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: system::Trait + pallet_session::Trait + pallet_authorship::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// Epoch length in number of slots
    type MinEpochLength: Get<u64>;

    /// Maximum no. of active validators allowed
    type MaxActiveValidators: Get<u8>;

    type Currency: Currency<Self::AccountId>;
}

// This pallet's storage items.
decl_storage! {

    trait Store for Module<T: Trait> as PoAModule {
        /// List of active validators. Maximum allowed are `MaxActiveValidators`
        ActiveValidators get(fn active_validators) config(): Vec<T::AccountId>;

        /// Next epoch will begin after this slot number, i.e. this slot number will be the last
        /// slot of the current epoch
        EpochEndsAt get(fn epoch_ends_at): u64;

        /// Queue of validators to become part of the active validators. Validators can be added either
        /// to the back of the queue or front by passing a flag in the add method.
        /// On epoch end or prematurely if forced, validators from the queue are taken out in FIFO order
        /// and added to the active validators unless the number of active validators reaches the max allowed.
        QueuedValidators get(fn validators_to_add): Vec<T::AccountId>;

        /// List to hold validators to remove either on the end of epoch or immediately. If a candidate validator
        /// is queued for becoming an active validator but also present in the removal list, it will
        /// not become active as this list takes precedence of queued validators. It is emptied on each
        /// epoch end
        RemoveValidators get(fn validators_to_remove): Vec<T::AccountId>;

        /// Set when a hot swap is to be performed, replacing validator id as 1st element of tuple
        /// with the 2nd one.
        HotSwap get(fn hot_swap): Option<(T::AccountId, T::AccountId)>;

        /// Transaction fees
        TxnFees get(fn txn_fees): <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

        /// Current epoch
        Epoch get(fn epoch): u32;

        /// For each epoch, validator count, starting slot, ending slot
        Epochs get(fn get_epoch_detail): map hasher(identity) u32 => (u8, u64, Option<u64>);

        /// Block produced by each validator per epoch
        EpochBlockCounts get(fn get_block_count_for_validator):
            double_map hasher(identity) u32, hasher(blake2_128_concat) T::AccountId => u64;
    }
}

// The pallet's events
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        // New validator added in front of queue.
        ValidatorQueuedInFront(AccountId),

        // New validator added at back of queue.
        ValidatorQueued(AccountId),

        // Validator removed.
        ValidatorRemoved(AccountId),

        EpochBegins(u64),
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
        // `should_end_session` since that it called more frequently.

        type Error = Error<T>;

        fn deposit_event() = default;

        /// Add a new validator to active validator set unless already a validator and the total number
        /// of validators don't exceed the max allowed count. The validator is considered for adding at
        /// the end of this epoch unless `short_circuit` is true. If a validator is already added to the queue
        /// an error will be thrown unless `short_circuit` is true, in which case it swallows the error.
        // Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
        #[weight = 0]
        pub fn add_validator(origin, validator_id: T::AccountId, short_circuit: bool) -> dispatch::DispatchResult {
            // TODO: Check the origin is Master
            ensure_root(origin)?;

            Self::add_validator_(validator_id, short_circuit)
        }

        /// Remove the given validator from active validator set and the queued validators at the end
        /// of epoch unless `short_circuit` is true. If validator is already queued for removal, an error
        /// will be thrown unless `short_circuit` is true, in which case it swallows the error.
        /// It will not remove the validator if the removal will cause the active validator set to
        /// be empty even after considering the queued validators.
        // Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
        #[weight = 0]
        pub fn remove_validator(origin, validator_id: T::AccountId, short_circuit: bool) -> dispatch::DispatchResult {
            // TODO: Check the origin is Master
            ensure_root(origin)?;
            Self::remove_validator_(validator_id, short_circuit)
        }

        /// Replace an active validator (`old_validator_id`) with a new validator (`new_validator_id`)
        /// without waiting for epoch to end. Throws error if `old_validator_id` is not active or
        /// `new_validator_id` is already active. Also useful when a validator wants to rotate his account.
        // Weight can be 0 as its called by Master. TODO: Use signed extension to make it free
        #[weight = 0]
        pub fn swap_validator(origin, old_validator_id: T::AccountId, new_validator_id: T::AccountId) -> dispatch::DispatchResult {
            // TODO: Check the origin is Master
            ensure_root(origin)?;
            Self::swap_validator_(old_validator_id, new_validator_id)
        }

        /// Awards the complete txn fees to the block author if any and increment block count for
        /// current epoch and who authored it.
        fn on_finalize() {
            print("Finalized block");

            // Get the current block author
            let author = <pallet_authorship::Module<T>>::author();

            Self::award_txn_fees_if_any(&author);

            Self::increment_current_epoch_block_count(author)
        }
    }
}

impl<T: Trait> Module<T> {
    fn add_validator_(validator_id: T::AccountId, short_circuit: bool) -> dispatch::DispatchResult {
        // Check if the validator is not already present as an active one
        let active_validators = Self::active_validators();
        ensure!(
            !active_validators.contains(&validator_id),
            Error::<T>::AlreadyActiveValidator
        );

        if short_circuit {
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
            Self::short_circuit_current_epoch();
            Self::deposit_event(RawEvent::ValidatorQueuedInFront(validator_id));
        } else {
            let mut validators = Self::validators_to_add();
            ensure!(
                !validators.contains(&validator_id),
                Error::<T>::AlreadyQueuedForAddition
            );
            print("Adding a new validator at back");
            // The new validator should be at the back of the queue
            validators.push(validator_id.clone());
            <QueuedValidators<T>>::put(validators);
            Self::deposit_event(RawEvent::ValidatorQueued(validator_id));
        }
        Ok(())
    }

    fn remove_validator_(
        validator_id: T::AccountId,
        short_circuit: bool,
    ) -> dispatch::DispatchResult {
        let mut validators_to_remove: Vec<T::AccountId> = Self::validators_to_remove();
        // Form a set of validators to remove
        let mut removals = BTreeSet::new();
        for v in validators_to_remove.iter() {
            removals.insert(v);
        }

        // Check if already queued for removal
        let already_queued_for_rem = if removals.contains(&validator_id) {
            if short_circuit {
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

        if short_circuit {
            Self::short_circuit_current_epoch();
        }
        Ok(())
    }

    fn swap_validator_(
        old_validator_id: T::AccountId,
        new_validator_id: T::AccountId,
    ) -> dispatch::DispatchResult {
        let active_validators: Vec<T::AccountId> = Self::active_validators().into();

        let mut found = false;
        for v in active_validators.iter() {
            if *v == new_validator_id {
                print("New validator to swap in already present");
                fail!(Error::<T>::SwapInFailed)
            }
            if *v == old_validator_id {
                found = true;
            }
        }

        if !found {
            print("Validator to swap out not present");
            fail!(Error::<T>::SwapOutFailed)
        }

        <HotSwap<T>>::put((old_validator_id, new_validator_id));
        Ok(())
    }

    /// Takes a validator id and a mutable vector of validator ids and remove any occurrence from
    /// the mutable vector. Returns number of removed occurrences
    fn remove_validator_id(id: &T::AccountId, validators: &mut Vec<T::AccountId>) -> usize {
        let old_size = validators.len();
        validators.retain(|v| v != id);
        old_size - validators.len()
    }

    /// Update active validator set if needed and return if the active validator set changed and the
    /// count of the new active validators.
    fn update_active_validators_if_needed() -> (bool, u8) {
        let mut active_validators = Self::active_validators();
        let mut validators_to_add = Self::validators_to_add();
        // Remove any validators that need to be removed.
        let validators_to_remove = <RemoveValidators<T>>::take();

        let mut active_validator_set_changed = false;
        let mut queued_validator_set_changed = false;

        // If any validator is to be added or removed
        if (validators_to_remove.len() > 0) || (validators_to_add.len() > 0) {
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
                let new_val = validators_to_add.remove(0);
                // Check if the validator to add is not already active. The check is needed as a swap
                // might make a validator as active which is already present in the queue.
                if !active_validators.contains(&new_val) {
                    active_validator_set_changed = true;
                    queued_validator_set_changed = true;
                    active_validators.push(new_val);
                    count_added += 1;
                }
            }

            // Only write if queued_validator_set_changed
            if queued_validator_set_changed {
                <QueuedValidators<T>>::put(validators_to_add);
            }

            let active_validator_count = active_validators.len() as u8;
            if active_validator_set_changed {
                debug!(
                    target: "runtime",
                    "Active validator set changed, rotating session. Added {} and removed {}",
                    count_added, count_removed
                );
                <ActiveValidators<T>>::put(active_validators);
            }
            (active_validator_set_changed, active_validator_count)
        } else {
            (false, active_validators.len() as u8)
        }
    }

    /// Set next epoch duration such that it is >= `MinEpochLength` and also a multiple of the
    /// number of active validators
    fn set_current_epoch_end(current_slot_no: u64, active_validator_count: u8) -> u64 {
        let min_epoch_len = T::MinEpochLength::get();
        let active_validator_count = active_validator_count as u64;
        let rem = min_epoch_len % active_validator_count;
        let epoch_len = if rem == 0 {
            min_epoch_len
        } else {
            min_epoch_len + active_validator_count - rem
        };
        // Current slot no is part of epoch
        let epoch_ends_at = current_slot_no + epoch_len - 1;
        EpochEndsAt::put(epoch_ends_at);
        epoch_ends_at
    }

    /// Swap out from active validators if `swap` is not None and will return count of active validators
    /// in an Option
    fn swap_if_needed(swap: Option<(T::AccountId, T::AccountId)>) -> Option<u8> {
        match swap {
            Some((old_validator, new_validator)) => Some(Self::swap(old_validator, new_validator)),
            None => None,
        }
    }
    /// Swap a validator account from active validators. Swap out `old_validator_id` for `new_validator_id`.
    /// Expects the active validator set to contain `old_validator_id`. This is ensured by the extrinsic.
    fn swap(old_validator_id: T::AccountId, new_validator_id: T::AccountId) -> u8 {
        let mut active_validators = Self::active_validators();
        let count = active_validators.len() as u8;
        for (i, v) in active_validators.iter().enumerate() {
            if *v == old_validator_id {
                active_validators[i] = new_validator_id;
                break;
            }
        }
        <ActiveValidators<T>>::put(active_validators);
        count
    }

    /// Return the current slot no if accessible
    fn current_slot_no() -> Option<u64> {
        let digest = <system::Module<T>>::digest();
        let logs = digest.logs();
        if logs.len() > 0 {
            // Assumes that the first log is for PreRuntime digest
            match logs[0].as_pre_runtime() {
                Some(pre_run) => {
                    // Assumes that the 2nd element of tuple is for slot no.
                    let s = u64::decode(&mut &pre_run.1[..]).unwrap();
                    debug!(target: "runtime", "current slo no is {}", s);
                    Some(s)
                }
                None => {
                    // print("Not as_pre_runtime ");
                    None
                }
            }
        } else {
            // print("No logs");
            None
        }
    }

    /// Prematurely end current epoch but keep slots multiple of no of validators
    /// Updates storage for end of current epoch
    fn short_circuit_current_epoch() -> u64 {
        let current_slot_no = Self::current_slot_no().unwrap();
        // Moving the logic to separate method to keep it testable
        Self::update_current_epoch_end_on_short_circuit(current_slot_no)
    }

    /// Updates storage for end of current epoch on premature ending of epoch.
    /// Takes the current slot no.
    fn update_current_epoch_end_on_short_circuit(current_slot_no: u64) -> u64 {
        let current_epoch_no = Self::epoch();
        let (active_validator_count, starting_slot, _) = Self::get_epoch_detail(current_epoch_no);
        let active_validator_count = active_validator_count as u64;
        let current_progress = current_slot_no - starting_slot + 1;
        let rem = current_progress % active_validator_count;
        let epoch_ends_at = if rem == 0 {
            current_slot_no
        } else {
            current_slot_no + active_validator_count - rem
        };
        EpochEndsAt::put(epoch_ends_at);
        debug!(
            target: "runtime",
            "Epoch {} prematurely ended at slot {}",
            current_epoch_no, epoch_ends_at
        );
        epoch_ends_at
    }

    /// If there is any transaction fees, credit it to the given author
    fn award_txn_fees_if_any(block_author: &T::AccountId) -> Option<u64> {
        // ------------- DEBUG START -------------
        let current_block_no = <system::Module<T>>::block_number();
        debug!(
            target: "runtime",
            "block author in finalize for {:?} is {:?}",
            current_block_no, block_author
        );

        let total_issuance = T::Currency::total_issuance().saturated_into::<u64>();
        let ab = T::Currency::free_balance(block_author).saturated_into::<u64>();
        debug!(
            target: "runtime",
            "block author's balance is {} and total issuance is {}",
            ab, total_issuance
        );
        // ------------- DEBUG END -------------

        let txn_fees = <TxnFees<T>>::take();
        let fees_as_u64 = txn_fees.saturated_into::<u64>();
        if fees_as_u64 > 0 {
            print("Depositing fees");
            // `deposit_creating` will do the issuance of tokens burnt during transaction fees
            T::Currency::deposit_creating(block_author, txn_fees);
        }

        // ------------- DEBUG START -------------
        let total_issuance = T::Currency::total_issuance().saturated_into::<u64>();
        let ab = T::Currency::free_balance(block_author).saturated_into::<u64>();
        debug!(
            target: "runtime",
            "block author's balance is {} and total issuance is {}",
            ab, total_issuance
        );
        // ------------- DEBUG END -------------

        if fees_as_u64 > 0 {
            Some(fees_as_u64)
        } else {
            None
        }
    }

    fn increment_current_epoch_block_count(block_author: T::AccountId) {
        let current_epoch_no = Self::epoch();
        let block_count = Self::get_block_count_for_validator(current_epoch_no, &block_author);
        // Not doing saturating add as its practically impossible to produce 2^64 blocks
        <EpochBlockCounts<T>>::insert(current_epoch_no, block_author, block_count + 1);
    }

    fn update_details_on_epoch_change(
        current_epoch_no: u32,
        current_slot_no: u64,
        active_validator_count: u8,
    ) {
        if current_epoch_no == 1 {
            // First epoch, no no previous epoch to update
        } else {
            // Track end of previous epoch
            let prev_epoch = current_epoch_no - 1;
            let (v, start, _) = Epochs::get(&prev_epoch);
            if v == 0 {
                // This get should never fail. But if it does, let it panic
                warn!(
                    target: "runtime",
                    "Data for previous epoch not found: {}",
                    prev_epoch
                );
                panic!();
            }
            debug!(
                target: "runtime",
                "Epoch {} ends at slot {}",
                prev_epoch, current_slot_no - 1
            );
            Epochs::insert(prev_epoch, (v, start, Some(current_slot_no - 1)))
        }

        debug!(
            target: "runtime",
            "Epoch {} begins at slot {}",
            current_epoch_no, current_slot_no
        );
        Epoch::put(current_epoch_no);
        Epochs::insert(
            current_epoch_no,
            (active_validator_count, current_slot_no, None as Option<u64>),
        );
    }

    /// The validator set needs to update, either due to swap or epoch end.
    fn update_validator_set(current_slot_no: u64, epoch_ends_at: u64, swap: Option<(T::AccountId, T::AccountId)>) -> (bool, u8) {
        match Self::swap_if_needed(swap) {
            Some(count) => {
                // Swap occurred, check if the swap coincided with an epoch end
                if current_slot_no > epoch_ends_at {
                    let (changed, new_count) = Self::update_active_validators_if_needed();
                    // There is a chance that `update_active_validators_if_needed` undoes the swap and in that case
                    // rotate_session can be avoided.
                    if changed {
                        // The epoch end changed the active validator set and count
                        (changed, new_count)
                    } else {
                        (true, count)
                    }
                } else {
                    // Epoch did not end but swap did happen
                    (true, count)
                }
            },
            None => Self::update_active_validators_if_needed(),
        }
    }
}

/// Indicates to the session module if the session should be rotated.
impl<T: Trait> pallet_session::ShouldEndSession<T::BlockNumber> for Module<T> {
    fn should_end_session(_now: T::BlockNumber) -> bool {
        print("Called should_end_session");

        // TODO: Next 2 are debugging lines. Remove them.
        let current_block_no = <system::Module<T>>::block_number().saturated_into::<u32>();
        debug!(target: "runtime", "current_block_no {}", current_block_no);

        let current_slot_no = match Self::current_slot_no() {
            Some(s) => s,
            None => {
                print("Cannot fetch slot number");
                return false;
            }
        };

        let epoch_ends_at = Self::epoch_ends_at().saturated_into::<u64>();
        debug!(
            target: "runtime",
            "epoch ends at {}",
            epoch_ends_at
        );

        // Unless the epoch has had the required number of blocks, or hot swap is triggered, continue the session.
        let swap = <HotSwap<T>>::take();

        if (current_slot_no > epoch_ends_at) || swap.is_some() {
            let (active_validator_set_changed, active_validator_count) = Self::update_validator_set(current_slot_no, epoch_ends_at, swap);

            if active_validator_set_changed {
                // Manually calling `rotate_session` will make the new validator set change take effect
                // on next session (as `rotate_session` will be called again once this function returns true)
                <pallet_session::Module<T>>::rotate_session();
            }

            let last_slot = Self::set_current_epoch_end(current_slot_no, active_validator_count);
            debug!(
                target: "runtime",
                "epoch will ends at {}",
                last_slot
            );
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

    fn new_session(session_idx: u32) -> Option<Vec<T::AccountId>> {
        print("Called new_session");
        let validators = Self::active_validators();
        // Check for error on empty validator set. On returning None, it loads validator set from genesis
        if validators.len() == 0 {
            None
        } else {
            debug!(
                target: "runtime",
                "Current session index {}",
                session_idx
            );

            // This slot number should always be available here. If its not then panic.
            let current_slot_no = Self::current_slot_no().unwrap();

            let active_validator_count = validators.len() as u8;
            let current_epoch_no = session_idx - 1;

            Self::update_details_on_epoch_change(
                current_epoch_no,
                current_slot_no,
                active_validator_count,
            );

            Some(validators)
        }
    }

    fn end_session(_: u32) {}
    fn start_session(_: u32) {}
}

/// Negative imbalance used to transfer transaction fess to block author
type NegativeImbalanceOf<T> =
    <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::NegativeImbalance;

/// Transfer complete transaction fees (including tip) to the block author
impl<T: Trait> OnUnbalanced<NegativeImbalanceOf<T>> for Module<T> {
    /// There is only 1 way to have an imbalance in the system right now which is txn fees
    /// This function will store txn fees for the block in storage which is "taken out" of storage
    /// in `on_finalize`. Not retrieving block author here as that is unreliable and gives different
    /// author than the block's.
    fn on_nonzero_unbalanced(amount: NegativeImbalanceOf<T>) {
        // TODO: Remove the next 3 debug lines
        let current_fees = amount.peek();

        // ------------- DEBUG START -------------
        let total_issuance = T::Currency::total_issuance().saturated_into::<u64>();

        debug!(
            target: "runtime",
            "Current txn fees is {} and total issuance is {}",
            current_fees.saturated_into::<u64>(), total_issuance
        );

        let current_block_no = <system::Module<T>>::block_number();

        // Get the current block author
        let author = <pallet_authorship::Module<T>>::author();
        debug!(
            target: "runtime",
            "block author for {:?} is {:?}",
            current_block_no, author
        );

        // ------------- DEBUG END -------------

        <TxnFees<T>>::put(current_fees);
    }
}
