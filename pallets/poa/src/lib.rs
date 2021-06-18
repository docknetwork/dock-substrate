//! Pallet to add/remove validators and do emission rewards.
//! UPDATE: Adding removing validators and emission rewards is no more done by this pallet. The only
//! reason for this pallet's existence is to unlock the locked emission rewards and tracking last
//! block of PoA chain.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, ensure, fail, log,
    sp_runtime::{
        print,
        runtime_logger::RuntimeLogger,
        traits::{AccountIdConversion, CheckedSub, OpaqueKeys, Saturating, StaticLookup, Zero},
        ModuleId, SaturatedConversion,
    },
    traits::{
        BalanceStatus::Reserved, Currency, ExistenceRequirement::AllowDeath, Get,
        ReservableCurrency,
    },
    weights::{Pays, Weight},
};

use frame_system::{self as system, ensure_root, RawOrigin};
use sp_std::prelude::Vec;

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

pub mod runtime_api;

pub type EpochNo = u32;
type EpochLen = u32;
type SlotNo = u64;

pub type BalanceOf<T> =
    <<T as Trait>::Currency as Currency<<T as system::Config>::AccountId>>::Balance;

#[cfg(test)]
mod tests;

/// Details per epoch
#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
pub struct EpochDetail<Balance> {
    /// Count of active validators in the epoch
    pub validator_count: u8,
    /// Starting slot no of the epoch
    pub starting_slot: SlotNo,
    /// Expected ending slot for the epoch. This is set such that the no of slots in the epoch
    /// is >= minimum slots in the epoch and is a multiple of the no of validators, this giving each
    /// validator same no of slots
    pub expected_ending_slot: SlotNo,
    /// The epoch might end earlier than the expected ending due to short circuiting of the epoch (more
    /// on that in the extrinsic documentation) or swap. This might also be higher than the expected
    /// ending slot when the network halts (crashes)
    pub ending_slot: Option<SlotNo>,
    /// Total emission rewards for all the validators in the epoch
    pub emission_for_validators: Option<Balance>,
    /// Emission rewards for the treasury in the epoch
    pub emission_for_treasury: Option<Balance>,
}

/// Details per epoch per validator
#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
pub struct ValidatorStatsPerEpoch<Balance> {
    /// Count of blocks authored by the validator in the epoch
    pub block_count: EpochLen,
    /// Amount of locked rewards earned by the validator in the epoch. This reward is added to the
    /// reserved balance (by calling `Balances::reserve`) of the validator. When unlocking (during PoS),
    /// we move this reserved balance to free balance (by calling `Balances::unreserve` and pass amount)
    /// for each epoch since beginning, thus giving us the gradual release functionality.
    pub locked_reward: Option<Balance>,
    /// Amount of unlocked rewards earned by the validator in the epoch.
    pub unlocked_reward: Option<Balance>,
}

impl<Balance> EpochDetail<Balance> {
    /// Create a new epoch detail object. This is called when epoch is starting
    pub fn new(validator_count: u8, starting_slot: SlotNo, expected_ending_slot: SlotNo) -> Self {
        EpochDetail {
            validator_count,
            starting_slot,
            expected_ending_slot,
            ending_slot: None,
            emission_for_validators: None,
            emission_for_treasury: None,
        }
    }

    pub fn expected_slots_per_validator(&self) -> EpochLen {
        ((self.expected_ending_slot - self.starting_slot + 1) / self.validator_count as SlotNo)
            as EpochLen
    }
}

/// Enum specifying whether same no of blocks were produced by the validators in an epoch. If not then
/// what is the maximum number of blocks produced in the epoch.
enum BlockCount {
    /// Different no of blocks were produced by different validators, the max is captured
    MaxBlocks(EpochLen),
    /// Same no of blocks were produced by all the validators
    SameBlocks(EpochLen),
}

impl BlockCount {
    pub fn to_number(&self) -> EpochLen {
        match self {
            BlockCount::MaxBlocks(n) => *n,
            BlockCount::SameBlocks(n) => *n,
        }
    }
}

/// Hardcoded treasury id; used to create the special Treasury account
/// Must be exactly 8 characters long
const TREASURY_ID: ModuleId = ModuleId(*b"Treasury");

/// The pallet's configuration trait.
pub trait Trait: system::Config + pallet_session::Config + pallet_authorship::Config {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;

    type Currency: ReservableCurrency<Self::AccountId>;
}

// This pallet's storage items.
decl_storage! {

    trait Store for Module<T: Trait> as PoAModule {
        /// Minimum epoch length in number of slots, the actual slot length >= it and set as a
        /// multiple of number of active validators
        MinEpochLength get(fn min_epoch_length) config(): EpochLen;

        /// Minimum epoch length set through extrinsic, this will become `MinEpochLength` for next epoch
        /// Once read, this value is made empty
        // XXX: The storage value is not an `Option` due to serialization error. This might be fixed in
        // future. Using 0 as lack of value since it is not an acceptable value for this.
        MinEpochLengthTentative get(fn min_epoch_length_tentative): EpochLen;

        /// Maximum active validators (the ones that produce blocks).
        MaxActiveValidators get(fn max_active_validators) config(): u8;

        /// Maximum active validators set through extrinsic, this will become `MaxActiveValidators` for
        /// next epoch. Once read, this value is made empty
        // XXX: The storage value is not an `Option` due to serialization error. This might be fixed in
        // future. Using 0 as lack of value since it is not an acceptable value for this.
        MaxActiveValidatorsTentative get(fn max_active_validators_tentative): u8;

        /// Flag set when forcefully rotating a session
        ForcedSessionRotation get(fn forced_session_rotation): bool;

        /// List of active validators. Maximum allowed are `MaxActiveValidators`.
        /// The validators are fed to the session pallet using the `new_session` method implemented
        /// below and are set as `pallet_session::Validators`. For most of the time, the
        /// `ActiveValidators` should be same as `pallet_session::Validators` except the duration
        /// where `ActiveValidators` is set and not yet fed to the session pallet.
        ActiveValidators get(fn active_validators) config(): Vec<T::AccountId>;

        /// Next epoch will begin after this slot number, i.e. this slot number will be the last
        /// slot of the current epoch
        EpochEndsAt get(fn epoch_ends_at): SlotNo;

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

        /// Holds transaction fees for a block. Every transaction fees detected through the imbalance
        /// accumulates the fees in this storage item. Once a block is done (`on_finalize`), the accumulated
        /// fees is given to the block author and this item is zeroed out.
        /// # <weight>
        /// Regarding contribution to the weight, the read and write is not counted towards weight
        /// contribution of the extrinsic since there is only 1 read and 1 write per block to this
        /// due to Substrate's _overlay change set_ abstraction on storage.
        /// # </weight>
        TxnFees get(fn txn_fees): BalanceOf<T>;

        /// Current epoch
        Epoch get(fn epoch): EpochNo;

        /// For each epoch, details like validator count, starting slot, ending slot, etc
        Epochs get(fn get_epoch_detail): map hasher(identity) EpochNo => EpochDetail<BalanceOf<T>>;

        /// Blocks produced, rewards for each validator per epoch
        ValidatorStats get(fn get_validator_stats_for_epoch):
            double_map hasher(identity) EpochNo, hasher(blake2_128_concat) T::AccountId => ValidatorStatsPerEpoch<BalanceOf<T>>;

        /// Remaining emission supply. This reduces after each epoch as emissions happen unless
        /// emissions are disabled.
        pub EmissionSupply get(fn emission_supply) config(): BalanceOf<T>;

        /// Max emission per validator in an epoch
        MaxEmmValidatorEpoch get(fn max_emm_validator_epoch) config(): BalanceOf<T>;

        /// Percentage of emission rewards for treasury in each epoch
        pub TreasuryRewardsPercent get(fn treasury_reward_pc) config(): u8;

        /// Percentage of emission rewards locked per epoch for validators
        ValidatorRewardsLockPercent get(fn validator_reward_lock_pc) config(): u8;

        /// Boolean flag determining whether to generate emission rewards or not
        EmissionStatus get(fn emission_status) config(): bool;

        /// Used to track information to unlock validator rewards.
        /// `EpochNo` is for which epoch number to unlock next
        /// `T::BlockNumber` for which is the last block number for the epoch
        /// `bool` set to true if all epochs that needed to be unlocked are processed. Used to avoid
        /// looking for more epochs
        NextEpochToReward get(fn next_epoch_to_reward): Option<(EpochNo, T::BlockNumber, bool)>;

        /// PoA chain's last block's hash. Not storing genesis block hash of PoA chain.
        PoALastBlock get(fn poa_last_block) config(): T::Hash
    }
}

// The pallet's events
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Config>::AccountId,
        Balance = BalanceOf<T>,
    {
        /// New validator added in front of queue.
        ValidatorQueuedInFront(AccountId),

        /// New validator added at back of queue.
        ValidatorQueued(AccountId),

        /// Validator removed.
        ValidatorRemoved(AccountId),

        /// Validator swapped. Swapped out validator id and swapped in validator id
        ValidatorSwapped(AccountId, AccountId),

        /// Epoch begins at slot and expected to end at slot
        EpochBegins(EpochNo, SlotNo, SlotNo),

        /// Epoch ends at slot
        EpochEnds(EpochNo, SlotNo),

        /// Txn fees given to block author, (validator id, fees)
        TxnFeesGiven(AccountId, Balance),

        /// Emission reward unlocked for validator in certain epoch
        RewardUnlocked(EpochNo, AccountId, Balance),
    }
);

// The pallet's errors
decl_error! {
    /// Errors for the module.
    pub enum Error for Module<T: Trait> {
        AlreadyActiveValidator,
        AlreadyQueuedForAddition,
        AlreadyQueuedForRemoval,
        NeedAtLeast1Validator,
        EpochLengthCannotBe0,
        SwapOutFailed,
        SwapInFailed,
        PercentageGreaterThan100,
        InsufficientFreeBalance,
        InsufficientReservedBalance
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        /// Do maximum of the work in functions to `add_validator` or `remove_validator` and minimize the work in
        /// `should_end_session` since that it called more frequently.

        type Error = Error<T>;

        fn deposit_event() = default;

        /// Add a new validator to active validator set unless already a validator and the total number
        /// of validators don't exceed the max allowed count. The validator is considered for adding at
        /// the end of this epoch unless `short_circuit` is true. If a validator is already added to the queue
        /// an error will be thrown unless `short_circuit` is true, in which case it swallows the error.
        /// # <weight>
        /// Assuming worst case for below. Not considering iteration cost over in memory arrays since the arrays
        /// are small and these dispatchables are rarely called.
        /// 2 reads for storage items, 1 each for `ActiveValidators` and `QueuedValidators`.
        /// In worst case there is a write to `QueuedValidators`.
        /// In case of short circuit there is 1 read to `Epochs` and 1 write to `EpochEndsAt`
        /// # </weight>
        #[weight = T::DbWeight::get().reads_writes(2 + *short_circuit as Weight, 1 + *short_circuit as Weight)]
        pub fn add_validator(origin, validator_id: T::AccountId, short_circuit: bool) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            Self::add_validator_(validator_id, short_circuit)?;
            Ok(Pays::No.into())
        }

        /// Remove the given validator from active validator set and the queued validators at the end
        /// of epoch unless `short_circuit` is true. If validator is already queued for removal, an error
        /// will be thrown unless `short_circuit` is true, in which case it swallows the error.
        /// It will not remove the validator if the removal will cause the active validator set to
        /// be empty even after considering the queued validators.
        /// Remove takes priority over adding and thus if a validator is both is set for removal, it
        /// cannot be added in the next epoch when added in the queue.
        /// # <weight>
        /// Assuming worst case for below. Not considering iteration cost over in memory arrays since the arrays
        /// are small and these dispatchables are rarely called.
        /// 3 reads for storage items, 1 each for `ActiveValidators`, `QueuedValidators` and `RemoveValidators`
        /// In worst case there is a write to `RemoveValidators`.
        /// In case of short circuit there is 1 read to `Epochs` and 1 write to `EpochEndsAt`
        /// # </weight>
        #[weight = T::DbWeight::get().reads_writes(3 + *short_circuit as Weight, 1 + *short_circuit as Weight)]
        pub fn remove_validator(origin, validator_id: T::AccountId, short_circuit: bool) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            Self::remove_validator_(validator_id, short_circuit)?;
            Ok(Pays::No.into())
        }

        /// Replace an active validator (`old_validator_id`) with a new validator (`new_validator_id`)
        /// without waiting for epoch to end. Throws error if `old_validator_id` is not active or
        /// `new_validator_id` is already active. Also useful when a validator wants to rotate his account.
        /// When several of such extrinsics are in a single block, only the last extrinsic's swap will
        /// take effect assuming they are swapping out existing validators and swapping in non-existent
        /// validators. Since this extrinsic is rarely used, the risk is non-existent in practice. However,
        /// it can be enforced that only first one takes effect by checking that storage entry `HotSwap<T>`
        /// is "empty" else abort the extrinsic.
        /// # <weight>
        /// Only takes into account the weight of read of active validator vector and write to the swap
        /// storage item. The write to validator set happens while loading next block and is counted
        /// in `BlockExecutionWeight`
        /// # </weight>
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn swap_validator(origin, old_validator_id: T::AccountId, new_validator_id: T::AccountId) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            Self::swap_validator_(old_validator_id, new_validator_id)?;
            Ok(Pays::No.into())
        }

        /// End epoch early
        /// # <weight>
        /// 1 read to `Epochs` and 1 write to `EpochEndsAt`
        /// # </weight>
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn short_circuit_epoch(origin) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            Self::short_circuit_current_epoch();
            Ok(Pays::No.into())
        }

        /// Used to set session keys for a validator. A validator shares its session key with the
        /// author of this extrinsic who then calls `set_keys` of the session pallet. This is useful
        /// when the validator does not balance to pay fees for `set_keys`
        /// # <weight>
        /// Wights computation copied from session pallet's `set_keys` dispatchable
        /// # </weight>
        #[weight = 200_000_000
            + T::DbWeight::get().reads(2 + T::Keys::key_ids().len() as Weight)
            + T::DbWeight::get().writes(1 + T::Keys::key_ids().len() as Weight)]
        pub fn set_session_key(origin, validator_id: T::AccountId, keys: T::Keys) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            <pallet_session::Module<T>>::set_keys(RawOrigin::Signed(validator_id).into(), keys, [].to_vec())?;
            Ok(Pays::No.into())
        }

        /// Enable/disable emission rewards by calling this function with true or false respectively.
        /// Only Master can call this.
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_emission_status(origin, status: bool) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            EmissionStatus::put(status);
            Ok(Pays::No.into())
        }

        /// Set the minimum number of slots in the epoch, i.e. storage item MinEpochLength. This
        /// does not effect the epoch in progress but only subsequent epochs
        /// # <weight>
        /// 3 writes in total:
        ///     1 write during extrinsic to `MinEpochLengthTentative`
        ///     1 write during epoch change to `MinEpochLength`
        ///     1 write during epoch change to `MinEpochLengthTentative` to zero it out
        /// # </weight>
        #[weight = T::DbWeight::get().writes(3)]
        pub fn set_min_epoch_length(origin, length: EpochLen) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(length > 0, Error::<T>::EpochLengthCannotBe0);
            MinEpochLengthTentative::put(length);
            Ok(Pays::No.into())
        }

        /// Set the maximum number of active validators, i.e. storage item MaxActiveValidators. This
        /// does not effect the epoch in progress but only subsequent epochs
        /// # <weight>
        /// 3 writes in total:
        ///     1 write during extrinsic to `MaxActiveValidatorsTentative`
        ///     1 write during epoch change to `MaxActiveValidators`
        ///     1 write during epoch change to `MaxActiveValidatorsTentative` to zero it out
        /// # </weight>
        #[weight = T::DbWeight::get().writes(3)]
        pub fn set_max_active_validators(origin, count: u8) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(count > 0, Error::<T>::NeedAtLeast1Validator);
            MaxActiveValidatorsTentative::put(count);
            Ok(Pays::No.into())
        }

        /// Set the maximum emission rewards per validator per epoch.
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_max_emm_validator_epoch(origin, emission: BalanceOf<T>) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            <MaxEmmValidatorEpoch<T>>::put(emission);
            Ok(Pays::No.into())
        }

        /// Set percentage of emission rewards locked per epoch for validators
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_validator_reward_lock_pc(origin, lock_pc: u8) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(
                lock_pc <= 100,
                Error::<T>::PercentageGreaterThan100
            );
            ValidatorRewardsLockPercent::put(lock_pc);
            Ok(Pays::No.into())
        }

        /// Set percentage of emission rewards for treasury in each epoch
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_treasury_reward_pc(origin, reward_pc: u8) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(
                reward_pc <= 100,
                Error::<T>::PercentageGreaterThan100
            );
            TreasuryRewardsPercent::put(reward_pc);
            Ok(Pays::No.into())
        }

        /// Force a transfer using root to transfer balance of reserved as well as free kind.
        /// This call is dangerous and can be abused by a malicious Root
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn force_transfer_both(
            origin, source: <T::Lookup as StaticLookup>::Source, dest: <T::Lookup as StaticLookup>::Source,
            #[compact] free: BalanceOf<T>, #[compact] reserved: BalanceOf<T>
        ) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let source = T::Lookup::lookup(source)?;
            let dest = T::Lookup::lookup(dest)?;
            Self::force_transfer_both_(&source, &dest, free, reserved)?;
            Ok(Pays::No.into())
        }

        fn on_initialize(block_no: T::BlockNumber) -> Weight {
            Self::unlock_validator_rewards_if_needed(block_no)
        }
    }
}

impl<T: Trait> Module<T> {
    /// Add a validator. Check documentation of `add_validator` dispatchable
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

    /// Remove a validator. Check documentation of `remove_validator` dispatchable
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

        let active_validators: Vec<T::AccountId> = Self::active_validators();
        let validators_to_add: Vec<T::AccountId> = Self::validators_to_add();

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

    /// Swap existing validator. Check documentation of `swap_validator` dispatchable
    fn swap_validator_(
        old_validator_id: T::AccountId,
        new_validator_id: T::AccountId,
    ) -> dispatch::DispatchResult {
        let active_validators: Vec<T::AccountId> = Self::active_validators();

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

        <HotSwap<T>>::put((old_validator_id.clone(), new_validator_id.clone()));
        Self::deposit_event(RawEvent::ValidatorSwapped(
            old_validator_id,
            new_validator_id,
        ));
        Ok(())
    }

    /// The account ID that holds the Treasury's funds
    pub fn treasury_account() -> T::AccountId {
        TREASURY_ID.into_account()
    }

    /// Treasury's free balance. Only free balance makes sense for treasury in context of PoA
    pub fn treasury_balance() -> BalanceOf<T> {
        T::Currency::free_balance(&Self::treasury_account())
    }

    fn force_transfer_both_(
        source: &T::AccountId,
        dest: &T::AccountId,
        free: BalanceOf<T>,
        reserved: BalanceOf<T>,
    ) -> dispatch::DispatchResult {
        T::Currency::free_balance(source)
            .checked_sub(&free)
            .ok_or_else(|| Error::<T>::InsufficientFreeBalance)?;
        T::Currency::reserved_balance(source)
            .checked_sub(&reserved)
            .ok_or_else(|| Error::<T>::InsufficientReservedBalance)?;
        // ensure!((T::Cuurency::free_balance(source) >= free && T::Cuurency::reserved_balance(source) >= reserved), Error::<T>::InSufficientFreeOrReservedBalance);
        T::Currency::transfer(&source, &dest, free, AllowDeath)?;
        T::Currency::repatriate_reserved(&source, &dest, reserved, Reserved)?;
        Ok(())
    }

    /// Return total (validators + treasury) emission rewards for given epoch
    pub fn get_total_emission_in_epoch(epoch_no: EpochNo) -> BalanceOf<T> {
        // No need to check if epoch detail of the epoch exists or not. If it does not, `EpochDetail`
        // with default values will be returned which will have `emission_for_validators` and `emission_for_treasury` as 0.
        let epoch_detail = Self::get_epoch_detail(epoch_no);
        epoch_detail
            .emission_for_validators
            .unwrap_or_else(|| BalanceOf::<T>::zero())
            + epoch_detail
                .emission_for_treasury
                .unwrap_or_else(|| BalanceOf::<T>::zero())
    }

    /// Takes a validator id and a mutable vector of validator ids and remove any occurrence from
    /// the mutable vector. Returns number of removed occurrences
    fn remove_validator_id(id: &T::AccountId, validators: &mut Vec<T::AccountId>) -> usize {
        let old_size = validators.len();
        validators.retain(|v| v != id);
        old_size - validators.len()
    }

    /// Get maximum active validators (allowed) on current epoch end and for the next epoch. Reads
    /// from the tentative value set in storage and if set (>0), "take" it, i.e. read and reset to 0.
    /// Updates `MaxActiveValidators` as well
    fn get_and_set_max_active_validators_on_epoch_end() -> u8 {
        let max_v = MaxActiveValidatorsTentative::take();
        if max_v > 0 {
            MaxActiveValidators::put(max_v);
            max_v
        } else {
            Self::max_active_validators()
        }
    }

    /// Get minimum epoch length on current epoch end and for the next epoch. Reads from the tentative
    /// value set in storage and if set (>0), "take" it, i.e. read and reset to 0. Updates
    /// `MinEpochLength` as well
    fn get_and_set_min_epoch_length_on_epoch_end() -> EpochLen {
        let len = MinEpochLengthTentative::take();
        if len > 0 {
            MinEpochLength::put(len);
            len
        } else {
            Self::min_epoch_length()
        }
    }

    /// Update active validator set if needed and return if the active validator set changed and the
    /// count of the new active validators.
    fn update_active_validators_if_needed() -> (bool, u8) {
        let mut active_validators = Self::active_validators();
        let mut validators_to_add = Self::validators_to_add();
        // Remove any validators that need to be removed.
        let validators_to_remove = <RemoveValidators<T>>::take();

        // Need these flags as the debugging variables will `count_added` and `count_removed` be removed.
        let mut active_validator_set_changed = false;
        let mut queued_validator_set_changed = false;

        // If any validator is to be added or removed. This can happen if the there are any validators
        // to remove or there are validators to add or the no. of active validators is greater than max
        // allowed active validators
        // TODO: Remove debugging variable below
        let mut count_removed = 0;

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
                // validator set and queued validators with the exception of swap-in for an already queued validators.
                // This exception is guarded against when adding queued validator below.
                let removed_queued = Self::remove_validator_id(&v, &mut validators_to_add);
                if removed_queued > 0 {
                    queued_validator_set_changed = true;
                }
            }
        }

        // Get max allowed active validators
        let max_validators = Self::get_and_set_max_active_validators_on_epoch_end() as usize;

        // TODO: Remove debugging variable below
        let mut count_added = 0u32;

        // Make any queued validators active.
        while (active_validators.len() < max_validators) && (!validators_to_add.is_empty()) {
            let new_val = validators_to_add.remove(0);
            // Check if the validator to add is not already active. The check is needed as a swap
            // might make a validator as active which is already present in the queue.
            if !active_validators.contains(&new_val) {
                active_validators.push(new_val);
                active_validator_set_changed = true;
                queued_validator_set_changed = true;
                count_added += 1;
            }
        }

        // When max active validators is decreased (through `MaxActiveValidators`), appropriate no.
        // of active validators are moved to the front of the queued validators
        while active_validators.len() > max_validators {
            // `pop` will never return None as its ensured that neither `active_validators` can be
            // empty nor `max_validators` can be 0.
            let validator_id = active_validators.pop().unwrap();
            validators_to_add.insert(0, validator_id);
            active_validator_set_changed = true;
            queued_validator_set_changed = true;
            count_removed += 1;
        }

        // Only write if queued_validator_set_changed
        if queued_validator_set_changed {
            <QueuedValidators<T>>::put(validators_to_add);
        }

        let active_validator_count = active_validators.len() as u8;
        if active_validator_set_changed {
            log::debug!(
                target: "runtime",
                "Active validator set changed, rotating session. Added {} and removed {}",
                count_added, count_removed
            );
            <ActiveValidators<T>>::put(active_validators);
        }
        (active_validator_set_changed, active_validator_count)
    }

    /// Set next epoch duration such that it is >= `MinEpochLength` and also a multiple of the
    /// number of active validators
    fn set_next_epoch_end(current_slot_no: SlotNo, active_validator_count: u8) -> SlotNo {
        let min_epoch_len = Self::get_and_set_min_epoch_length_on_epoch_end();
        let active_validator_count = active_validator_count as EpochLen;
        let rem = min_epoch_len % active_validator_count;
        let epoch_len = if rem == 0 {
            min_epoch_len
        } else {
            min_epoch_len + active_validator_count - rem
        };
        // Current slot no is part of new epoch
        let epoch_ends_at = current_slot_no + epoch_len as SlotNo - 1;
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
    fn current_slot_no() -> Option<SlotNo> {
        let digest = <system::Module<T>>::digest();
        let logs = digest.logs();
        // The logs are added in `on_slot` function of slots pallet by the validator
        if !logs.is_empty() {
            // Assumes that the first log is for PreRuntime digest
            match logs[0].as_pre_runtime() {
                // The first log is added with `pre_digest_data` function of `SimpleSlotWorker`
                Some(pre_run) => {
                    // Assumes that the 2nd element of tuple is for slot no.
                    let s = SlotNo::decode(&mut &pre_run.1[..]).unwrap();
                    log::debug!(target: "runtime", "current slot no is {}", s);
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
    fn short_circuit_current_epoch() -> SlotNo {
        let current_slot_no = Self::current_slot_no().unwrap();
        // Moving the logic to separate method to keep it testable
        Self::update_current_epoch_end_on_short_circuit(current_slot_no)
    }

    /// Updates storage for end of current epoch on premature ending of epoch.
    /// Takes the current slot no.
    fn update_current_epoch_end_on_short_circuit(current_slot_no: SlotNo) -> SlotNo {
        let current_epoch_no = Self::epoch();
        let epoch_detail = Self::get_epoch_detail(current_epoch_no);
        let active_validator_count = epoch_detail.validator_count as SlotNo;
        let current_progress = current_slot_no - epoch_detail.starting_slot + 1;
        let rem = current_progress % active_validator_count;
        let epoch_ends_at = if rem == 0 {
            current_slot_no
        } else {
            current_slot_no + active_validator_count - rem
        };
        EpochEndsAt::put(epoch_ends_at);
        log::debug!(
            target: "runtime",
            "Epoch {} prematurely ending at slot {}",
            current_epoch_no,
            epoch_ends_at
        );
        epoch_ends_at
    }

    /// Increment count of authored block for the current epoch by the given author
    fn increment_current_epoch_block_count(block_author: T::AccountId) {
        let current_epoch_no = Self::epoch();
        let mut stats = Self::get_validator_stats_for_epoch(current_epoch_no, &block_author);
        // Not doing saturating add as its practically impossible to produce 2^32 blocks
        stats.block_count += 1;
        <ValidatorStats<T>>::insert(current_epoch_no, block_author, stats);
    }

    /// Get count of slots reserved for a validator in given epoch. Considers the length of epoch
    /// and no of validators in the epoch and calculates slots that were reserved for each validator.
    /// Handles the cases where an epoch was short circuited or the epoch seems (apparently) extended
    /// as node crashed.
    fn get_slots_per_validator(
        epoch_detail: &EpochDetail<BalanceOf<T>>,
        ending_slot: SlotNo,
        block_count: &BlockCount,
    ) -> EpochLen {
        if epoch_detail.expected_ending_slot >= ending_slot {
            // Epoch was either short circuited or ended in the expected slot
            if epoch_detail.expected_ending_slot > ending_slot {
                log::debug!(
                    target: "runtime",
                    "Epoch ending early. Swap or epoch short circuited. Ending slot {}",
                    ending_slot
                );
            }
            // This can be slightly disadvantageous for the highest block producer(s) if the following
            // division leaves a remainder (in case of shorter epoch). The disadvantage is loss of emission reward on 1 block.
            ((ending_slot - epoch_detail.starting_slot + 1)
                / epoch_detail.validator_count as SlotNo) as EpochLen
        } else {
            log::debug!(
                target: "runtime",
                "Epoch ending late. This means the network stopped in between. Ending slot {}",
                ending_slot
            );
            match block_count {
                BlockCount::MaxBlocks(max_blocks) => {
                    // At least one of the validator produced more blocks than the rest
                    // Pick slot as every one should have got max_blocks - 1 slots at least, this is slightly
                    // disadvantageous for the highest block producer as he does not get paid for one block.
                    if *max_blocks > 0 {
                        *max_blocks - 1
                    } else {
                        0
                    }
                }
                // All validator produced same no of blocks so that no of slots were taken by each validator
                BlockCount::SameBlocks(count) => *count,
            }
        }
    }

    /// Return an enum containing either maximum number of blocks produced by any validator if all validators
    /// did not produce equal blocks in the epoch or the number of blocks if they produced the same number.
    /// Also return count of blocks produced by each validator in a map.
    fn count_validator_blocks(
        current_epoch_no: EpochNo,
    ) -> (BlockCount, BTreeMap<T::AccountId, EpochLen>) {
        let mut validator_block_counts = BTreeMap::new();
        let mut max_blocks = 0;
        // Flag to check if all validators produced same blocks
        let mut same_block_count = true;
        let validators = Self::active_validators();
        for (i, v) in validators.into_iter().enumerate() {
            let stats = Self::get_validator_stats_for_epoch(current_epoch_no, &v);
            let block_count = stats.block_count;
            if i == 0 {
                // first iteration
                max_blocks = block_count
            } else {
                if max_blocks != block_count {
                    // Block count of this validator is different from previous, set the flag as false
                    same_block_count = false;
                }
                if block_count > max_blocks {
                    max_blocks = block_count;
                }
            }
            log::debug!(target: "runtime", "Validator {:?} has blocks {}", v, block_count);
            validator_block_counts.insert(v, block_count);
        }
        (
            if same_block_count {
                BlockCount::SameBlocks(max_blocks)
            } else {
                BlockCount::MaxBlocks(max_blocks)
            },
            validator_block_counts,
        )
    }

    /// Emission rewards per epoch are set assuming the epoch is of at least `MinEpochLength` and thus
    /// each validator gets at least `MinEpochLength` / (validator count) number of slots. When this is
    /// not the case, decrease emission rewards proportionally.
    /// Assumes that `slots_per_validator` is not 0 and <= expected_slots_per_validator.
    fn get_max_emission_reward_per_validator_per_epoch(
        expected_slots_per_validator: EpochLen,
        slots_per_validator: EpochLen,
    ) -> BalanceOf<T> {
        // Maximum emission reward for each validator in an epoch assuming epoch was at least `MinEpochLength`
        let max_em = Self::max_emm_validator_epoch();
        if slots_per_validator != expected_slots_per_validator {
            // Reduce the emission for shorter epoch
            max_em.saturating_mul(slots_per_validator.into())
                / <BalanceOf<T>>::from(expected_slots_per_validator)
        } else {
            max_em
        }
    }

    /// Calculate reward for treasury in an epoch given total reward for validators
    fn calculate_treasury_reward(total_validator_reward: BalanceOf<T>) -> BalanceOf<T> {
        let treasury_reward_pc = <BalanceOf<T>>::from(Self::treasury_reward_pc() as u32);
        (total_validator_reward.saturating_mul(treasury_reward_pc))
            / <BalanceOf<T>>::from(100 as u32)
    }

    /// Credit locked balance to validator's account as reserved balance
    fn credit_locked_emission_rewards_to_validator(validator: &T::AccountId, locked: BalanceOf<T>) {
        // Only proceed if locked balance > 0 as we don't care about positive imbalances (0 or otherwise)
        if locked > BalanceOf::<T>::zero() {
            // Deposit locked balance
            T::Currency::deposit_creating(validator, locked);
            // Reserve the balance.
            // The following unwrap will never throw error as the balance to reserve was just transferred.
            T::Currency::reserve(validator, locked).unwrap();
        }
    }

    /// Credit unlocked and locked balance to validator's account
    fn credit_emission_rewards_to_validator(
        validator: &T::AccountId,
        locked: BalanceOf<T>,
        unlocked: BalanceOf<T>,
    ) {
        T::Currency::deposit_creating(validator, unlocked);
        Self::credit_locked_emission_rewards_to_validator(validator, locked)
    }

    /// Track locked and unlocked reward for each validator in the given epoch and return sum of
    /// emission rewards (locked + unlocked) for all validators
    fn mint_and_track_validator_rewards_for_rewarding_epoch(
        current_epoch_no: EpochNo,
        expected_slots_per_validator: EpochLen,
        slots_per_validator: EpochLen,
        validator_block_counts: BTreeMap<T::AccountId, EpochLen>,
    ) -> BalanceOf<T> {
        let mut total_validator_reward = BalanceOf::<T>::zero();
        // Maximum emission per validator in this epoch
        let max_em = Self::get_max_emission_reward_per_validator_per_epoch(
            expected_slots_per_validator,
            slots_per_validator,
        );
        let lock_pc = <BalanceOf<T>>::from(Self::validator_reward_lock_pc() as u32);
        for (v, block_count) in validator_block_counts {
            // The actual emission rewards depends on the availability, i.e. ratio of blocks produced
            // to slots available

            // In case of a crash, it might happen that some validators produce more blocks than others
            // and thus their block count > `slots_per_validator` but only by 1. In that case, adjust
            // their block count so that their reward does not exceed maximum (adjusted) reward for epoch
            let adjusted_block_count = if (block_count > 0) && (block_count > slots_per_validator) {
                if (block_count - 1) != slots_per_validator {
                    panic!("THIS SHOULD NEVER TRIGGER. ADJUSTED BLOCK COUNT NOT EQUAL TO SLOTS PER VALIDATOR");
                }
                block_count - 1
            } else {
                block_count
            };
            let reward = max_em.saturating_mul(adjusted_block_count.into())
                / <BalanceOf<T>>::from(slots_per_validator);

            let locked_reward = (reward.saturating_mul(lock_pc)) / <BalanceOf<T>>::from(100 as u32);
            let unlocked_reward = reward.saturating_sub(locked_reward);
            Self::credit_emission_rewards_to_validator(&v, locked_reward, unlocked_reward);
            <ValidatorStats<T>>::insert(
                current_epoch_no,
                v,
                ValidatorStatsPerEpoch {
                    block_count,
                    locked_reward: Some(locked_reward),
                    unlocked_reward: Some(unlocked_reward),
                },
            );
            total_validator_reward = total_validator_reward.saturating_add(reward);
        }
        total_validator_reward
    }

    /// Mint emission rewards for treasury and credit to the treasury account
    fn mint_treasury_emission_rewards(total_validator_reward: BalanceOf<T>) -> BalanceOf<T> {
        let treasury_reward = Self::calculate_treasury_reward(total_validator_reward);
        T::Currency::deposit_creating(&Self::treasury_account(), treasury_reward);
        treasury_reward
    }

    /// Track validator rewards for epoch with no rewards. The tracked rewards will be 0
    fn update_validator_stats_for_worthless_epoch(
        current_epoch_no: EpochNo,
        validator_block_counts: BTreeMap<T::AccountId, EpochLen>,
    ) {
        for (v, block_count) in validator_block_counts {
            <ValidatorStats<T>>::insert(
                current_epoch_no,
                v,
                ValidatorStatsPerEpoch {
                    block_count,
                    locked_reward: Some(BalanceOf::<T>::zero()),
                    unlocked_reward: Some(BalanceOf::<T>::zero()),
                },
            );
        }
    }

    /// Calculate validator and treasury rewards for epoch with non-zero rewards and reward each
    /// validator. During each epoch, the network will offer at most `p` tokens to each validator,
    /// thus the network (with `n` validators) will offer at max `p*n` Dock tokens in total to all validators.
    /// If a validator is fully available, i.e. it produces all the blocks that it can, it will get `p` tokens
    /// in the epoch. However, if the validator is unavailable for some time (the node crashed, the network was
    /// down or some other reason), they get proportionately less rewards. The max rewards `p` will decrease in
    /// proportion if epoch is shorter than minimum epoch length. Once the total rewards for validators
    /// are calculated, an extra `t` percent of that is emitted for the treasury.
    fn mint_and_track_rewards_for_rewarding_epoch(
        epoch_detail: &mut EpochDetail<BalanceOf<T>>,
        current_epoch_no: EpochNo,
        slots_per_validator: EpochLen,
        validator_block_counts: BTreeMap<T::AccountId, EpochLen>,
    ) {
        let total_validator_reward = Self::mint_and_track_validator_rewards_for_rewarding_epoch(
            current_epoch_no,
            epoch_detail.expected_slots_per_validator(),
            slots_per_validator,
            validator_block_counts,
        );

        // Treasury's reward depends on the total reward for validators in the epoch
        let treasury_reward = Self::mint_treasury_emission_rewards(total_validator_reward);

        // Total reward is reward for treasury and validators
        let total_reward = total_validator_reward.saturating_add(treasury_reward);

        // Subtract from total supply
        let mut emission_supply = <EmissionSupply<T>>::take();
        emission_supply = emission_supply.saturating_sub(total_reward);
        <EmissionSupply<T>>::put(emission_supply.saturated_into::<BalanceOf<T>>());

        epoch_detail.emission_for_treasury = Some(treasury_reward);
        epoch_detail.emission_for_validators = Some(total_validator_reward);
    }

    /// Calculate validator and treasury rewards for epoch with 0 rewards. The tracked rewards will be 0
    fn update_epoch_detail_for_worthless_epoch(
        epoch_detail: &mut EpochDetail<BalanceOf<T>>,
        current_epoch_no: EpochNo,
        validator_block_counts: BTreeMap<T::AccountId, EpochLen>,
    ) {
        Self::update_validator_stats_for_worthless_epoch(current_epoch_no, validator_block_counts);
        epoch_detail.emission_for_treasury = Some(BalanceOf::<T>::zero());
        epoch_detail.emission_for_validators = Some(BalanceOf::<T>::zero());
    }

    /// Mint emission rewards and disburse them among validators and treasury. Returns true if emission
    /// rewards were minted, false otherwise.
    fn mint_emission_rewards_if_needed(
        current_epoch_no: EpochNo,
        ending_slot: SlotNo,
        epoch_detail: &mut EpochDetail<BalanceOf<T>>,
    ) -> bool {
        // Get blocks authored by each validator
        let (max_blocks, validator_block_counts) = Self::count_validator_blocks(current_epoch_no);

        // If emission is disabled, return false after updating validators' block count and rewards
        if !Self::emission_status() {
            Self::update_epoch_detail_for_worthless_epoch(
                epoch_detail,
                current_epoch_no,
                validator_block_counts,
            );
            return false;
        }

        // Emission is enabled, move on
        let emission_supply = Self::emission_supply();

        // The check below is not accurate as the remaining emission supply might be > 0 but not sufficient
        // to reward all validators and treasury; we would be over-issuing in that case. This is not a
        // concern for us as the supply won't go down for the life of the PoA network. A more accurate
        // check would be to get the maximum emission rewards in the epoch with `count_validatiors * max_emission_per_valdiator * (1 + treasury_share_percent/100)`
        // and don't mint if remaining emission supply is less than above. This would leave some supply
        // unminted for some amount of time, maybe indefinitely. Another option is to reduce rewards of
        // all parties (or maybe some parties) by a certain percentage so that remaining supply is sufficient.
        if emission_supply == BalanceOf::<T>::zero() {
            Self::update_epoch_detail_for_worthless_epoch(
                epoch_detail,
                current_epoch_no,
                validator_block_counts,
            );
            return false;
        }

        // Get slots received by each validator
        let slots_per_validator =
            Self::get_slots_per_validator(&epoch_detail, ending_slot, &max_blocks);
        log::debug!(target: "runtime", "slots_per_validator {}", slots_per_validator);

        // It might happen that `slots_per_validator` > `max_blocks` as the network went down for
        // a brief moment of time but a validator should not be able to produce any more than 1 blocks
        // more than the slots allowed per validator. The cushion of 1 is given in the case when network
        // abruptly terminates and some validators don't get a chance to produce blocks
        let max_bl = max_blocks.to_number();
        if max_bl.saturating_sub(slots_per_validator) > 1 {
            log::error!(target: "poa", "slots_per_validator={} max_blocks.to_number()={}", slots_per_validator, max_bl);
            panic!(
                "THIS PANIC SHOULD NEVER TRIGGER: max_blocks.to_number() > slots_per_validator + 1"
            );
        }

        if slots_per_validator > 0 {
            Self::mint_and_track_rewards_for_rewarding_epoch(
                epoch_detail,
                current_epoch_no,
                slots_per_validator,
                validator_block_counts,
            );
            true
        } else {
            // No slots claimed, 0 rewards for validators and treasury
            Self::update_epoch_detail_for_worthless_epoch(
                epoch_detail,
                current_epoch_no,
                validator_block_counts,
            );
            false
        }
    }

    /// Track epoch ending slot and rewards for validators and treasury and mint and disburse the rewards.
    fn update_details_for_ending_epoch(current_slot_no: SlotNo) {
        let current_epoch_no = Self::epoch();
        if current_epoch_no == 0 {
            print("Starting up, no epoch to update");
            return;
        }
        let ending_slot = current_slot_no - 1;
        log::debug!(
            target: "runtime",
            "Epoch {} ends at slot {}",
            current_epoch_no, ending_slot
        );
        let mut epoch_detail = Self::get_epoch_detail(current_epoch_no);
        epoch_detail.ending_slot = Some(ending_slot);

        log::debug!(target: "runtime", "Epoch {} ending at slot {}", current_epoch_no, ending_slot);

        Self::mint_emission_rewards_if_needed(current_epoch_no, ending_slot, &mut epoch_detail);

        Epochs::<T>::insert(current_epoch_no, epoch_detail);

        Self::deposit_event(RawEvent::EpochEnds(current_epoch_no, ending_slot));
    }

    /// Set the current epoch, starting slot, expected ending of the current epoch and active validator
    /// count for this epoch
    fn update_details_on_new_epoch(
        current_epoch_no: EpochNo,
        current_slot_no: SlotNo,
        active_validator_count: u8,
    ) {
        log::debug!(
            target: "runtime",
            "Epoch {} begins at slot {}",
            current_epoch_no,
            current_slot_no
        );
        Epoch::put(current_epoch_no);
        let expected_ending = Self::epoch_ends_at();

        Epochs::<T>::insert(
            current_epoch_no,
            EpochDetail::new(active_validator_count, current_slot_no, expected_ending),
        );
        Self::deposit_event(RawEvent::EpochBegins(
            current_epoch_no,
            current_slot_no,
            expected_ending,
        ));
    }

    /// The validator set needs to update, either due to swap or epoch end.
    fn update_validator_set(
        current_slot_no: SlotNo,
        epoch_ends_at: SlotNo,
        swap: Option<(T::AccountId, T::AccountId)>,
    ) -> (bool, u8) {
        match Self::swap_if_needed(swap) {
            Some(count) => {
                // Swap occurred, check if the swap coincided with an epoch end
                if current_slot_no > epoch_ends_at {
                    let (_, new_count) = Self::update_active_validators_if_needed();
                    // Potential optimization: There is a chance that `update_active_validators_if_needed`
                    // undoes the swap and in that case `rotate_session` can be avoided. Not doing the
                    // optimization here.
                    (true, new_count)
                } else {
                    // Epoch did not end but swap did happen
                    (true, count)
                }
            }
            None => Self::update_active_validators_if_needed(),
        }
    }

    /// Unlock emission rewards for validators. Checks if there is any epoch for which rewards need to
    /// be unlocked and if it does then unlocks the reward for all validators for that epoch and also sets
    /// up next epoch which should be unlocked. Return the the weight (only DB weight is considered)
    fn unlock_validator_rewards_if_needed(current_block_no: T::BlockNumber) -> Weight {
        let mut weight = T::DbWeight::get().reads(1); // For reading `NextEpochToReward`

        if let Some((epoch_no, ending_block, all_epochs_unlocked)) = Self::next_epoch_to_reward() {
            if !all_epochs_unlocked && (current_block_no > ending_block) {
                weight += Self::unlock_rewards_for_validators(epoch_no);
                Self::find_and_setup_next_epoch_to_unlock(epoch_no + 1, current_block_no);
            }
        } else {
            weight += Self::find_and_setup_next_epoch_to_unlock(1, current_block_no);
        }
        weight
    }

    /// Find next epoch to unlock and set storage `NextEpochToReward` accordingly and return weight
    fn find_and_setup_next_epoch_to_unlock(
        start_from_epoch: EpochNo,
        current_block_no: T::BlockNumber,
    ) -> Weight {
        let mut weight = 0;
        let epoch_no = Self::find_next_epoch_to_unlock(start_from_epoch, &mut weight);
        weight += epoch_no.map_or_else(
            || {
                // No more epoch to unlock, set false in NextEpochToReward
                <NextEpochToReward<T>>::mutate(|n| {
                    if let Some((_, _, all_epochs_unlocked)) = n {
                        *all_epochs_unlocked = true;
                    }
                });
                T::DbWeight::get().writes(1)
            },
            |e| Self::setup_new_epoch_to_unlock(e, current_block_no),
        );
        weight
    }

    /// Starting from `start_from` epoch (inclusive), finds the next epoch to unlock. Returns None
    /// if there are no more epochs to unlock. The weight argument is updated with the weight consumed.
    fn find_next_epoch_to_unlock(start_from: EpochNo, weight: &mut Weight) -> Option<EpochNo> {
        let mut epoch_no = start_from;
        loop {
            let epoch = Self::get_epoch_detail(epoch_no);
            *weight += T::DbWeight::get().reads(1);
            if epoch.expected_ending_slot == 0 {
                // No more epochs to unlock as the `expected_ending_slot` is always set to non-zero
                return None;
            }
            // If an epoch had no rewards for validators likely due to disabling of emission rewards,
            // then it doesn't make sense to include that delay in the unlocking period.
            if epoch
                .emission_for_validators
                .unwrap_or(BalanceOf::<T>::zero())
                > BalanceOf::<T>::zero()
            {
                // Epoch has rewards for validator, need to unlock this
                break;
            }
            // Check next epoch
            epoch_no += 1;
        }
        Some(epoch_no)
    }

    /// Setup storage item `NextEpochToReward` with the next epoch to unlock
    fn setup_new_epoch_to_unlock(epoch_no: EpochNo, current_block_no: T::BlockNumber) -> Weight {
        let mut weight = 0;
        let max_block_count = Self::max_block_count_in_epoch(epoch_no, &mut weight);
        let ending_block = if max_block_count > 0 {
            current_block_no + T::BlockNumber::from(max_block_count - 1)
        } else {
            // Probably means the end of tracked epochs. It should not be the case that an epoch did not
            // have any blocks but just in case
            current_block_no
        };
        <NextEpochToReward<T>>::put((epoch_no, ending_block, false));
        weight += T::DbWeight::get().writes(1);
        weight
    }

    /// Unlocks rewards for all validators for the given epoch and return the weight (only DB weight
    /// is considered). As part of unlock, it sets the `locked_reward` field to 0 and increments the
    /// `unlocked_reward` field.
    fn unlock_rewards_for_validators(epoch_no: EpochNo) -> Weight {
        let mut reads = 0;
        let mut writes = 0;
        for (validator_account, mut stats) in <ValidatorStats<T>>::iter_prefix(epoch_no) {
            reads += 1;
            if let Some(locked) = stats.locked_reward {
                if locked > BalanceOf::<T>::zero() {
                    let rem = T::Currency::unreserve(&validator_account, locked);
                    if !rem.is_zero() {
                        // This should never happen
                        log::error!(
                            target: "runtime",
                            "For epoch {}, unreserving locked reward of {:?} returned {:?}",
                            epoch_no, validator_account, locked
                        );
                    }
                    let actual_reward = locked.saturating_sub(rem);
                    Self::deposit_event(RawEvent::RewardUnlocked(
                        epoch_no,
                        validator_account.clone(),
                        actual_reward,
                    ));
                    stats.locked_reward = Some(BalanceOf::<T>::zero());
                    stats.unlocked_reward = stats
                        .unlocked_reward
                        .map_or(Some(actual_reward), |u| Some(u + actual_reward));
                    <ValidatorStats<T>>::insert(epoch_no, validator_account, stats);
                    writes += 2;
                } else {
                    log::info!(
                        target: "runtime",
                        "For epoch {}, locked reward of {:?} wasn't greater than 0",
                        epoch_no, validator_account
                    );
                }
            }
        }
        T::DbWeight::get().reads_writes(reads, writes)
    }

    /// Return maximum blocks produced by a validator in the given epoch. It accepts a mutable which
    /// is incremented with the weight of DB read calls made during the process.
    fn max_block_count_in_epoch(epoch_no: EpochNo, weight: &mut Weight) -> EpochLen {
        let mut max_block_count = 0;
        for stats in <ValidatorStats<T>>::iter_prefix_values(epoch_no) {
            *weight += T::DbWeight::get().reads(1);
            if max_block_count < stats.block_count {
                max_block_count = stats.block_count
            }
        }
        max_block_count
    }
}

// NOTE: Session handling is no more done by this pallet.

/// Indicates to the session module if the session should be rotated.
/// The following query function modifies the state as well. If an epoch is ending it calculates the
/// ending epoch's block counts and rewards and mints the rewards and transfers to the intended recipients.
/// It also calculates the validator set if the validator set needs to change and calls `rotate_session`
/// explicitly such that delay of 1 session for validator set change can be avoided as another call to
/// `rotate_session` will be made when this function returns true; thus 2 calls to `rotate_session`
/// in total if validator set changes, otherwise one (non explicit call)
/// To make this a "pure" query, i.e. without any state modifications, apart from `new_session`
/// doing the accounting done by this function, it has to make 2 calls to `rotate_session` with an
/// integer storage flag handling for recursive calls (flag decrements on each call) since
/// `rotate_session` calls `new_session`; this will make total calls to `rotate_session`
/// as 3 (2 explicit by `new_session`, 1 implicit by this function).
impl<T: Trait> pallet_session::ShouldEndSession<T::BlockNumber> for Module<T> {
    fn should_end_session(_now: T::BlockNumber) -> bool {
        print("Called should_end_session");

        let current_slot_no = match Self::current_slot_no() {
            Some(s) => s,
            None => {
                print("Cannot fetch slot number");
                return false;
            }
        };

        let epoch_ends_at = Self::epoch_ends_at();
        log::debug!(
            target: "runtime",
            "epoch ends at {}",
            epoch_ends_at
        );

        // Unless the epoch has had the required number of blocks, or hot swap is triggered, continue the session.
        let swap = <HotSwap<T>>::take();

        if (current_slot_no > epoch_ends_at) || swap.is_some() {
            // Mint and disburse rewards to validators and treasury for the ending epoch
            Self::update_details_for_ending_epoch(current_slot_no);

            let (active_validator_set_changed, active_validator_count) =
                Self::update_validator_set(current_slot_no, epoch_ends_at, swap);

            if active_validator_set_changed {
                // `ActiveValidators` has become different from `<pallet_session::Validators>`

                // Manually calling `rotate_session` will make the new validator set change take effect
                // on next session (as `rotate_session` will be called again once this function returns true)
                // The flag will be set to false on in `new_session`. This should not be set here (after
                // `rotate_session` to avoid a deadlock in case of immediate node crash after `rotate_session`)
                ForcedSessionRotation::put(true);
                <pallet_session::Module<T>>::rotate_session();

                // `ActiveValidators` is again same as `<pallet_session::Validators>`
            }

            let last_slot_for_next_epoch =
                Self::set_next_epoch_end(current_slot_no, active_validator_count);
            log::debug!(
                target: "runtime",
                "next epoch will end at {}",
                last_slot_for_next_epoch
            );
            true
        } else {
            false
        }
    }
}

/// Provides the new set of validators to the session module when session is being rotated.
impl<T: Trait> pallet_session::SessionManager<T::AccountId> for Module<T> {
    // `SessionIndex` is u32 but comes from sp_staking pallet. Since staking is not needed for now, not
    // importing the pallet.

    fn new_session(session_idx: u32) -> Option<Vec<T::AccountId>> {
        print("Called new_session");
        // Calling init here for the lack of a better place.
        // The init will be called on beginning of each session.
        RuntimeLogger::init();

        log::debug!(
            target: "runtime",
            "Current session index {}",
            session_idx
        );

        let validators = Self::active_validators();
        if validators.is_empty() {
            // On genesis
            return None;
        }
        if session_idx < 2 {
            // `session_idx` 0 and 1 are called on genesis
            Some(validators)
        } else if Self::forced_session_rotation() {
            // this function will be called again as `should_end_session` will return true
            ForcedSessionRotation::put(false);
            Some(validators)
        } else {
            let current_epoch_no = Self::epoch() + 1;
            // This slot number should always be available here. If its not then panic.
            let current_slot_no = Self::current_slot_no().unwrap();

            let active_validator_count = validators.len() as u8;
            Self::update_details_on_new_epoch(
                current_epoch_no,
                current_slot_no,
                active_validator_count,
            );
            // Validator set unchanged, return None
            None
        }
    }

    fn end_session(_: u32) {}
    fn start_session(_: u32) {}
}
