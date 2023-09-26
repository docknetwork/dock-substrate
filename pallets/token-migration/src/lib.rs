//! Pallet for token migration from ERC-20 to Dock's native token. Migrators are assumed to not be adversarial
//! and not do DoS attacks on the chain and are the exchanges in practice. Migrators are given balance
//! by Dock to fulfil expected migration requests and Dock needs to ensure that migrators do hold the
//! correct amount of ERC-20 and that they will lock it (request signature from addresses to check ownership
//! and monitor addresses or ask them to transfer to the Vault). Also bonus amounts are calculated post
//! the initial migration and depend on the participating holder and their vesting choice which Dock
//! should verify with external migrators.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::*,
    ensure, fail,
    sp_runtime::{
        traits::{
            CheckedAdd, CheckedSub, Convert, DispatchInfoOf, Saturating, SignedExtension,
            StaticLookup, Zero,
        },
        transaction_validity::{
            InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
        },
        RuntimeDebug,
    },
    traits::{
        Currency, ExistenceRequirement, ExistenceRequirement::AllowDeath, Get, IsSubType,
        ReservableCurrency, WithdrawReasons,
    },
    weights::{Pays, Weight},
    CloneNoBound, DefaultNoBound, EqNoBound, PartialEqNoBound, WeakBoundedVec,
};
use sp_std::{marker::PhantomData, prelude::Vec};

pub use pallet::*;

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;

/// Struct to encode all the bonuses of an account.
#[derive(
    Encode,
    Decode,
    scale_info::TypeInfo,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    RuntimeDebug,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
pub struct Bonus<T: Config> {
    /// Each element of the vector is swap bonus and the block number at which it unlocks
    pub swap_bonuses: WeakBoundedVec<(BalanceOf<T>, T::BlockNumber), T::MaxSwapBonuses>,
    /// Each element of the vector is total bonus (set only once when bonus is given), remaining locked bonus and starting block number
    pub vesting_bonuses:
        WeakBoundedVec<(BalanceOf<T>, BalanceOf<T>, T::BlockNumber), T::MaxVestingBonuses>,
}

impl<T: Config> Bonus<T> {
    fn is_empty(&self) -> bool {
        self.swap_bonuses.is_empty() && self.vesting_bonuses.is_empty()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    /// The pallet's configuration trait.
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type Event: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;

        /// Currency type that supports locking
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Convert the block number into a balance.
        type BlockNumberToBalance: Convert<Self::BlockNumber, BalanceOf<Self>>;

        /// NOTE: Both `VestingMilestones` and `VestingDuration` must be > 0. The ideal situation would be
        /// to have a compile time assertion in this pallet but since the static assertions pallet does
        /// not work with generics (https://github.com/nvzqz/static-assertions-rs/issues/21), the check
        /// has been moved to the runtime instantiation. If this pallet is used outside this project,
        /// corresponding checks should be done.

        /// Vesting happens in milestones. The total duration is sub-divided into equal duration milestones
        /// and for each milestone, proportional balance is vested.
        /// This might be moved to a storage item if needs to be configurable but is less likely.
        type VestingMilestones: Get<u8>;

        /// Vesting duration in number of blocks.
        type VestingDuration: Get<u32>;

        type MaxSwapBonuses: Get<u32>;
        type MaxVestingBonuses: Get<u32>;
    }

    /// Track accounts registered as migrators
    #[pallet::storage]
    #[pallet::getter(fn migrators)]
    pub type Migrators<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u16>;

    /// Tracks swap and vesting bonuses that will be given to holders
    #[pallet::storage]
    #[pallet::getter(fn bonus)]
    pub type Bonuses<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Bonus<T>>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Migrator transferred tokens
        Migration(
            <T as frame_system::Config>::AccountId,
            <T as frame_system::Config>::AccountId,
            BalanceOf<T>,
        ),

        /// New migrator added
        MigratorAdded(<T as frame_system::Config>::AccountId, u16),

        /// Existing migrator removed
        MigratorRemoved(<T as frame_system::Config>::AccountId),

        /// Migrator's allowed migrations increased
        MigratorExpanded(<T as frame_system::Config>::AccountId, u16),

        /// Migrator's allowed migrations decreased
        MigratorContracted(<T as frame_system::Config>::AccountId, u16),

        /// Swap bonus was added. Parameters are sender, receiver, bonus, unlock block number
        SwapBonusAdded(
            <T as frame_system::Config>::AccountId,
            <T as frame_system::Config>::AccountId,
            BalanceOf<T>,
            <T as frame_system::Config>::BlockNumber,
        ),

        /// Swap bonus was claimed
        SwapBonusClaimed(<T as frame_system::Config>::AccountId, BalanceOf<T>),

        /// Vesting bonus was added. Parameters are sender, receiver, bonus, starting block number
        VestingBonusAdded(
            <T as frame_system::Config>::AccountId,
            <T as frame_system::Config>::AccountId,
            BalanceOf<T>,
            <T as frame_system::Config>::BlockNumber,
        ),

        /// Vesting bonus was claimed
        VestingBonusClaimed(<T as frame_system::Config>::AccountId, BalanceOf<T>),
    }

    /// Errors for the module.
    #[pallet::error]
    pub enum Error<T> {
        MigratorAlreadyPresent,
        UnknownMigrator,
        ExceededMigrations,
        CannotExpandMigrator,
        CannotContractMigrator,
        InsufficientBalance,
        /// Overflow while doing bonus calculations
        BonusOverflowError,
        /// The account has no bonus.
        NoBonus,
        /// The account has no swap bonus.
        NoSwapBonus,
        /// Has a swap bonus but cannot claim yet.
        CannotClaimSwapBonusYet,
        /// Vesting has not started yet.
        VestingNotStartedYet,
        /// The account has no vesting bonus.
        NoVestingBonus,
        /// Has a vesting bonus but cannot claim yet.
        CannotClaimVestingBonusYet,
        TooManyBonuses,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// The module declaration.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Does a token migration. The migrator should have sufficient balance to give tokens to recipients
        /// The check whether it is a valid migrator is made inside the SignedExtension.
        /// Migrators are assumed to not be adversarial and not do DoS attacks on the chain. They might act
        /// in their benefit and try to send more fee txns then allowed which is guarded against.
        /// A bad migrator can flood the network with properly signed but invalid txns like trying to pay more
        /// than he has, make the network reject his txn but still spend network resources for free.
        #[pallet::weight((T::DbWeight::get().reads_writes(3 + recipients.len() as u64, 1 + recipients.len() as u64) + Weight::from_ref_time(22_100 * recipients.len() as u64), Pays::No))]
        pub fn migrate(
            origin: OriginFor<T>,
            recipients: BTreeMap<T::AccountId, BalanceOf<T>>,
        ) -> DispatchResult {
            let migrator = ensure_signed(origin)?;
            Self::migrate_(migrator, recipients)
        }

        /// Increase the migrators allowed migrations by the given number
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn expand_migrator(
            origin: OriginFor<T>,
            migrator: T::AccountId,
            increase_migrations_by: u16,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            match Self::migrators(&migrator) {
                Some(current_migrations) => {
                    let new_migrations = current_migrations
                        .checked_add(increase_migrations_by)
                        .ok_or(Error::<T>::CannotExpandMigrator)?;
                    Migrators::<T>::insert(migrator.clone(), new_migrations);
                    Self::deposit_event(Event::MigratorExpanded(migrator, new_migrations));
                    Ok(Pays::No.into())
                }
                None => fail!(Error::<T>::UnknownMigrator),
            }
        }

        /// Decrease the migrators allowed migrations by the given number
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn contract_migrator(
            origin: OriginFor<T>,
            migrator: T::AccountId,
            decrease_migrations_by: u16,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let new_migrations = Self::migrators(&migrator)
                .ok_or(Error::<T>::UnknownMigrator)?
                .checked_sub(decrease_migrations_by)
                .ok_or(Error::<T>::CannotContractMigrator)?;
            Migrators::<T>::insert(&migrator, new_migrations);
            Self::deposit_event(Event::MigratorContracted(migrator, new_migrations));
            Ok(Pays::No.into())
        }

        /// Add a new migrator
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn add_migrator(
            origin: OriginFor<T>,
            migrator: T::AccountId,
            allowed_migrations: u16,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(
                !Migrators::<T>::contains_key(&migrator),
                Error::<T>::MigratorAlreadyPresent
            );
            Migrators::<T>::insert(migrator.clone(), allowed_migrations);
            Self::deposit_event(Event::MigratorAdded(migrator, allowed_migrations));
            Ok(Pays::No.into())
        }

        /// Remove an existing migrator
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn remove_migrator(
            origin: OriginFor<T>,
            migrator: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(
                Migrators::<T>::contains_key(&migrator),
                Error::<T>::UnknownMigrator
            );
            Migrators::<T>::remove(&migrator);
            Self::deposit_event(Event::MigratorRemoved(migrator));
            Ok(Pays::No.into())
        }

        /// Give bonuses to recipients. Only callable by migrator. An alternate data structure of both bonus args could be a map from AccountId -> Set<(amount, offset)>
        /// # <weight>
        /// 2 storage entries are touched (read and write) per recipient, its account and bonus. Repeated recipients are not counted.
        /// Locks don't contribute to DB weight as once an account data is read from disk, locks are loaded as well
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(({
            // Find unique accounts as number of reads and writes depend on them
            let mut set = BTreeSet::<T::AccountId>::new();
            for (a, _, _) in swap_bonus_recips.iter() {
                set.insert(a.clone());
            }
            for (a, _, _) in vesting_bonus_recips.iter() {
                set.insert(a.clone());
            }
            let ops = 2 * set.len() as u64;
            T::DbWeight::get().reads_writes(3 + ops, 1 + ops)
        }, Pays::No))]
        pub fn give_bonuses(
            origin: OriginFor<T>,
            swap_bonus_recips: Vec<(T::AccountId, BalanceOf<T>, u32)>,
            vesting_bonus_recips: Vec<(T::AccountId, BalanceOf<T>, u32)>,
        ) -> DispatchResult {
            let migrator = ensure_signed(origin)?;
            Self::give_bonuses_(migrator, swap_bonus_recips, vesting_bonus_recips)
        }

        // TODO: Bonus claims for swap and vesting individually could be removed to give a cleaner interface
        // to user as a user might not care what bonus he is getting but only the amount

        /// Claim bonus if any and can be claimed
        /// # <weight>
        /// There is 1 read and write for bonus storage.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn claim_bonus(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::unlock_bonus(who)
        }

        /// Similar to `claim_bonus` but done for another account. The bonus does not
        /// credit to the sending account's free balance
        /// # <weight>
        /// There are 2 reads, one for bonus storage, one for account storage. Similarly for writes.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn claim_bonus_for_other(
            origin: OriginFor<T>,
            target: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::unlock_bonus(T::Lookup::lookup(target)?)
        }

        /// Claim swap bonus if any and can be claimed
        /// # <weight>
        /// There is 1 read and write for bonus storage.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn claim_swap_bonus(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::unlock_swap_bonus(who)
        }

        /// Similar to `claim_swap_bonus` but done for another account. The bonus does not
        /// credit to the sending account's free balance
        /// # <weight>
        /// There are 2 reads, one for bonus storage, one for account storage. Similarly for writes.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn claim_swap_bonus_for_other(
            origin: OriginFor<T>,
            target: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::unlock_swap_bonus(T::Lookup::lookup(target)?)
        }

        /// Claim vesting bonus if any and can be claimed
        /// # <weight>
        /// There is 1 read and write for bonus storage.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn claim_vesting_bonus(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::unlock_vesting_bonus(who)
        }

        /// Similar to `claim_vesting_bonus` but done for another account. The bonus does not
        /// credit to the sending account's free balance
        /// # <weight>
        /// There are 2 reads, one for bonus storage, one for account storage. Similarly for writes.
        /// Ignoring weight of in-memory operations
        /// # </weight>
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn claim_vesting_bonus_for_other(
            origin: OriginFor<T>,
            target: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::unlock_vesting_bonus(T::Lookup::lookup(target)?)
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Deduct tokens from the migrator's account and decrease the allowed migrations
    fn migrate_(
        migrator: T::AccountId,
        recipients: BTreeMap<T::AccountId, BalanceOf<T>>,
    ) -> DispatchResult {
        let mut mig_count = recipients.len() as u16;
        let allowed_migrations = Self::check_allowed_migrations_limit(&migrator, mig_count)?;

        // The balance that needs to be transferred to all recipients combined
        let total_transfer_balance = recipients
            .values()
            .fold(BalanceOf::<T>::zero(), |acc, &x| acc.saturating_add(x));

        Self::check_if_migrator_has_sufficient_balance(&migrator, total_transfer_balance)?;

        // XXX: A potentially more efficient way could be to replace all transfers with one call to withdraw
        // for migrator and then one call to `deposit_creating` for each recipient. This will cause 1
        // negative imbalance and 1 positive imbalance for each recipient. It needs to be ensured that
        // the negative imbalance is destroyed and not end up with the validator as txn fees.
        // This approach needs to be benchmarked for comparison.

        // Transfer to each recipient
        for (recip, balance) in recipients {
            // There is a very slim chance that transfer fails with an addition overflow when the
            // recipient has a very high balance.
            // Using `AllowDeath` to let migrator be wiped out once he has transferred to all.
            match T::Currency::transfer(&migrator, &recip, balance, AllowDeath) {
                Ok(_) => Self::deposit_event(Event::Migration(migrator.clone(), recip, balance)),
                Err(_) => mig_count -= 1,
            }
        }
        Migrators::<T>::insert(migrator, allowed_migrations - mig_count);
        Ok(())
    }

    /// Set bonuses for recipients
    fn give_bonuses_(
        migrator: T::AccountId,
        swap_bonus_recips: Vec<(T::AccountId, BalanceOf<T>, u32)>,
        vesting_bonus_recips: Vec<(T::AccountId, BalanceOf<T>, u32)>,
    ) -> DispatchResult {
        let mut mig_count = (swap_bonus_recips.len() + vesting_bonus_recips.len()) as u16;
        let allowed_migrations = Self::check_allowed_migrations_limit(&migrator, mig_count)?;

        // The balance that needs to be transferred to all recipients combined
        let mut total_transfer_balance = swap_bonus_recips
            .iter()
            .fold(BalanceOf::<T>::zero(), |acc, x| acc.saturating_add(x.1));
        total_transfer_balance = vesting_bonus_recips
            .iter()
            .fold(total_transfer_balance, |acc, x| acc.saturating_add(x.1));

        Self::check_if_migrator_has_sufficient_balance(&migrator, total_transfer_balance)?;

        let now = <frame_system::Pallet<T>>::block_number();

        // Give swap bonuses
        for (acc_id, amount, offset) in swap_bonus_recips {
            if Self::add_swap_bonus(
                migrator.clone(),
                acc_id,
                amount,
                now + T::BlockNumber::from(offset),
            )
            .is_err()
            {
                mig_count -= 1;
            }
        }

        // Give vesting bonuses
        for (acc_id, amount, offset) in vesting_bonus_recips {
            if Self::add_vesting_bonus(
                migrator.clone(),
                acc_id,
                amount,
                now + T::BlockNumber::from(offset),
            )
            .is_err()
            {
                mig_count -= 1;
            }
        }

        Migrators::<T>::insert(migrator, allowed_migrations - mig_count);
        Ok(())
    }

    /// Unlock whatever swap and vesting bonus that can be unlocked
    fn unlock_bonus(who: T::AccountId) -> DispatchResult {
        let swap_bonus = Self::unlock_swap_bonus(who.clone());
        let vesting_bonus = Self::unlock_vesting_bonus(who);
        if swap_bonus.is_ok() || vesting_bonus.is_ok() {
            Ok(())
        } else {
            fail!(Error::<T>::NoBonus)
        }
    }

    /// Add swap bonus for an account
    fn add_swap_bonus(
        from: T::AccountId,
        to: T::AccountId,
        amount: BalanceOf<T>,
        until: T::BlockNumber,
    ) -> DispatchResult {
        T::Currency::transfer(&from, &to, amount, ExistenceRequirement::AllowDeath)?;
        T::Currency::reserve(&to, amount)?;

        let mut bonus = Self::get_bonus_struct(&to);

        let bonuses = &mut bonus.swap_bonuses;

        // Maintain sorting in increasing order of block numbers for efficiency in unlocking
        let mut i = 0;
        while (i < bonuses.len()) && (until > bonuses[i].1) {
            i += 1;
        }
        bonuses
            .try_insert(i, (amount, until))
            .map_err(|_| Error::<T>::TooManyBonuses)?;

        // A storage optimization would be to combine bonuses unlocking at same block number but
        // this is a rare occurrence in practice and thus not worth paying the O(n) cost.

        Self::update_bonus(&to, bonus);
        Self::deposit_event(Event::SwapBonusAdded(from, to, amount, until));
        Ok(())
    }

    /// Unlock any swap bonuses that can be unlocked for an account
    fn unlock_swap_bonus(who: T::AccountId) -> DispatchResult {
        let mut bonus = Self::bonus(&who).ok_or(Error::<T>::NoBonus)?;
        ensure!(!bonus.swap_bonuses.is_empty(), Error::<T>::NoSwapBonus);
        let now = <frame_system::Pallet<T>>::block_number();
        let mut bonus_to_unlock = BalanceOf::<T>::zero();

        // Avoiding nightly `drain_filter`
        let mut i = 0;
        while i < bonus.swap_bonuses.len() {
            if bonus.swap_bonuses[i].1 <= now {
                bonus_to_unlock = bonus_to_unlock
                    .checked_add(&bonus.swap_bonuses[i].0)
                    .ok_or(Error::<T>::BonusOverflowError)?;
                i += 1;
            } else {
                break;
            }
        }
        ensure!(i > 0, Error::<T>::CannotClaimSwapBonusYet);

        bonus.swap_bonuses = bonus
            .swap_bonuses
            .try_mutate(|bonuses| {
                bonuses.drain(0..i);
            })
            .unwrap();
        T::Currency::unreserve(&who, bonus_to_unlock);

        Self::update_bonus(&who, bonus);
        Self::deposit_event(Event::SwapBonusClaimed(who, bonus_to_unlock));
        Ok(())
    }

    /// Add vesting bonus for an account
    fn add_vesting_bonus(
        from: T::AccountId,
        to: T::AccountId,
        amount: BalanceOf<T>,
        start: T::BlockNumber,
    ) -> DispatchResult {
        T::Currency::transfer(&from, &to, amount, ExistenceRequirement::AllowDeath)?;
        T::Currency::reserve(&to, amount)?;

        let mut bonus = Self::get_bonus_struct(&to);

        bonus
            .vesting_bonuses
            .try_push((amount, amount, start))
            .map_err(|_| Error::<T>::TooManyBonuses)?;

        // A storage optimization would be to combine bonuses with same offsets but
        // this is a rare occurrence in practice and thus not worth paying the O(n) cost.

        Self::update_bonus(&to, bonus);
        Self::deposit_event(Event::VestingBonusAdded(from, to, amount, start));
        Ok(())
    }

    /// Unlock any vesting bonuses that can be unlocked for an account
    fn unlock_vesting_bonus(who: T::AccountId) -> DispatchResult {
        let mut bonus = Self::bonus(&who).ok_or(Error::<T>::NoBonus)?;
        let bonuses = &mut bonus.vesting_bonuses;
        ensure!(!bonuses.is_empty(), Error::<T>::NoVestingBonus);

        let now = <frame_system::Pallet<T>>::block_number();
        let now_plus_1 = now + T::BlockNumber::from(1u32);

        let vesting_duration = T::BlockNumber::from(T::VestingDuration::get());
        let vesting_milestones = T::BlockNumber::from(T::VestingMilestones::get() as u32);
        let milestone_as_bal = BalanceOf::<T>::from(T::VestingMilestones::get() as u32);

        // XXX: The following division needs to be done only once in practice as vesting duration will be fixed.
        let milestone_duration = vesting_duration / vesting_milestones;

        let mut bonus_to_unlock = BalanceOf::<T>::zero();

        let mut i = 0;
        let mut completely_vested_bonus_indices = Vec::<usize>::new();
        // Vest any bonuses that can be vested
        while i < bonuses.len() {
            let start = bonuses[i].2;
            let total_bonus = bonuses[i].0;
            let locked_bonus = bonuses[i].1;
            // Note: To avoid the division in case the vesting duration is over, an additional `if`
            // block can be introduced checking `(start + vesting_duration) <= now_plus_1`
            // Calculate number of milestones already passed
            let milestones_passed = now_plus_1
                .checked_sub(&start)
                .ok_or(Error::<T>::BonusOverflowError)?
                / milestone_duration;
            if milestones_passed >= vesting_milestones {
                // Unlock all bonus in or post last milestone
                bonus_to_unlock = bonus_to_unlock
                    .checked_add(&locked_bonus)
                    .ok_or(Error::<T>::BonusOverflowError)?;
                completely_vested_bonus_indices.push(i);
            } else {
                let bonus_per_milestone = total_bonus / milestone_as_bal;
                let bonus_to_be_unlocked_till_now =
                    T::BlockNumberToBalance::convert(milestones_passed) * bonus_per_milestone;
                let expected_locked = total_bonus
                    .checked_sub(&bonus_to_be_unlocked_till_now)
                    .ok_or(Error::<T>::BonusOverflowError)?;
                if expected_locked < locked_bonus {
                    bonus_to_unlock = bonus_to_unlock
                        .checked_add(&(locked_bonus - expected_locked))
                        .ok_or(Error::<T>::BonusOverflowError)?;
                    bonuses[i].1 = expected_locked
                }
            }
            i += 1;
        }

        ensure!(
            bonus_to_unlock > BalanceOf::<T>::zero(),
            Error::<T>::CannotClaimVestingBonusYet
        );

        completely_vested_bonus_indices.reverse();
        for j in completely_vested_bonus_indices {
            bonuses.remove(j);
        }
        T::Currency::unreserve(&who, bonus_to_unlock);

        Self::update_bonus(&who, bonus);
        Self::deposit_event(Event::VestingBonusClaimed(who, bonus_to_unlock));
        Ok(())
    }

    /// Retrieve bonus struct from storage if exists or create a new one.
    fn get_bonus_struct(acc: &T::AccountId) -> Bonus<T> {
        Bonuses::<T>::get(acc).unwrap_or_default()
    }

    /// Update storage and lock for bonus of an account after bonus credit or a claim has been made.
    /// Remove lock and storage entry if all bonus claimed else reset lock and update storage.
    fn update_bonus(acc: &T::AccountId, bonus: Bonus<T>) {
        if bonus.is_empty() {
            // All bonus has been claimed, remove entry from storage
            Bonuses::<T>::remove(acc);
        } else {
            // Update storage
            Bonuses::<T>::insert(acc.clone(), bonus);
        }
    }

    /// Check if migrator can transfer to recipients as regular amounts or as locked (for bonus)
    fn check_allowed_migrations_limit(
        migrator: &T::AccountId,
        mig_count: u16,
    ) -> Result<u16, DispatchError> {
        // Unwrap is safe here as the `SignedExtension` will only allow the transaction when migrator
        // is present
        let allowed_migrations = Self::migrators(migrator).unwrap();
        ensure!(
            mig_count <= allowed_migrations,
            Error::<T>::ExceededMigrations
        );
        Ok(allowed_migrations)
    }

    /// Check if migrator has balance to transfer to recipients as regular amounts or as locked (for bonus
    fn check_if_migrator_has_sufficient_balance(
        migrator: &T::AccountId,
        to_transfer: BalanceOf<T>,
    ) -> DispatchResult {
        // The balance of the migrator after the transfer
        let new_free = T::Currency::free_balance(migrator)
            .checked_sub(&to_transfer)
            .ok_or(Error::<T>::InsufficientBalance)?;

        // Ensure that the migrator can transfer, i.e. has sufficient free and unlocked balance
        T::Currency::ensure_can_withdraw(
            migrator,
            to_transfer,
            WithdrawReasons::TRANSFER,
            new_free,
        )?;

        Ok(())
    }
}

/// Signed extension to ensure that only a Migrator can send the migrate extrinsic.
/// This is necessary to prevent a `migrate` call done by non-Migrator to even enter a block.
#[derive(Encode, Decode, scale_info::TypeInfo, Clone, Eq, PartialEq)]
#[scale_info(skip_type_params(T))]
pub struct OnlyMigrator<T: Config + Send + Sync>(PhantomData<T>);

impl<T: Config + Send + Sync> Default for OnlyMigrator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Config + Send + Sync> OnlyMigrator<T> {
    /// Create new `SignedExtension` to check runtime version.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: Config + Send + Sync> sp_std::fmt::Debug for OnlyMigrator<T> {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "OnlyMigrator")
    }
}

impl<T: Config + Send + Sync> SignedExtension for OnlyMigrator<T>
where
    <T as frame_system::Config>::Call: IsSubType<Call<T>>,
{
    const IDENTIFIER: &'static str = "OnlyMigrator";
    type AccountId = T::AccountId;
    type Call = <T as frame_system::Config>::Call;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        if let Some(local_call) = call.is_sub_type() {
            match local_call {
                // Migrator can make only these 2 calls without paying fees
                Call::migrate { .. } | Call::give_bonuses { .. } => {
                    if !<Migrators<T>>::contains_key(who) {
                        // If migrator not registered, don't include transaction in block
                        return InvalidTransaction::Custom(1).into();
                    }
                }
                _ => (),
            }
        }
        Ok(ValidTransaction::default())
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        self.validate(who, call, info, len).map(|_| ())
    }
}
