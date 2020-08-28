#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch,
    dispatch::IsSubType,
    ensure, fail,
    sp_runtime::{
        traits::{CheckedSub, DispatchInfoOf, SaturatedConversion, SignedExtension},
        transaction_validity::{
            InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
        },
    },
    traits::{Currency, ExistenceRequirement::AllowDeath, Get, WithdrawReason},
    weights::{Pays, Weight},
};
/// Pallet for token migration.
use sp_std::marker::PhantomData;

use frame_system::{self as system, ensure_root, ensure_signed};
extern crate alloc;
use alloc::collections::BTreeMap;

type Balance = u64;
type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

#[cfg(test)]
mod tests;

mod benchmarking;

/// The pallet's configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    type Currency: Currency<Self::AccountId>;
}

// This pallet's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as MigrationModule {
        Migrators get(fn migrators): map hasher(blake2_128_concat) T::AccountId => Option<u16>;
    }
}

// The pallet's events
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        // Migrator transferred tokens
        Migration(AccountId, AccountId, Balance),

        // New migrator added
        MigratorAdded(AccountId, u16),

        // Existing migrator removed
        MigratorRemoved(AccountId),

        // Migrator's allowed migrations increased
        MigratorExpanded(AccountId, u16),

        // Migrator's allowed migrations decreased
        MigratorContracted(AccountId, u16),
    }
);

// The pallet's errors
decl_error! {
    /// Errors for the module.
    pub enum Error for Module<T: Trait> {
        MigratorAlreadyPresent,
        UnknownMigrator,
        ExceededMigrations,
        CannotExpandMigrator,
        CannotContractMigrator,
        InsufficientBalance
    }
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        type Error = Error<T>;

        fn deposit_event() = default;

        /// Does a token migration. The migrator should have sufficient balance to give tokens to recipients
        /// The check whether it is a valid migrator is made inside the SignedExtension.
        /// Migrators are assumed to not be adversarial and do DoS attacks on the chain. They might act
        /// in their benefit and try to send more fee txns then allowed which is guarded against.
        /// An bad migrator can flood the network with properly signed but invalid txns like trying to pay more
        /// than he has, make the network reject his txn but still spend netowork resources for free.
        #[weight = (T::DbWeight::get().reads_writes(3 + recipients.len() as u64, 1 + recipients.len() as u64) + (22_100 * recipients.len() as Weight), Pays::No)]
        pub fn migrate(origin, recipients: BTreeMap<T::AccountId, BalanceOf<T>>) -> dispatch::DispatchResult {
            let migrator = ensure_signed(origin)?;
            Self::migrate_(migrator, recipients)
        }

        /// Increase the migrators allowed migrations by the given number
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn expand_migrator(origin, migrator: T::AccountId, increase_migrations_by: u16) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            match Self::migrators(&migrator) {
                Some(current_migrations) => {
                    let new_migrations = current_migrations.checked_add(increase_migrations_by).ok_or(Error::<T>::CannotExpandMigrator)?;
                    Migrators::<T>::insert(migrator.clone(), new_migrations);
                    Self::deposit_event(RawEvent::MigratorExpanded(migrator, new_migrations));
                    Ok(Pays::No.into())
                },
                None => fail!(Error::<T>::UnknownMigrator)
            }
        }

        /// Decrease the migrators allowed migrations by the given number
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn contract_migrator(origin, migrator: T::AccountId, decrease_migrations_by: u16) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let new_migrations = Self::migrators(&migrator)
                .ok_or(Error::<T>::UnknownMigrator)?
                .checked_sub(decrease_migrations_by)
                .ok_or(Error::<T>::CannotContractMigrator)?;
            Migrators::<T>::insert(&migrator, &new_migrations);
            Self::deposit_event(RawEvent::MigratorContracted(migrator, new_migrations));
            Ok(Pays::No.into())
        }

        /// Add a new migrator
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn add_migrator(origin, migrator: T::AccountId, allowed_migrations: u16) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(!Migrators::<T>::contains_key(&migrator), Error::<T>::MigratorAlreadyPresent);
            Migrators::<T>::insert(migrator.clone(), allowed_migrations);
            Self::deposit_event(RawEvent::MigratorAdded(migrator, allowed_migrations));
            Ok(Pays::No.into())
        }

        /// Remove an existing migrator
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_migrator(origin, migrator: T::AccountId) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ensure!(Migrators::<T>::contains_key(&migrator), Error::<T>::UnknownMigrator);
            Migrators::<T>::remove(&migrator);
            Self::deposit_event(RawEvent::MigratorRemoved(migrator));
            Ok(Pays::No.into())
        }
    }
}

impl<T: Trait> Module<T> {
    /// Deduct tokens from the migrator's account and decrease the allowed migrations
    pub fn migrate_(
        migrator: T::AccountId,
        recipients: BTreeMap<T::AccountId, BalanceOf<T>>,
    ) -> dispatch::DispatchResult {
        // Unwrap is safe here as the `SignedExtension` will only allow the transaction when migrator
        // is present
        let allowed_migrations = Self::migrators(&migrator).unwrap();
        let mut mig_count = recipients.len() as u16;
        ensure!(
            mig_count <= allowed_migrations,
            Error::<T>::ExceededMigrations
        );

        // The balance that needs to be transferred to all recipients combined
        let total_transfer_balance = recipients
            .values()
            .fold(0 as Balance, |acc, &x| {
                acc.saturating_add(x.saturated_into::<Balance>())
            })
            .saturated_into();

        // The balance of the migrator after the transfer
        let new_free = T::Currency::free_balance(&migrator)
            .checked_sub(&total_transfer_balance)
            .ok_or(Error::<T>::InsufficientBalance)?;

        // Ensure that the migrator can transfer, i.e. has sufficient free and unlocked balance
        T::Currency::ensure_can_withdraw(
            &migrator,
            total_transfer_balance,
            WithdrawReason::Transfer.into(),
            new_free,
        )?;

        // XXX: A potentially more efficient way could be to replace all transfers with one call to withdraw
        // for migrator and then one call to `deposit_creating` for each recipient. This will cause 1
        // negative imbalance and 1 positive imbalance for each recipient. It needs to be ensured that
        // the negative imbalance is destroyed and not end up with the validator as txn fees.
        // This approach needs to be benchmarked for comparison.

        // Transfer to each recipient
        for (recip, balance) in recipients {
            // There is a very slim change that transfer fails with an addition overflow when the
            // recipient has a very high balance.
            // Using `AllowDeath` to let migrator be wiped out once he has transferred to all.
            match T::Currency::transfer(&migrator, &recip, balance, AllowDeath) {
                Ok(_) => Self::deposit_event(RawEvent::Migration(
                    migrator.clone(),
                    recip,
                    balance.saturated_into::<Balance>(),
                )),
                Err(_) => mig_count -= 1,
            }
        }
        Migrators::<T>::insert(migrator, allowed_migrations - mig_count);
        Ok(())
    }
}

/// Signed extension to ensure that only a Migrator can send the migrate extrinsic.
/// This is necessary to prevent a `migrate` call done by non-Migrator to even enter a block.
#[derive(Encode, Decode, Clone, Eq, PartialEq)]
pub struct OnlyMigrator<T: Trait + Send + Sync>(PhantomData<T>);

impl<T: Trait + Send + Sync> sp_std::fmt::Debug for OnlyMigrator<T> {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "OnlyMigrator")
    }
}

impl<T: Trait + Send + Sync> SignedExtension for OnlyMigrator<T>
where
    <T as system::Trait>::Call: IsSubType<Call<T>>,
{
    const IDENTIFIER: &'static str = "OnlyMigrator";
    type AccountId = T::AccountId;
    type Call = <T as system::Trait>::Call;
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
            if let Call::migrate(..) = local_call {
                if !<Migrators<T>>::contains_key(who) {
                    // If migrator not registered, dont include transaction in block
                    return InvalidTransaction::Custom(1).into();
                }
            }
        }
        Ok(ValidTransaction::default())
    }
}
