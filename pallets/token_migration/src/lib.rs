#![cfg_attr(not(feature = "std"), no_std)]

/// Pallet for token migration.

use sp_std::marker::PhantomData;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, ensure, fail, weights::Pays,
    dispatch::{IsSubType},
    debug::{RuntimeLogger, debug},
    traits::{
        Get, Currency, ExistenceRequirement::AllowDeath, WithdrawReason
    },
    sp_runtime::{print,
                 traits::{SaturatedConversion, CheckedSub, SignedExtension, DispatchInfoOf},
                 transaction_validity::{
                     TransactionValidity, ValidTransaction, InvalidTransaction,
                     TransactionValidityError,
                 }}
};

use frame_system::{self as system, ensure_root, ensure_signed};
extern crate alloc;
use alloc::collections::BTreeMap;

type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

#[cfg(test)]
mod tests;

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
        Migration(AccountId, AccountId, u128),

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
        /// The check whether it is a valid migrator is made inside the SignedExtension
        // TODO: Set correct weight
        #[weight = (T::DbWeight::get().reads_writes(1, recipients.len() as u64), Pays::No)]
        pub fn migrate(origin, recipients: BTreeMap<T::AccountId, BalanceOf<T>>) -> dispatch::DispatchResult {
            let migrator = ensure_signed(origin)?;
            Self::migrate_(migrator, recipients)
        }

        /// Increase the migrators allowed migrations by the given number
        #[weight = (0, Pays::No)]
        pub fn expand_migrator(origin, migrator: T::AccountId, increase_migrations_by: u16) -> dispatch::DispatchResult {
            ensure_root(origin)?;
            match Self::migrators(&migrator) {
                Some(current_migrations) => {
                    let new_migrations = current_migrations.checked_add(increase_migrations_by).ok_or(Error::<T>::CannotExpandMigrator)?;
                    Migrators::<T>::insert(migrator.clone(), new_migrations.clone());
                    Self::deposit_event(RawEvent::MigratorExpanded(migrator, new_migrations));
                    Ok(())
                },
                None => fail!(Error::<T>::UnknownMigrator)
            }
        }

        /// Decrease the migrators allowed migrations by the given number
        #[weight = (0, Pays::No)]
        pub fn contract_migrator(origin, migrator: T::AccountId, decrease_migrations_by: u16) -> dispatch::DispatchResult {
            ensure_root(origin)?;
            let new_migrations = Self::migrators(&migrator)
                .ok_or(Error::<T>::UnknownMigrator)?
                .checked_sub(decrease_migrations_by)
                .ok_or(Error::<T>::CannotContractMigrator)?;
            Migrators::<T>::insert(&migrator, &new_migrations);
            Self::deposit_event(RawEvent::MigratorContracted(migrator, new_migrations));
            Ok(())
        }

        /// Add a new migrator
        #[weight = (0, Pays::No)]
        pub fn add_migrator(origin, migrator: T::AccountId, allowed_migrations: u16) -> dispatch::DispatchResult {
            ensure_root(origin)?;
            ensure!(!Migrators::<T>::contains_key(&migrator), Error::<T>::MigratorAlreadyPresent);
            Migrators::<T>::insert(migrator, allowed_migrations);
            Ok(())
        }

        /// Remove an existing migrator
        #[weight = (0, Pays::No)]
        pub fn remove_migrator(origin, migrator: T::AccountId) -> dispatch::DispatchResult {
            ensure_root(origin)?;
            ensure!(Migrators::<T>::contains_key(&migrator), Error::<T>::UnknownMigrator);
            Migrators::<T>::remove(migrator);
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    /// Deduct tokens from the migrator's account
    pub fn migrate_(migrator:T::AccountId, recipients: BTreeMap<T::AccountId, BalanceOf<T>>) -> dispatch::DispatchResult {
        let allowed_migrations = Self::migrators(&migrator).unwrap();
        let mut mig_count = recipients.len() as u16;
        ensure!(
            mig_count <= allowed_migrations,
            Error::<T>::ExceededMigrations
        );

        // The balance that needs to be transferred to all recipients combined
        let total_transfer_balance = recipients.values().fold(0u128, |acc, &x| acc.saturating_add(x.saturated_into::<u128>())).saturated_into();
        // The balance of the migrator after the transfer
        let new_free = T::Currency::free_balance(&migrator).checked_sub(&total_transfer_balance).ok_or(Error::<T>::InsufficientBalance)?;
        // Ensure that the migrator can transfer, i.e. has sufficient free and unlocked balance
        T::Currency::ensure_can_withdraw(&migrator, total_transfer_balance, WithdrawReason::Transfer.into(), new_free)?;

        for (recip, balance) in recipients {
            // There is a very slim change that transfer fails with an addition overflow when the recipient has a very high balance
            match T::Currency::transfer(&migrator, &recip, balance, AllowDeath) {
                Ok(_) => Self::deposit_event(RawEvent::Migration(migrator.clone(), recip, balance.saturated_into())),
                Err(_) => mig_count -= 1
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
        <T as system::Trait>::Call: IsSubType<Module<T>, T>,
{
    const IDENTIFIER: &'static str = "OnlyMigrator";
    type AccountId = T::AccountId;
    type Call = <T as system::Trait>::Call;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> { Ok(()) }

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
                    return InvalidTransaction::Custom(1).into()
                }
            }
        }
        Ok(ValidTransaction::default())
    }
}