//! Pallet to add/remove validators and do emission rewards.
//! UPDATE: Adding removing validators and emission rewards is no more done by this pallet. The only
//! reason for this pallet's existence is to unlock the locked emission rewards and tracking last
//! block of PoA chain.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
    decl_module, decl_storage,
    traits::{Currency, ReservableCurrency},
    PalletId,
};
use sp_runtime::traits::AccountIdConversion;
use sp_std::prelude::*;

use frame_system::{self as system};

pub mod runtime_api;

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as system::Config>::AccountId>>::Balance;

#[cfg(test)]
mod tests;

/// Hardcoded treasury id; used to create the special Treasury account
/// Must be exactly 8 characters long
const TREASURY_ID: PalletId = PalletId(*b"Treasury");

/// The pallet's configuration trait.
pub trait Config: system::Config {
    type Currency: ReservableCurrency<Self::AccountId>;
}

// This pallet's storage items.
decl_storage! {
    trait Store for Module<T: Config> as PoAModule {
        /// Remaining emission supply. This reduces after each epoch as emissions happen unless
        /// emissions are disabled.
        pub EmissionSupply get(fn emission_supply) config(): BalanceOf<T>;

        /// PoA chain's last block's hash. Not storing genesis block hash of PoA chain.
        PoALastBlock get(fn poa_last_block) config(): T::Hash
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {
        /*/// Force a transfer using root to transfer balance of reserved as well as free kind.
        /// This call is dangerous and can be abused by a malicious Root
        #[weight = <T as frame_system::Config>::DbWeight::get().reads_writes(1, 1)]
        pub fn force_transfer_both(
            origin, source: <T::Lookup as StaticLookup>::Source, dest: <T::Lookup as StaticLookup>::Source,
            #[compact] free: BalanceOf<T>, #[compact] reserved: BalanceOf<T>
        ) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            let source = T::Lookup::lookup(source)?;
            let dest = T::Lookup::lookup(dest)?;
            Self::force_transfer_both_(&source, &dest, free, reserved)?;
            Ok(Pays::No.into())
        }*/
    }
}

impl<T: Config> Module<T> {
    /// The account ID that holds the Treasury's funds
    pub fn treasury_account() -> T::AccountId {
        TREASURY_ID.into_account_truncating()
    }

    /// Treasury's free balance. Only free balance makes sense for treasury in context of PoA
    pub fn treasury_balance() -> BalanceOf<T> {
        T::Currency::free_balance(&Self::treasury_account())
    }

    /*fn force_transfer_both_(
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
    }*/
}
