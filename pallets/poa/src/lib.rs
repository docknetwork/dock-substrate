//! Pallet to add/remove validators and do emission rewards.
//! UPDATE: Adding removing validators and emission rewards is no more done by this pallet. The only
//! reason for this pallet's existence is to unlock the locked emission rewards and tracking last
//! block of PoA chain.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
    traits::{Currency, ReservableCurrency},
    PalletId,
};
use sp_runtime::traits::AccountIdConversion;

pub use pallet::*;

pub mod runtime_api;

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[cfg(test)]
mod tests;

/// Hardcoded treasury id; used to create the special Treasury account
/// Must be exactly 8 characters long
const TREASURY_ID: PalletId = PalletId(*b"Treasury");

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;

    /// The pallet's configuration trait.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Currency: ReservableCurrency<Self::AccountId>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// Remaining emission supply. This reduces after each epoch as emissions happen unless
    /// emissions are disabled.
    #[pallet::storage]
    #[pallet::getter(fn emission_supply)]
    pub type EmissionSupply<T> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// PoA chain's last block's hash. Not storing genesis block hash of PoA chain.
    #[pallet::storage]
    #[pallet::getter(fn poa_last_block)]
    pub type PoALastBlock<T: Config> = StorageValue<_, T::Hash>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub emission_supply: BalanceOf<T>,
        pub poa_last_block: T::Hash,
        pub _marker: PhantomData<T>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                emission_supply: Default::default(),
                poa_last_block: Default::default(),
                _marker: PhantomData,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            EmissionSupply::<T>::put(self.emission_supply);
            PoALastBlock::<T>::put(self.poa_last_block);
        }
    }

    impl<T: Config> Pallet<T> {
        /// The account ID that holds the Treasury's funds
        pub fn treasury_account() -> T::AccountId {
            TREASURY_ID.into_account_truncating()
        }

        /// Treasury's free balance. Only free balance makes sense for treasury in context of PoA
        pub fn treasury_balance() -> BalanceOf<T> {
            T::Currency::free_balance(&Self::treasury_account())
        }
    }
}
