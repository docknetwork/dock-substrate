//! A pallet that facilitates the smooth transfer of `DOCK` tokens from the `Dock` Chain to `CHEQD` tokens on the `Cheqd` Chain.

#![cfg_attr(not(feature = "std"), no_std)]

use scale_info::prelude::string::String;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
mod weights;

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

use weights::{SubstrateWeight, WeightInfo};

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        dispatch::WithPostDispatchInfo,
        pallet_prelude::*,
        traits::{Currency, ExistenceRequirement::AllowDeath},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Zero;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// Address of the recipient on the `cheqd` side.
    #[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    #[derive(scale_info_derive::TypeInfo)]
    #[scale_info(omit_prefix)]
    pub struct CheqdAddress(String);

    impl CheqdAddress {
        pub fn new<T>(value: String) -> Result<Self, Error<T>> {
            let (prefix, addr) =
                bech32::decode(&value).map_err(|_| Error::<T>::AddressMustBeValidBech32)?;
            ensure!(
                prefix.as_str() == "cheqd",
                Error::<T>::AddressMustStartWithCheqd
            );
            ensure!(addr.len() == 20, Error::<T>::InvalidAddressLength);

            Ok(Self(value))
        }
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// The currency to be burnt during migration.
        type Currency: Currency<Self::AccountId>;
        /// Id of the recipient account on the dock side to send burnt funds.
        type BurnDestination: Get<Self::AccountId>;
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `cheqd` address must start with `cheqd` prefix.
        AddressMustStartWithCheqd,
        /// Provided `cheqd` address is invalid because it has an incorrect length.
        InvalidAddressLength,
        /// `cheqd` address part coming after `cheqd` must be a valid bech-32 sequence.
        AddressMustBeValidBech32,
        /// Caller account's balance is zero.
        BalanceIsZero,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Burns the free `DOCK` balance of the sender and emits an event containing the supplied recipient `cheqd` address.
        /// By submitting this transaction, you agree to the Terms and Conditions.
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::migrate())]
        pub fn migrate(origin: OriginFor<T>, cheqd_address: String) -> DispatchResultWithPostInfo {
            let dock_account = ensure_signed(origin)?;

            let cheqd_account = CheqdAddress::new::<T>(cheqd_address)
                .map_err(DispatchError::from)
                .map_err(|error| {
                    error.with_weight(SubstrateWeight::<T::DbWeight>::migrate_validation_failure())
                })?;

            let dock_tokens_amount = T::Currency::free_balance(&dock_account);
            ensure!(!dock_tokens_amount.is_zero(), Error::<T>::BalanceIsZero);

            let dest = T::BurnDestination::get();
            T::Currency::transfer(&dock_account, &dest, dock_tokens_amount, AllowDeath)?;

            Self::deposit_event(Event::Migrated {
                dock_account,
                cheqd_account,
                dock_tokens_amount,
                accepted_terms_and_conditions: true,
            });

            Ok(Pays::Yes.into())
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// The corresponding amount of `DOCK` tokens was burned on the `Dock` Chain side, and an equivalent amount
        /// of `CHEQD` tokens will be issued to the specified address on the `cheqd` Chain side.
        /// Terms and conditions were accepted by the sender.
        Migrated {
            /// The account whose funds were burnt on the `Dock` side.
            dock_account: T::AccountId,
            /// Recipient address on the `cheqd` side which will receive `CHEQD` tokens.
            cheqd_account: CheqdAddress,
            /// Amount of the burnt DOCK tokens.
            dock_tokens_amount: BalanceOf<T>,
            /// Indicates whether terms and conditions were accepted by the sender.
            accepted_terms_and_conditions: bool,
        },
    }
}
