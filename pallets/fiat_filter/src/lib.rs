#![cfg_attr(not(feature = "std"), no_std)]

use common::arith_utils::DivCeil;
use common::traits::PriceProvider;
use core::fmt::Debug;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::traits::Get;
use frame_support::{
    decl_error, decl_module,
    dispatch::{
        DispatchError, DispatchErrorWithPostInfo, DispatchResultWithPostInfo, PostDispatchInfo,
        UnfilteredDispatchable,
    },
    fail,
    traits::{Currency, ExistenceRequirement, IsSubType, WithdrawReasons},
    weights::{GetDispatchInfo, Pays, Weight},
    Parameter,
};
use frame_system::{self as system, ensure_signed};
use sp_std::boxed::Box;

// #[cfg(test)]
// mod test_mock;
// #[cfg(test)]
// #[allow(non_snake_case)]
// mod tests;

/// The pallet's configuration trait
/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Config:
    system::Config
    + did::Config
    + anchor::Config
    + blob::Config
    + revoke::Config
    + attest::Config
    + Debug
{
    /// Config option for updating the DockFiatRate
    type PriceProvider: common::traits::PriceProvider;
    /// The module's Currency type definition
    type Currency: Currency<Self::AccountId>;

    /// The outer call (dispatchable) that this module is called with. It is possible to use another type here, but
    /// it's expected that your runtime::Call will be used.
    /// Since we need to match by origin crate, we implement `IsSubType` for each Call type we want to match for.
    type Call: Parameter
        + UnfilteredDispatchable<Origin = Self::Origin>
        + GetDispatchInfo
        + IsSubType<did::Call<Self>>
        + IsSubType<anchor::Call<Self>>
        + IsSubType<blob::Call<Self>>
        + IsSubType<revoke::Call<Self>>
        + IsSubType<attest::Call<Self>>;

    /// Minimum price, in case the price fetched from optimized_get_dock_usd_price is zero or an error
    /// expressed in USD_1000th/DOCK (as u32) (== USD/1000DOCK) just like the actual result from optimized_get_dock_usd_price
    type MinDockFiatRate: Get<u32>;
}

decl_error! {
    pub enum Error for Module<T: Config> where T: Debug {
        /// Call is not among the core_mods ones that should go through fiat_filter
        UnexpectedCall,
    }
}

// The module's callable functions (Dispatchable functions)
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
    pub struct Module<T: Config> for enum Call
    where
        origin: T::Origin, T: Debug
    {
        const MinDockFiatRate: u32 = T::MinDockFiatRate::get();

        // Errors must be initialized if they are used by the pallet.
        type Error = Error<T>;

        /// Execute a Call. Must be a core_mods call (DID, Blob, Anchor, Revoke/Unrevoke, Attest)
        #[weight = 10_000]
        pub fn execute_call(origin, call: Box<<T as Config>::Call>) -> DispatchResultWithPostInfo {
            Ok(Self::execute_call_(origin, &call)?)
        }
    }
}

type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as system::Config>::AccountId>>::Balance;

type AmountUsd = u32;

pub mod fiat_rate {
    // all prices given in nUSD (billionth USD)
    // This unit is chosen to avoid multiplications later in get_call_fee_dock_()
    pub const PRICE_OFFCHAIN_DID_CREATE: u32 = 150_000_000; // 50_000_000/1B or 0.5 USD
    pub const PRICE_ONCHAIN_DID_CREATE: u32 = 150_000_000; // 150_000_000/1B or 0.15 USD
    pub const PRICE_DID_KEY_UPDATE: u32 = 170_000_000;
    pub const PRICE_OFFCHAIN_DID_REMOVE: u32 = 50_000_000;
    pub const PRICE_ONCHAIN_DID_REMOVE: u32 = 150_000_000;
    pub const PRICE_ANCHOR_OP_PER_BYTE: u32 = 3438;
    pub const PRICE_REVOKE_REGISTRY_CREATE: u32 = 130_000_000;
    pub const PRICE_REVOKE_REGISTRY_REMOVE: u32 = 170_000_000;
    pub const PRICE_REVOKE_OP_CONST_FACTOR: u32 = 150_000_000;
    pub const PRICE_REVOKE_PER_REVOCATION: u32 = 30_000_000;
    pub const PRICE_BLOB_OP_BASE: u32 = 110_000_000;
    pub const PRICE_BLOB_OP_PER_100_BYTES: u32 = 55_000_000;
    pub const PRICE_ATTEST_OP_BASE: u32 = PRICE_BLOB_OP_BASE;
    pub const PRICE_ATTEST_OP_PER_100_BYTES: u32 = PRICE_BLOB_OP_PER_100_BYTES;
}

// private helper functions
impl<T: Config + Debug> Module<T> {
    /// Get fee in fiat unit for a given Call
    /// Result expressed in nUSD (billionth USD)
    fn get_call_fee_fiat_(call: &<T as Config>::Call) -> Result<AmountUsd, DispatchError> {
        use fiat_rate::*;
        match call.is_sub_type() {
            Some(did::Call::new_offchain(_, _)) => return Ok(PRICE_OFFCHAIN_DID_CREATE),
            // TODO: This needs to be revisited as it should depend on the number of keys and controllers
            Some(did::Call::new_onchain(_, _, __)) => return Ok(PRICE_ONCHAIN_DID_CREATE),
            // TODO: This needs to be revisited as it should depend on the number of keys
            Some(did::Call::add_keys(_, _)) => return Ok(PRICE_DID_KEY_UPDATE),
            // TODO: This needs to be revisited as it should depend on the number of keys
            Some(did::Call::add_controllers(_, _)) => return Ok(PRICE_DID_KEY_UPDATE),
            Some(did::Call::remove_offchain_did(_)) => return Ok(PRICE_OFFCHAIN_DID_REMOVE),
            Some(did::Call::remove_onchain_did(_, _)) => return Ok(PRICE_ONCHAIN_DID_REMOVE),
            _ => {}
        };
        match call.is_sub_type() {
            Some(anchor::Call::deploy(bytes)) => {
                return Ok(PRICE_ANCHOR_OP_PER_BYTE.saturating_mul(bytes.len() as u32))
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(blob::Call::new(blob, _sig)) => {
                let size: u32 = blob.blob.blob.len() as u32;
                let price = PRICE_BLOB_OP_BASE.saturating_add(
                    (size.div_ceil(100)).saturating_mul(PRICE_ATTEST_OP_PER_100_BYTES),
                );
                return Ok(price);
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(revoke::Call::new_registry(_add_registry)) => {
                return Ok(PRICE_REVOKE_REGISTRY_CREATE)
            }
            Some(revoke::Call::remove_registry(_rm, _proof)) => {
                return Ok(PRICE_REVOKE_REGISTRY_REMOVE)
            }

            Some(revoke::Call::revoke(revocation, _proof)) => {
                return Ok(PRICE_REVOKE_PER_REVOCATION
                    .saturating_mul(revocation.revoke_ids.len() as u32)
                    .saturating_add(PRICE_REVOKE_OP_CONST_FACTOR));
            }
            Some(revoke::Call::unrevoke(unrevoke, _proof)) => {
                return Ok(PRICE_REVOKE_PER_REVOCATION
                    .saturating_mul(unrevoke.revoke_ids.len() as u32)
                    .saturating_add(PRICE_REVOKE_OP_CONST_FACTOR));
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(attest::Call::set_claim(attestation, _sig)) => {
                let iri_size_100bytes: u32 = attestation
                    .attest
                    .iri
                    .as_ref()
                    .map_or_else(|| 1, |i| (i.len() as u32).div_ceil(100));
                let price = PRICE_ATTEST_OP_BASE.saturating_add(
                    iri_size_100bytes.saturating_mul(PRICE_ATTEST_OP_PER_100_BYTES),
                );
                return Ok(price);
            }
            _ => {}
        }

        // return error if Call not in list
        fail!(Error::<T>::UnexpectedCall)
    }

    pub fn get_call_fee_dock_(
        call: &<T as Config>::Call,
    ) -> Result<(BalanceOf<T>, Weight), DispatchError> {
        // the fee in fiat is expressed in nUSD (1 billionth USD)
        let fee_usd_billionth: AmountUsd = Self::get_call_fee_fiat_(call)?;

        // the DOCK/USD rate in the price_feed pallet is the price of 1DOCK,
        // expressed in USD_1000th/DOCK (as u32) (== USD/1000DOCK)
        let (dock_usd1000th_rate, weight): (u32, Weight) =
            match <T as Config>::PriceProvider::optimized_get_dock_usd_price() {
                Some((rate, weight)) => (sp_std::cmp::max(rate, T::MinDockFiatRate::get()), weight),
                None => (T::MinDockFiatRate::get(), 10_000),
            };

        // we want the result fee, expressed in µDOCK (1 millionth DOCK)
        // no need for any multiplication factor since (1/1B USD)/(1/1000 USD/DOCK) already == (1/1M DOCK)
        let fee_microdock = fee_usd_billionth / dock_usd1000th_rate;

        // The token has 6 decimal places (defined in the runtime)
        // See in runtime: pub const DOCK: Balance = 1_000_000;
        // T::Balance is already expressed in µDOCK (1 millionth DOCK)
        Ok((<BalanceOf<T>>::from(fee_microdock as u32), weight))
    }

    fn charge_fees_(who: T::AccountId, amount: BalanceOf<T>) -> Result<(), DispatchError> {
        let _ = <T::Currency>::withdraw(
            &who,
            amount,
            WithdrawReasons::FEE,
            ExistenceRequirement::KeepAlive,
        )?;
        Ok(())
    }

    fn execute_call_(origin: T::Origin, call: &<T as Config>::Call) -> DispatchResultWithPostInfo {
        // check signature before charging any fees
        let sender = ensure_signed(origin.clone())?;
        let weight_call = call.get_dispatch_info().weight;

        // calculate fee based on type of call
        let (fee_dock, weight_get_price) = match Self::get_call_fee_dock_(&call) {
            Ok((f, w)) => (f, w),
            Err(error) => {
                return Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(weight_call),
                        pays_fee: Pays::Yes, // uses Pays::Yes to prevent spam
                    },
                    error,
                });
            }
        };

        // deduct fees based on Currency::Withdraw
        Self::charge_fees_(sender, fee_dock)?;

        let weight_total = weight_call.saturating_add(weight_get_price);
        let dispatch_result = call.clone().dispatch_bypass_filter(origin);
        return match dispatch_result {
            Ok(_post_dispatch_info) => Ok(PostDispatchInfo {
                actual_weight: Some(weight_total),
                pays_fee: Pays::No,
            }),
            Err(e) => Err(DispatchErrorWithPostInfo {
                post_info: PostDispatchInfo {
                    actual_weight: Some(weight_total),
                    pays_fee: Pays::No,
                },
                error: e.error,
            }),
        };
    }
}
