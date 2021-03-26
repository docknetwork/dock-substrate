#![cfg_attr(not(feature = "std"), no_std)]

use common::PriceProvider;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::{
    decl_error, decl_module,
    dispatch::{
        DispatchError, DispatchErrorWithPostInfo, DispatchResultWithPostInfo, PostDispatchInfo,
        UnfilteredDispatchable,
    },
    traits::{Currency, ExistenceRequirement, IsSubType, WithdrawReasons},
    weights::{GetDispatchInfo, Pays},
    Parameter,
};
use frame_system::{self as system, ensure_signed};
use sp_std::boxed::Box;

#[cfg(test)]
#[allow(non_snake_case)]
mod tests;

/// The pallet's configuration trait
/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Config:
    system::Config + did::Trait + anchor::Trait + blob::Trait + revoke::Trait + attest::Trait
{
    /// Config option for updating the DockFiatRate
    type PriceProvider: common::PriceProvider;
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
}

decl_error! {
    pub enum Error for Module<T: Config> where BalanceOf<T>: From<u64> {
        /// Failed calculation because of numeric type overflow
        ArithmeticOverflow,
        /// checked_div: tried to divide by zero
        DivideByZero,
        /// Call is not among the core_mods ones that should go through fiat_filter
        UnexpectedCall,
        /// Call to T::PriceProvider::optimized_get_dock_usd_rate() failed
        NoPriceFound,
    }
}

// The module's callable functions (Dispatchable functions)
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
    pub struct Module<T: Config> for enum Call
    where
        origin: T::Origin,
        BalanceOf<T>: From<u64>,
    {
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

type AmountUsd = u64;

// all prices given in nUSD (billionth USD)
pub const PRICE_DID_OP: u64 = 100_000; // 100_000/1B or 0.0001 USD
pub const PRICE_ANCHOR_OP_PER_BYTE: u64 = 1000;
pub const PRICE_BLOB_OP_PER_BYTE: u64 = 1000;
pub const PRICE_REVOKE_REGISTRY_OP: u64 = 40_000;
pub const PRICE_REVOKE_REVOCATION_OP: u64 = 20_000;
pub const PRICE_ATTEST_OP_PER_BYTE: u64 = 1000;

// private helper functions
impl<T: Config> Module<T>
where
    BalanceOf<T>: From<u64>,
{
    /// Get fee in fiat unit for a given Call
    /// Result expressed in nUSD (billionth USD)
    fn get_call_fee_fiat_(
        call: &<T as Config>::Call,
    ) -> Result<AmountUsd, DispatchErrorWithPostInfo> {
        // TODO make sure we discuss and decide the actual pricing for each call type
        match call.is_sub_type() {
            Some(did::Call::new(_did, _detail)) => return Ok(PRICE_DID_OP), // 50/1B or 0.00000005 USD
            Some(did::Call::update_key(_key_update, _sig)) => return Ok(PRICE_DID_OP),
            Some(did::Call::remove(_to_remove, _sig)) => return Ok(PRICE_DID_OP),
            _ => {}
        };
        match call.is_sub_type() {
            Some(anchor::Call::deploy(bytes)) => {
                return Ok(PRICE_ANCHOR_OP_PER_BYTE * bytes.len() as u64)
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(blob::Call::new(blob, _sig)) => {
                let size: u64 = 64 + blob.blob.len() as u64;
                return Ok(PRICE_BLOB_OP_PER_BYTE * size);
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(revoke::Call::new_registry(_id, _registry)) => {
                return Ok(PRICE_REVOKE_REGISTRY_OP)
            }
            Some(revoke::Call::remove_registry(_rm, _proof)) => {
                return Ok(PRICE_REVOKE_REGISTRY_OP)
            }

            Some(revoke::Call::revoke(revocation, _proof)) => {
                // 32 bytes for the registry_ID, 32 bytes per revocation
                let size: u64 = 32 + 32 * revocation.revoke_ids.len() as u64;
                return Ok(PRICE_REVOKE_REVOCATION_OP * size);
            }
            Some(revoke::Call::unrevoke(unrevoke, _proof)) => {
                // 32 bytes for the registry_ID, 32 bytes per unrevocation
                let size: u64 = 32 + 32 * unrevoke.revoke_ids.len() as u64;
                return Ok(PRICE_REVOKE_REVOCATION_OP * size);
            }
            _ => {}
        };
        match call.is_sub_type() {
            Some(attest::Call::set_claim(_attester, attestation, _sig)) => {
                // 8 bytes for the priority, plus IRI bytes
                let size: u64 = 8 + attestation.iri.as_ref().unwrap_or(&[1].to_vec()).len() as u64;
                return Ok(PRICE_ATTEST_OP_PER_BYTE * size);
            }
            _ => {}
        }

        // return error if Call not in list
        // uses Pays::Yes to prevent spam
        return Err(Error::<T>::UnexpectedCall.into());
    }

    fn compute_call_fee_dock_(
        call: &<T as Config>::Call,
    ) -> Result<BalanceOf<T>, DispatchErrorWithPostInfo> {
        // the fee in fiat is expressed in nUSD (1 billionth USD)
        let fee_usd_billionth: AmountUsd = Self::get_call_fee_fiat_(call)?;

        // the DOCK/USD rate in the price_feed pallet is the price of 1DOCK,
        // expressed in USD_1000th/DOCK (as u32) (== USD/1000DOCK)
        let dock_usd1000th_rate: u32 =
            match <T as Config>::PriceProvider::optimized_get_dock_usd_price() {
                Some((rate, _weight)) => rate,
                None => return Err(Error::<T>::NoPriceFound.into()),
            };

        // we want the result fee, expressed in µDOCK (1 millionth DOCK)
        // no need for any multiplication factor since (1/1B USD)/(1/1000 USD/DOCK) already == (1/1M DOCK)
        let fee_microdock: u64 = fee_usd_billionth
            .checked_div(dock_usd1000th_rate as u64)
            .ok_or(Error::<T>::DivideByZero)?;

        // The token has 6 decimal places (defined in the runtime)
        // See in runtime: pub const DOCK: Balance = 1_000_000;
        // T::Balance is already expressed in µDOCK (1 millionth DOCK)
        Ok(<BalanceOf<T>>::from(fee_microdock))
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
        let weight = call.get_dispatch_info().weight;
        // check signature before charging any fees
        let sender = ensure_signed(origin.clone())?;

        // calculate fee based on type of call
        let fee_dock = Self::compute_call_fee_dock_(&call)?;
        // deduct fees based on Currency::Withdraw
        Self::charge_fees_(sender, fee_dock)?;

        let dispatch_result = call.clone().dispatch_bypass_filter(origin);
        return match dispatch_result {
            Ok(_post_dispatch_info) => Ok(PostDispatchInfo {
                actual_weight: Some(weight),
                pays_fee: Pays::No,
            }),
            Err(e) => {
                frame_support::debug::info!("{:?}", &e);
                Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(weight),
                        pays_fee: Pays::No,
                    },
                    error: e.error,
                })
            }
        };
    }
}
