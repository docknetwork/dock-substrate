#![cfg_attr(not(feature = "std"), no_std)]

use codec::Codec;
use sp_runtime::traits::{MaybeDisplay, MaybeFromStr};
use super::EpochNo;

sp_api::decl_runtime_apis! {
    pub trait PoAApi<AccountId, Balance> where
        AccountId: Codec + MaybeDisplay + MaybeFromStr,
        Balance: Codec + MaybeDisplay + MaybeFromStr, {

        /// Return account address of treasury. The account address can then be used to query the
        /// chain for balance
        fn get_treasury_account() -> AccountId;

        /// Return free balance of treasury account. In the context of PoA, only free balance makes
        /// sense for treasury. But just in case, to check all kinds of balance (locked, reserved, etc),
        /// get the account address with above call and query the chain.
        fn get_treasury_balance() -> Balance;

        /// Return total (validators + treasury) emission rewards for given epoch
        fn get_total_emission_in_epoch(epoch_no: EpochNo) -> Balance;
    }
}
