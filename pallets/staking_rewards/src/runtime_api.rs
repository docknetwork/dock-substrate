#![cfg_attr(not(feature = "std"), no_std)]

use codec::Codec;
use sp_runtime::traits::{MaybeDisplay, MaybeFromStr};

sp_api::decl_runtime_apis! {
    pub trait StakingRewardsApi<Balance> where
        Balance: Codec + MaybeDisplay + MaybeFromStr, {
        /// Get emission rewards for the whole year given total staked tokens and total issuance.
        /// Depends on the reward curve, decay percentage and remaining emission supply.
        fn yearly_emission(total_staked: Balance, total_issuance: Balance) -> Balance;

        /// Get max emission rewards for the whole year and depends on decay percentage and remaining emission supply.
        fn max_yearly_emission() -> Balance;
    }
}
