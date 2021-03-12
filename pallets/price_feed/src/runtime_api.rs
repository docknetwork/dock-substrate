#![cfg_attr(not(feature = "std"), no_std)]

sp_api::decl_runtime_apis! {
    pub trait PriceFeedApi {
        /// Gets the price of Dock/USD from pallet's storage
        fn token_usd_price() -> Option<u32>;

        /// Gets the price of Dock/USD from EVM contract
        fn token_usd_price_from_contract() -> Option<u32>;
    }
}
