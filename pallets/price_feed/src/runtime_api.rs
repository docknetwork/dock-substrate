#![cfg_attr(not(feature = "std"), no_std)]

sp_api::decl_runtime_apis! {
    pub trait PriceFeedApi {
        fn token_usd_price() -> Option<u32>;

        fn token_usd_price_from_contract() -> Option<u32>;
    }
}
