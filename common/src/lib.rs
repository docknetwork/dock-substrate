#![cfg_attr(not(feature = "std"), no_std)]

/// Trait to provide price of currency pairs. The price is multiplied by 1000 and rounded to make it integer
pub trait PriceProvider {
    // NOTE: Consider returning weight when None as well

    /// Get the latest price of Dock in terms of USD. Returns the price and consumed weight in this operation
    fn get_dock_usd_price() -> Option<(u32, u64)>;

    /// Get the latest price of Dock in terms of USD but it is an optimized call so it might not get
    /// the latest price. Returns the price and consumed weight in this operation
    fn optimized_get_dock_usd_price() -> Option<(u32, u64)>;
}
