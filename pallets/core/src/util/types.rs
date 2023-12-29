use core::fmt::Debug;
use frame_support::pallet_prelude::*;
use sp_runtime::traits::*;

/// Defines associated types used by `dock-core`.
pub trait Types: Clone + Eq {
    type BlockNumber: Parameter
        + Member
        + MaybeSerializeDeserialize
        + Debug
        + MaybeDisplay
        + AtLeast32BitUnsigned
        + Default
        + Bounded
        + Copy
        + sp_std::hash::Hash
        + sp_std::str::FromStr
        + MaybeMallocSizeOf
        + MaxEncodedLen
        + TypeInfo;

    type AccountId: Parameter
        + Member
        + MaybeSerializeDeserialize
        + Debug
        + MaybeDisplay
        + Ord
        + MaxEncodedLen;
}

impl<T: frame_system::Config> Types for T {
    type BlockNumber = T::BlockNumber;
    type AccountId = T::AccountId;
}
