use codec::{Decode, Encode, MaxEncodedLen};
use core::fmt::Debug;
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_runtime::traits::*;

#[derive(
    Encode, Decode, Copy, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum CurveType {
    /// BLS12-381
    Bls12381,
}

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
