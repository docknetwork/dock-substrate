use codec::{Decode, Encode, MaxEncodedLen};
use core::fmt::Debug;

pub use crate::util::Types;

#[derive(
    Encode, Decode, Copy, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum CurveType {
    /// BLS12-381
    Bls12381,
}
