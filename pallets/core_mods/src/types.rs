use codec::{Decode, Encode};

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum CurveType {
    /// BLS12-381
    Bls12381,
}
