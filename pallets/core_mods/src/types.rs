use codec::{Decode, Encode};

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CurveType {
    /// BLS12-381
    Bls12381,
}
