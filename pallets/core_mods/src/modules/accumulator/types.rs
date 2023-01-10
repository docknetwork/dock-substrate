use super::*;
use crate::util::WrappedBytes;

pub type AccumParametersStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyWithParams = (AccumulatorPublicKey, Option<AccumulatorParameters>);

/// Accumulator identifier.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorId(pub [u8; 32]);

crate::impl_wrapper!(AccumulatorId([u8; 32]), with tests as acc_tests);

/// Accumulator owner - DID with the ability to control given accumulator keys, params, etc.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorOwner(pub Did);

crate::impl_wrapper!(AccumulatorOwner(Did), for rand use Did(rand::random()), with tests as acc_owner_tests);

#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct AccumulatorParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<WrappedBytes>,
    pub curve_type: CurveType,
    pub bytes: WrappedBytes,
}

#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct AccumulatorPublicKey {
    pub curve_type: CurveType,
    pub bytes: WrappedBytes,
    /// The params used to generate the public key (`P_tilde` comes from params)
    pub params_ref: Option<AccumParametersStorageKey>,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum Accumulator {
    Positive(AccumulatorCommon),
    Universal(UniversalAccumulator),
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct AccumulatorCommon {
    pub accumulated: WrappedBytes,
    pub key_ref: AccumPublicKeyStorageKey,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct UniversalAccumulator {
    pub common: AccumulatorCommon,
    /// This is not enforced on chain and serves as metadata only
    pub max_size: u64,
}

impl Accumulator {
    /// Get reference to the public key of the accumulator
    pub fn key_ref(&self) -> AccumPublicKeyStorageKey {
        match self {
            Accumulator::Positive(a) => a.key_ref,
            Accumulator::Universal(a) => a.common.key_ref,
        }
    }

    /// DID of the owner of the accumulator
    pub fn owner_did(&self) -> &AccumulatorOwner {
        match self {
            Accumulator::Positive(a) => &a.key_ref.0,
            Accumulator::Universal(a) => &a.common.key_ref.0,
        }
    }

    pub fn accumulated(&self) -> &[u8] {
        match self {
            Accumulator::Positive(a) => &a.accumulated,
            Accumulator::Universal(a) => &a.common.accumulated,
        }
    }

    pub fn set_new_accumulated(&mut self, new_accumulated: impl Into<WrappedBytes>) {
        match self {
            Accumulator::Positive(a) => a.accumulated = new_accumulated.into(),
            Accumulator::Universal(a) => a.common.accumulated = new_accumulated.into(),
        }
    }
}

#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub struct StoredAccumulatorOwnerCounters {
    pub params_counter: IncId,
    pub key_counter: IncId,
}

#[derive(scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AccumulatorWithUpdateInfo<T>
where
    T: frame_system::Config,
{
    pub created_at: T::BlockNumber,
    pub last_updated_at: T::BlockNumber,
    pub accumulator: Accumulator,
}

impl<T: frame_system::Config> AccumulatorWithUpdateInfo<T> {
    pub fn new(accumulator: Accumulator, created_at: T::BlockNumber) -> Self {
        Self {
            accumulator,
            created_at,
            last_updated_at: created_at,
        }
    }
}
