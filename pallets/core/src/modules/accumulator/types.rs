use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};

use super::*;
use crate::{
    common::{Limits, TypesAndLimits},
    util::BoundedBytes,
};

pub type AccumParametersStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyWithParams<T> = (AccumulatorPublicKey<T>, Option<AccumulatorParameters<T>>);

/// Accumulator identifier.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorId(
    #[cfg_attr(feature = "serde", serde(with = "crate::util::hex"))] pub [u8; 32],
);

crate::impl_wrapper!(AccumulatorId([u8; 32]), with tests as acc_tests);

/// Accumulator owner - DID with the ability to control given accumulator keys, params, etc.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorOwner(pub Did);

crate::impl_wrapper!(AccumulatorOwner(Did), for rand use Did(rand::random()), with tests as acc_owner_tests);

#[derive(
    scale_info_derive::TypeInfo,
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AccumulatorParameters<T: Limits> {
    /// The label (generating string) used to generate the params
    pub label: Option<BoundedBytes<T::MaxAccumulatorLabelSize>>,
    pub curve_type: CurveType,
    pub bytes: BoundedBytes<T::MaxAccumulatorParamsSize>,
}

#[derive(
    scale_info_derive::TypeInfo,
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AccumulatorPublicKey<T: Limits> {
    pub curve_type: CurveType,
    pub bytes: BoundedBytes<T::MaxAccumulatorPublicKeySize>,
    /// The params used to generate the public key (`P_tilde` comes from params)
    pub params_ref: Option<AccumParametersStorageKey>,
}

#[derive(
    Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum Accumulator<T: Limits> {
    Positive(AccumulatorCommon<T>),
    Universal(UniversalAccumulator<T>),
}

#[derive(
    Encode,
    Decode,
    scale_info_derive::TypeInfo,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AccumulatorCommon<T: Limits> {
    pub accumulated: BoundedBytes<T::MaxAccumulatorAccumulatedSize>,
    pub key_ref: AccumPublicKeyStorageKey,
}

#[derive(
    Encode,
    Decode,
    scale_info_derive::TypeInfo,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UniversalAccumulator<T: Limits> {
    pub common: AccumulatorCommon<T>,
    /// This is not enforced on chain and serves as metadata only
    pub max_size: u64,
}

impl<T: Limits> Accumulator<T> {
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

    pub fn set_new_accumulated<A>(&mut self, new_accumulated: A) -> Result<&mut Self, A::Error>
    where
        A: TryInto<BoundedBytes<T::MaxAccumulatorAccumulatedSize>>,
    {
        match self {
            Accumulator::Positive(a) => a.accumulated = new_accumulated.try_into()?,
            Accumulator::Universal(a) => a.common.accumulated = new_accumulated.try_into()?,
        }

        Ok(self)
    }
}

#[derive(
    scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug, Default, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(omit_prefix)]
pub struct StoredAccumulatorOwnerCounters {
    pub params_counter: IncId,
    pub key_counter: IncId,
}

#[derive(
    scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AccumulatorWithUpdateInfo<T>
where
    T: TypesAndLimits,
{
    pub created_at: T::BlockNumber,
    pub last_updated_at: T::BlockNumber,
    pub accumulator: Accumulator<T>,
}

impl<T: TypesAndLimits> AccumulatorWithUpdateInfo<T> {
    pub fn new(accumulator: Accumulator<T>, created_at: T::BlockNumber) -> Self {
        Self {
            accumulator,
            created_at,
            last_updated_at: created_at,
        }
    }
}
