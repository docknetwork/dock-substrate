use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};

use super::*;
use crate::{
    common::{AuthorizeTarget, Limits, TypesAndLimits},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    util::{Associated, BoundedBytes, OptionExt, StorageRef},
};

pub type AccumPublicKeyWithParams<T> = (AccumulatorPublicKey<T>, Option<AccumulatorParameters<T>>);

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumParametersStorageKey(pub AccumulatorOwner, pub IncId);

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumPublicKeyStorageKey(pub AccumulatorOwner, pub IncId);

/// Accumulator identifier.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorId(
    #[cfg_attr(feature = "serde", serde(with = "crate::util::serde_hex"))] pub [u8; 32],
);

crate::impl_wrapper!(AccumulatorId([u8; 32]), with tests as acc_tests);

/// Accumulator owner - DID with the ability to control given accumulator keys, params, etc.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct AccumulatorOwner(pub DidOrDidMethodKey);

crate::impl_wrapper!(AccumulatorOwner(DidOrDidMethodKey));

impl<T: TypesAndLimits> Associated<T> for AccumulatorId {
    type Value = AccumulatorWithUpdateInfo<T>;
}

impl<T: Config> StorageRef<T> for AccumulatorId {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<AccumulatorWithUpdateInfo<T>>) -> Result<R, E>,
    {
        Accumulators::<T>::try_mutate_exists(self, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<AccumulatorWithUpdateInfo<T>>) -> R,
    {
        f(Accumulators::<T>::get(self))
    }
}

impl<T: Limits> Associated<T> for AccumPublicKeyStorageKey {
    type Value = AccumulatorPublicKey<T>;
}

impl<T: Config> StorageRef<T> for AccumPublicKeyStorageKey {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<AccumulatorPublicKey<T>>) -> Result<R, E>,
    {
        AccumulatorKeys::<T>::try_mutate_exists(self.0, self.1, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<AccumulatorPublicKey<T>>) -> R,
    {
        f(AccumulatorKeys::<T>::get(self.0, self.1))
    }
}

impl<T: Limits> Associated<T> for AccumParametersStorageKey {
    type Value = AccumulatorParameters<T>;
}

impl<T: Config> StorageRef<T> for AccumParametersStorageKey {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<AccumulatorParameters<T>>) -> Result<R, E>,
    {
        AccumulatorParams::<T>::try_mutate_exists(self.0, self.1, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<AccumulatorParameters<T>>) -> R,
    {
        f(AccumulatorParams::<T>::get(self.0, self.1))
    }
}

impl<T: TypesAndLimits> AuthorizeTarget<T, AccumulatorId, DidKey> for AccumulatorOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, AccumulatorId, DidMethodKey> for AccumulatorOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, Self, DidKey> for AccumulatorOwner {}
impl<T: TypesAndLimits> AuthorizeTarget<T, Self, DidMethodKey> for AccumulatorOwner {}
crate::impl_authorize_target!(
    for AccumPublicKeyStorageKey: AccumulatorOwner fn (self, _, action, _) {
        ensure!(action.target().0 == *self, Error::<T>::NotPublicKeyOwner);
    }
);

crate::impl_authorize_target!(
    for AccumParametersStorageKey: AccumulatorOwner fn (self, _, action, _) {
        ensure!(action.target().0 == *self, Error::<T>::NotParamsOwner);
    }
);

impl<T: TypesAndLimits> Associated<T> for AccumulatorOwner {
    type Value = StoredAccumulatorOwnerCounters;
}

impl<T: Config> StorageRef<T> for AccumulatorOwner {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<StoredAccumulatorOwnerCounters>) -> Result<R, E>,
    {
        AccumulatorOwnerCounters::<T>::try_mutate_exists(self, |entry| f(entry.initialized()))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<StoredAccumulatorOwnerCounters>) -> R,
    {
        f(Some(AccumulatorOwnerCounters::<T>::get(self)))
    }
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
    KBUniversal(AccumulatorCommon<T>),
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
            Accumulator::KBUniversal(a) => a.key_ref,
        }
    }

    /// DID of the owner of the accumulator
    pub fn owner_did(&self) -> &AccumulatorOwner {
        match self {
            Accumulator::Positive(a) => &a.key_ref.0,
            Accumulator::Universal(a) => &a.common.key_ref.0,
            Accumulator::KBUniversal(a) => &a.key_ref.0,
        }
    }

    pub fn accumulated(&self) -> &[u8] {
        match self {
            Accumulator::Positive(a) => &a.accumulated,
            Accumulator::Universal(a) => &a.common.accumulated,
            Accumulator::KBUniversal(a) => &a.accumulated,
        }
    }

    pub fn set_new_accumulated<A>(&mut self, new_accumulated: A) -> Result<&mut Self, A::Error>
    where
        A: TryInto<BoundedBytes<T::MaxAccumulatorAccumulatedSize>>,
    {
        match self {
            Accumulator::Positive(a) => a.accumulated = new_accumulated.try_into()?,
            Accumulator::Universal(a) => a.common.accumulated = new_accumulated.try_into()?,
            Accumulator::KBUniversal(a) => a.accumulated = new_accumulated.try_into()?,
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
