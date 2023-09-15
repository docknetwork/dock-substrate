use super::*;
use crate::{common::SizeConfig, util::Bytes};
use frame_support::DebugNoBound;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulatorPublicKey<T: SizeConfig + frame_system::Config> {
    pub public_key: AccumulatorPublicKey<T>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulatorParams<T: SizeConfig + frame_system::Config> {
    pub params: AccumulatorParameters<T>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulatorParams<T: SizeConfig + frame_system::Config> {
    pub params_ref: AccumParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulatorPublicKey<T: SizeConfig + frame_system::Config> {
    pub key_ref: AccumPublicKeyStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulator<T: SizeConfig + frame_system::Config> {
    pub id: AccumulatorId,
    pub accumulator: Accumulator<T>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulator<T: SizeConfig + frame_system::Config> {
    pub id: AccumulatorId,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UpdateAccumulator<T: SizeConfig + frame_system::Config> {
    pub id: AccumulatorId,
    pub new_accumulated: Bytes,
    pub additions: Option<Vec<Bytes>>,
    pub removals: Option<Vec<Bytes>>,
    pub witness_update_info: Option<Bytes>,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    for AccumulatorId:
        UpdateAccumulator with 1 as len, id as target,
        RemoveAccumulator with 1 as len, id as target
}

crate::impl_action_with_nonce! {
    for ():
        AddAccumulator with 1 as len, () as target,
        AddAccumulatorParams with 1 as len, () as target,
        AddAccumulatorPublicKey with 1 as len, () as target,
        RemoveAccumulatorPublicKey with 1 as len, () as target,
        RemoveAccumulatorParams with 1 as len, () as target
}
