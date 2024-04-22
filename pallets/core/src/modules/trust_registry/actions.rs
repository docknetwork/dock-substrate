use super::*;
use crate::{
    impl_action_with_nonce,
    util::{Bytes, Types},
};
use alloc::{collections::BTreeSet, string::String};
use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};

#[derive(
    Encode,
    Decode,
    scale_info_derive::TypeInfo,
    DebugNoBound,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct InitOrUpdateTrustRegistry<T: Types> {
    pub registry_id: TrustRegistryId,
    pub name: String,
    pub gov_framework: Bytes,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct SetSchemasMetadata<T: Types> {
    pub registry_id: TrustRegistryId,
    pub schemas: UnboundedSchemasUpdate,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct SuspendIssuers<T: Types> {
    pub registry_id: TrustRegistryId,
    pub issuers: BTreeSet<Issuer>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UnsuspendIssuers<T: Types> {
    pub registry_id: TrustRegistryId,
    pub issuers: BTreeSet<Issuer>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UpdateDelegatedIssuers<T: Types> {
    pub registry_id: TrustRegistryId,
    pub delegated: UnboundedDelegatedUpdate,
    pub nonce: T::BlockNumber,
}

impl_action_with_nonce!(
    for ():
        InitOrUpdateTrustRegistry with 1 as len, () as target,
        UpdateDelegatedIssuers with 1 as len, () as target
);

impl_action_with_nonce!(
    for TrustRegistryId:
        SetSchemasMetadata with { |this: &Self| match &this.schemas { SetOrModify::Set(_) => 1, SetOrModify::Modify(update) => update.len() } } as len, registry_id as target,
        SuspendIssuers with issuers.len() as len, registry_id as target,
        UnsuspendIssuers with issuers.len() as len, registry_id as target
);
