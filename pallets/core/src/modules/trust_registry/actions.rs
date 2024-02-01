use super::*;
use crate::{common::TypesAndLimits, impl_action_with_nonce, util::BoundedBytes};
use alloc::collections::{BTreeMap, BTreeSet};
use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use utils::BoundedString;

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
pub struct InitOrUpdateTrustRegistry<T: TypesAndLimits> {
    pub registry_id: TrustRegistryId,
    pub name: BoundedString<T::MaxTrustRegistryNameSize>,
    pub gov_framework: BoundedBytes<T::MaxTrustRegistryGovFrameworkSize>,
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
pub struct AddSchemaMetadata<T: TypesAndLimits> {
    pub registry_id: TrustRegistryId,
    pub schemas: BTreeMap<TrustRegistrySchemaId, TrustRegistrySchemaMetadata<T>>,
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
pub struct UpdateSchemaMetadata<T: TypesAndLimits> {
    pub registry_id: TrustRegistryId,
    pub schemas: BTreeMap<TrustRegistrySchemaId, SchemaMetadataModification<T>>,
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
pub struct SuspendIssuers<T: TypesAndLimits> {
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
pub struct UnsuspendIssuers<T: TypesAndLimits> {
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
pub struct UpdateDelegatedIssuers<T: TypesAndLimits> {
    pub registry_id: TrustRegistryId,
    pub delegated: DelegatedUpdate<T>,
    pub nonce: T::BlockNumber,
}

impl_action_with_nonce!(
    for ():
        InitOrUpdateTrustRegistry with 1 as len, () as target,
        UpdateDelegatedIssuers with delegated.len() as len, () as target
);

impl_action_with_nonce!(
    for TrustRegistryId:
        AddSchemaMetadata with schemas.len() as len, registry_id as target,
        UpdateSchemaMetadata with schemas.len() as len, registry_id as target,
        SuspendIssuers with issuers.len() as len, registry_id as target,
        UnsuspendIssuers with issuers.len() as len, registry_id as target
);
