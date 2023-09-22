use super::*;
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
pub struct AddRegistry<T: Limits> {
    pub id: RegistryId,
    pub new_registry: Registry<T>,
}

/// Command to create a set of revocations withing a registry.
/// Creation of revocations is idempotent; creating a revocation that already exists is allowed,
/// but has no effect.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RevokeRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
}

/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UnRevokeRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    /// Credential ids which will be revoked
    pub revoke_ids: BTreeSet<RevokeId>,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
}

/// Command to remove an entire registry. Removes all revocations in the registry as well as
/// registry metadata.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, DebugNoBound, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveRegistryRaw<T> {
    /// The registry on which to operate
    pub registry_id: RegistryId,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
}

crate::impl_action! {
    for RegistryId:
        RevokeRaw with revoke_ids.len() as len, registry_id as target no_state_change,
        UnRevokeRaw with revoke_ids.len() as len, registry_id as target no_state_change,
        RemoveRegistryRaw with 1 as len, registry_id as target no_state_change
}

/// Command to create a set of revocations withing a registry.
/// Creation of revocations is idempotent; creating a revocation that already exists is allowed,
/// but has no effect.
pub type Revoke<T> = WithNonce<T, RevokeRaw<T>>;
/// Command to remove a set of revocations within a registry.
/// Removal of revocations is idempotent; removing a revocation that doesn't exists is allowed,
/// but has no effect.
pub type UnRevoke<T> = WithNonce<T, UnRevokeRaw<T>>;
/// Command to remove an entire registry. Removes all revocations in the registry as well as
/// registry metadata.
pub type RemoveRegistry<T> = WithNonce<T, RemoveRegistryRaw<T>>;

crate::impl_action_with_nonce! {
    for RegistryId:
        UnRevoke with data().len() as len, data().registry_id as target,
        Revoke with data().len() as len, data().registry_id as target,
        RemoveRegistry with data().len() as len, data().registry_id as target
}
