use frame_support::DebugNoBound;
use sp_std::marker::PhantomData;

use crate::{common::Limits, util::WithNonce};
use codec::{Decode, Encode};

use super::{StatusListCredential, StatusListCredentialId};

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UpdateStatusListCredentialRaw<T: Limits> {
    pub id: StatusListCredentialId,
    pub credential: StatusListCredential<T>,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
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
pub struct RemoveStatusListCredentialRaw<T: Limits> {
    pub id: StatusListCredentialId,
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub _marker: PhantomData<T>,
}

crate::impl_action! {
    for StatusListCredentialId:
        UpdateStatusListCredentialRaw with 1 as len, id as target no_state_change,
        RemoveStatusListCredentialRaw with 1 as len, id as target no_state_change
}

pub type UpdateStatusListCredential<T> = WithNonce<T, UpdateStatusListCredentialRaw<T>>;
pub type RemoveStatusListCredential<T> = WithNonce<T, RemoveStatusListCredentialRaw<T>>;

crate::impl_action_with_nonce! {
    for StatusListCredentialId:
        UpdateStatusListCredential with data().len() as len, data().id as target,
        RemoveStatusListCredential with data().len() as len, data().id as target
}
