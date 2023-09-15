use crate::common::SizeConfig;
use frame_support::DebugNoBound;

use super::*;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddOffchainSignatureParams<T: SizeConfig + frame_system::Config> {
    pub params: OffchainSignatureParams<T>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddOffchainSignaturePublicKey<T: SizeConfig + frame_system::Config> {
    pub key: OffchainPublicKey<T>,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveOffchainSignatureParams<T: SizeConfig + frame_system::Config> {
    pub params_ref: SignatureParamsStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Eq, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveOffchainSignaturePublicKey<T: SizeConfig + frame_system::Config> {
    pub key_ref: SignaturePublicKeyStorageKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    for Did:
        AddOffchainSignaturePublicKey with 1 as len, did as target,
        RemoveOffchainSignaturePublicKey with 1 as len, did as target
}

crate::impl_action_with_nonce! {
    for ():
        AddOffchainSignatureParams with 1 as len, () as target,
        RemoveOffchainSignatureParams with 1 as len, () as target
}
