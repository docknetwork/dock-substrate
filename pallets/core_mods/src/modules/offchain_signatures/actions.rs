use super::*;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddOffchainSignatureParams<T: frame_system::Config> {
    pub params: OffchainSignatureParams,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddOffchainSignaturePublicKey<T: frame_system::Config> {
    pub key: OffchainPublicKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveOffchainSignatureParams<T: frame_system::Config> {
    pub params_ref: OffchainSignatureParamsStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveOffchainSignaturePublicKey<T: frame_system::Config> {
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
