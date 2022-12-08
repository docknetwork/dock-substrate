use super::*;
use crate::impl_action_with_nonce;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddKeys<T: frame_system::Config> {
    pub did: Did,
    pub keys: Vec<UncheckedDidKey>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveKeys<T: frame_system::Config> {
    pub did: Did,
    /// Key ids to remove
    pub keys: BTreeSet<IncId>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddControllers<T: frame_system::Config> {
    pub did: Did,
    pub controllers: BTreeSet<Controller>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveControllers<T: frame_system::Config> {
    pub did: Did,
    /// Controller ids to remove
    pub controllers: BTreeSet<Controller>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddServiceEndpoint<T: frame_system::Config> {
    pub did: Did,
    /// Endpoint id
    pub id: WrappedBytes,
    /// Endpoint data
    pub endpoint: ServiceEndpoint,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveServiceEndpoint<T: frame_system::Config> {
    pub did: Did,
    /// Endpoint id to remove
    pub id: WrappedBytes,
    pub nonce: T::BlockNumber,
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DidRemoval<T: frame_system::Config> {
    pub did: Did,
    pub nonce: T::BlockNumber,
}

impl_action_with_nonce!(
    for Did:
        AddKeys with keys.len() as len, did as target,
        RemoveKeys with keys.len() as len, did as target,
        AddControllers with controllers.len() as len, did as target,
        RemoveControllers with controllers.len() as len, did as target,
        AddServiceEndpoint with 1 as len, did as target,
        RemoveServiceEndpoint with 1 as len, did as target,
        DidRemoval with 1 as len, did as target
);
