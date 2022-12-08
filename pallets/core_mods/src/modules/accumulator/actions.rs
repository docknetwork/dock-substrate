use super::*;
use crate::util::WrappedBytes;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulatorPublicKey<T: frame_system::Config> {
    pub public_key: AccumulatorPublicKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulatorParams<T: frame_system::Config> {
    pub params: AccumulatorParameters,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulatorParams<T: frame_system::Config> {
    pub params_ref: AccumParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulatorPublicKey<T: frame_system::Config> {
    pub key_ref: AccumPublicKeyStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub accumulator: Accumulator,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct RemoveAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct UpdateAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub new_accumulated: WrappedBytes,
    pub additions: Option<Vec<WrappedBytes>>,
    pub removals: Option<Vec<WrappedBytes>>,
    pub witness_update_info: Option<WrappedBytes>,
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
        AddAccumulatorPublicKey with 1 as len, () as target
}

crate::impl_action_with_nonce! {
    for AccumulatorOwner:
        RemoveAccumulatorPublicKey with 1 as len, key_ref.0 as target,
        RemoveAccumulatorParams with 1 as len, params_ref.0 as target
}
