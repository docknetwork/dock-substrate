use super::*;

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddAccumulatorPublicKey<T: frame_system::Config> {
    pub public_key: AccumulatorPublicKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulatorParams<T: frame_system::Config> {
    pub params_ref: AccumParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulatorPublicKey<T: frame_system::Config> {
    pub key_ref: AccumPublicKeyStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub accumulator: Accumulator,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub new_accumulated: Vec<u8>,
    pub additions: Option<Vec<Vec<u8>>>,
    pub removals: Option<Vec<Vec<u8>>>,
    pub witness_update_info: Option<Vec<u8>>,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    for ():
        AddAccumulatorParams with 1 as len, () as target,
        AddAccumulatorPublicKey with 1 as len, () as target,
        RemoveAccumulatorParams with 1 as len, () as target,
        RemoveAccumulatorPublicKey with 1 as len, () as target,
        AddAccumulator with 1 as len, () as target,
        UpdateAccumulator with 1 as len, () as target,
        RemoveAccumulator with 1 as len, () as target
}
