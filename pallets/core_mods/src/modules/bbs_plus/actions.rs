use super::*;

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddBBSPlusParams<T: frame_system::Config> {
    pub params: BbsPlusParameters,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddBBSPlusPublicKey<T: frame_system::Config> {
    pub key: BbsPlusPublicKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveBBSPlusParams<T: frame_system::Config> {
    pub params_ref: BBSPlusParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveBBSPlusPublicKey<T: frame_system::Config> {
    pub key_ref: BBSPlusPublicKeyStorageKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce!(
    for Did:
        AddBBSPlusPublicKey with 1 as len, did as target,
        RemoveBBSPlusPublicKey with 1 as len, did as target
);

crate::impl_action_with_nonce!(
    for ():
        AddBBSPlusParams with 1 as len, () as target,
        RemoveBBSPlusParams with 1 as len, () as target
);
