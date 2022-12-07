use crate::{
    did::Did,
    impl_type_info,
    types::CurveType,
    util::{IncId, WrappedBytes},
};
use codec::{Decode, Encode};

/// DID owner of the BBSPlus parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BBSPlusParamsOwner(pub Did);

crate::impl_wrapper!(BBSPlusParamsOwner, Did, for rand use Did(rand::random()), with tests as bbs_plus_params_owner_tests);

pub type BBSPlusParametersStorageKey = (BBSPlusParamsOwner, IncId);
pub type BBSPlusPublicKeyStorageKey = (Did, IncId);
pub type BBSPlusPublicKeyWithParams = (BBSPlusPublicKey, Option<BBSPlusParameters>);

impl_type_info! {
    /// Signature params in G1 for BBS+ signatures
    #[derive(Encode, Decode, Clone, PartialEq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct BBSPlusParameters {
        /// The label (generating string) used to generate the params
        pub label: Option<WrappedBytes>,
        pub curve_type: CurveType,
        pub bytes: WrappedBytes,
    }
}

impl_type_info! {
    /// Public key in G2 for BBS+ signatures
    #[derive(Encode, Decode, Clone, PartialEq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct BBSPlusPublicKey {
        /// The public key should be for the same curve as the parameters but a public key might not have
        /// parameters on chain
        pub curve_type: CurveType,
        pub bytes: WrappedBytes,
        /// The params used to generate the public key (`g2` comes from params)
        pub params_ref: Option<BBSPlusParametersStorageKey>,
    }
}
