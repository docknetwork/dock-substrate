use super::*;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AddKeys<T: frame_system::Config> {
    pub did: Did,
    pub keys: Vec<DidKey>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RemoveKeys<T: frame_system::Config> {
    pub did: Did,
    /// Key ids to remove
    pub keys: BTreeSet<IncId>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AddControllers<T: frame_system::Config> {
    pub did: Did,
    pub controllers: BTreeSet<Controller>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RemoveControllers<T: frame_system::Config> {
    pub did: Did,
    /// Controller ids to remove
    pub controllers: BTreeSet<Controller>,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AddServiceEndpoint<T: frame_system::Config> {
    pub did: Did,
    /// Endpoint id
    pub id: WrappedBytes,
    /// Endpoint data
    pub endpoint: ServiceEndpoint,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RemoveServiceEndpoint<T: frame_system::Config> {
    pub did: Did,
    /// Endpoint id to remove
    pub id: WrappedBytes,
    pub nonce: T::BlockNumber,
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DidRemoval<T: frame_system::Config> {
    pub did: Did,
    pub nonce: T::BlockNumber,
}

impl_action_with_nonce!(
    for Did:
        AddKeys with keys as len, did as target,
        RemoveKeys with keys as len, did as target,
        AddControllers with controllers as len, did as target,
        RemoveControllers with controllers as len, did as target,
        AddServiceEndpoint with 1 as len, did as target,
        RemoveServiceEndpoint with 1 as len, did as target,
        DidRemoval with 1 as len, did as target
);

/// Wraps any action in an action with the given target.
pub(super) struct ActionWrapper<T: Config, A, D> {
    pub nonce: T::BlockNumber,
    pub action: A,
    pub target: D,
}

impl<T: Config, A, D> ActionWrapper<T, A, D> {
    /// Wraps any action in an action with the given target.
    pub fn new(nonce: T::BlockNumber, action: A, target: D) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }
}

impl<T: Config, A: Action<T>, D: Copy> Action<T> for ActionWrapper<T, A, D> {
    type Target = D;

    fn target(&self) -> Self::Target {
        self.target
    }

    fn len(&self) -> u32 {
        self.action.len()
    }

    fn to_state_change(&self) -> crate::StateChange<'_, T> {
        self.action.to_state_change()
    }

    fn into_state_change(self) -> crate::StateChange<'static, T> {
        self.action.into_state_change()
    }
}

impl<T: Config, A: Action<T>, D: Copy> ActionWithNonce<T> for ActionWrapper<T, A, D> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}
