use crate::{Action, ActionWithNonce, ToStateChange};
use codec::{Decode, Encode};
use frame_system::Config;

/// Wraps any value in an action with the supplied nonce and given target.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct WrappedActionWithNonce<T: Config, A, D> {
    pub nonce: T::BlockNumber,
    pub target: D,
    pub action: A,
}

impl<T: Config, A, D> WrappedActionWithNonce<T, A, D> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(nonce: T::BlockNumber, target: D, action: A) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }
}

impl<T: Config, A: Action<T>, D: Clone> Action<T> for WrappedActionWithNonce<T, A, D> {
    type Target = D;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: Config, A: Action<T>, D: Clone> ActionWithNonce<T> for WrappedActionWithNonce<T, A, D> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}

impl<T: frame_system::Config, A: Action<T> + ToStateChange<T>, D: Clone> ToStateChange<T>
    for WrappedActionWithNonce<T, A, D>
{
    fn to_state_change(&self) -> crate::StateChange<'_, T> {
        self.action.to_state_change()
    }

    fn into_state_change(self) -> crate::StateChange<'static, T> {
        self.action.into_state_change()
    }
}
