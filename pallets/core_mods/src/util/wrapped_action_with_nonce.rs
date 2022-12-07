use crate::{Action, ActionWithNonce};
use codec::{Decode, Encode};
use frame_system::Config;

/// Wraps any value in an action with the supplied nonce and given target.
#[derive(Clone, Debug, PartialEq, Encode, Decode, scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct WrappedActionWithNonce<T: Config, A, Ta> {
    pub nonce: T::BlockNumber,
    pub target: Ta,
    pub action: A,
}

impl<T: Config, A, Ta> WrappedActionWithNonce<T, A, Ta> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(nonce: T::BlockNumber, target: Ta, action: A) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }
}

impl<T: Config, A: Action<T>, Ta: Clone> Action<T> for WrappedActionWithNonce<T, A, Ta> {
    type Target = Ta;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: Config, A: Action<T>, Ta: Clone> ActionWithNonce<T> for WrappedActionWithNonce<T, A, Ta> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}
