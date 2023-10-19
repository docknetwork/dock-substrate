use crate::common::Types;

use super::{Action, ActionWithNonce};
use codec::{Decode, Encode};

/// Wraps any value in an action with the supplied nonce and given target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct WrappedActionWithNonce<T: Types, A, Ta> {
    pub nonce: T::BlockNumber,
    pub target: Ta,
    pub action: A,
}

impl<T: Types, A, Ta> WrappedActionWithNonce<T, A, Ta> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(nonce: T::BlockNumber, target: Ta, action: A) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }
}

impl<T: Types, A: Action, Ta: Clone> Action for WrappedActionWithNonce<T, A, Ta> {
    type Target = Ta;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: Types, A: Action, Ta: Clone> ActionWithNonce<T> for WrappedActionWithNonce<T, A, Ta> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}
