use crate::common::{ToStateChange, Types, TypesAndLimits};

use super::{Action, ActionWithNonce};
use codec::{Decode, Encode};

/// Wraps any value in an action with the supplied nonce and given target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct ActionWrapper<T: Types, A, Ta> {
    pub nonce: T::BlockNumber,
    pub target: Ta,
    pub action: A,
}

impl<T: Types, A, Ta> ActionWrapper<T, A, Ta> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(nonce: T::BlockNumber, target: Ta, action: A) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }

    /// Wraps given function producing a function that takes `ActionWrapper` as a parameter.
    pub fn wrap_fn<V, O, F: FnOnce(A, &mut V, Ta) -> O>(
        f: F,
    ) -> impl FnOnce(Self, &mut V, Ta) -> O {
        move |Self { action, .. }, value, target| f(action, value, target)
    }
}

impl<T: Types, A: Action, Ta: Clone> Action for ActionWrapper<T, A, Ta> {
    type Target = Ta;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: Types, A: Action, Ta: Clone> ActionWithNonce<T> for ActionWrapper<T, A, Ta> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}

impl<T: TypesAndLimits, A: Action, Ta: Clone> ToStateChange<T> for ActionWrapper<T, A, Ta>
where
    A: ToStateChange<T>,
{
    fn to_state_change(&self) -> crate::common::StateChange<'_, T> {
        self.action.to_state_change()
    }
}
