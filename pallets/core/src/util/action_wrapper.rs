use crate::common::{ToStateChange, Types, TypesAndLimits};

use super::{Action, ActionExecutionError, ActionWithNonce, NonceError, StorageRef};
use codec::{Decode, Encode};

/// Wraps any value in an action with the given target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct ActionWrapper<A, Ta> {
    pub target: Ta,
    pub action: A,
}

impl<A, Ta> ActionWrapper<A, Ta> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(target: Ta, action: A) -> Self {
        Self { target, action }
    }

    /// Wraps given function producing a function that takes `ActionWrapper` as a parameter.
    pub fn wrap_fn<V, O, F: FnOnce(A, V) -> O>(f: F) -> impl FnOnce(Self, V) -> O {
        move |Self { action, .. }, value| f(action, value)
    }
}

impl<A: Action, Ta: Clone> Action for ActionWrapper<A, Ta> {
    type Target = Ta;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: TypesAndLimits, A: Action, Ta: Clone> ToStateChange<T> for ActionWrapper<A, Ta>
where
    A: ToStateChange<T>,
{
    fn to_state_change(&self) -> crate::common::StateChange<'_, T> {
        self.action.to_state_change()
    }
}

/// Wraps any value in an action with the supplied nonce and given target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct ActionWithNonceWrapper<T: Types, A, Ta> {
    pub action: A,
    pub nonce: T::BlockNumber,
    pub target: Ta,
}

impl<T: Types, A, Ta> ActionWithNonceWrapper<T, A, Ta> {
    /// Wraps any value in an action with the supplied nonce and given target.
    pub fn new(nonce: T::BlockNumber, target: Ta, action: A) -> Self {
        Self {
            nonce,
            target,
            action,
        }
    }

    /// Wraps given function producing a function that takes `ActionWithNonceWrapper` as a parameter.
    pub fn wrap_fn<V, O, F: FnOnce(A, &mut V, Ta) -> O>(
        f: F,
    ) -> impl FnOnce(Self, &mut V, Ta) -> O {
        move |Self { action, .. }, value, target| f(action, value, target)
    }

    /// Wraps given function producing a function that takes `ActionWithNonceWrapper` as a parameter and then executes `action.modify`.
    pub fn wrap_fn_with_modify_removable_action<V, O, E, F>(
        f: F,
    ) -> impl FnOnce(Self, &mut V, Ta) -> Result<O, E>
    where
        A: Action,
        A::Target: StorageRef<T>,
        F: FnOnce(A, &mut V, &mut Option<<A::Target as StorageRef<T>>::Value>, Ta) -> Result<O, E>,
        E: From<ActionExecutionError> + From<NonceError>,
    {
        Self::wrap_fn(|action, value, target| {
            action.modify_removable(|action, other_value| f(action, value, other_value, target))
        })
    }
}

impl<T: Types, A: Action, Ta: Clone> Action for ActionWithNonceWrapper<T, A, Ta> {
    type Target = Ta;

    fn target(&self) -> Self::Target {
        self.target.clone()
    }

    fn len(&self) -> u32 {
        self.action.len()
    }
}

impl<T: Types, A: Action, Ta: Clone> ActionWithNonce<T> for ActionWithNonceWrapper<T, A, Ta> {
    fn nonce(&self) -> T::BlockNumber {
        self.nonce
    }
}

impl<T: TypesAndLimits, A: Action, Ta: Clone> ToStateChange<T> for ActionWithNonceWrapper<T, A, Ta>
where
    A: ToStateChange<T>,
{
    fn to_state_change(&self) -> crate::common::StateChange<'_, T> {
        self.action.to_state_change()
    }
}
