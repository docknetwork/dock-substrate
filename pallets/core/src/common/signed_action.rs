use crate::{
    common::{Authorization, AuthorizeSignedAction, AuthorizeTarget, ToStateChange},
    did::*,
    util::{action::*, with_nonce::*, WrappedActionWithNonce},
};
use core::ops::Deref;

impl<T: Config, A, Sig> SignedActionWithNonce<T, A, Sig>
where
    A: ActionWithNonce<T> + ToStateChange<T>,
    Sig: AuthorizeSignedAction<A>,
    Sig::Signer: AuthorizeTarget<A::Target, Sig::Key> + Deref,
{
    /// Verifies signer's signature and nonce, then executes given action providing a mutable reference to the
    /// value associated with the target.
    /// In case of a successful result, commits all storage changes and increases the signer's nonce.
    pub fn execute<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut <A::Target as StorageRef<T>>::Value, Sig::Signer) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        self.execute_removable(|action, data, actor| f(action, data.as_mut().unwrap(), actor))
    }

    /// Verifies signer's signature and nonce, then executes given action providing a mutable reference to the
    /// option containing a value associated with the target.
    /// In case of a successful result, commits all storage changes and increases the signer's nonce.
    pub fn execute_removable<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<<A::Target as StorageRef<T>>::Value>, Sig::Signer) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let SignedActionWithNonce {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        WrappedActionWithNonce::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|WrappedActionWithNonce { action, .. }, _| {
                action.execute_removable(|action, target_data| f(action, target_data, signer))
            })
            .map_err(Into::into)
    }
}
