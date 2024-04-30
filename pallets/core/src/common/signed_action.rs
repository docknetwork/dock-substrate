use crate::{
    common::{Authorization, AuthorizeSignedAction, AuthorizeTarget, ToStateChange},
    did::*,
    util::{action::*, signature::Signature, with_nonce::*, ActionWrapper, AnyOfOrAll},
};
use alloc::collections::BTreeSet;
use core::ops::Deref;
use frame_support::ensure;

use super::DidSignatureWithNonce;

impl<T: Config, A, Sig> SignedActionWithNonce<T, A, Sig>
where
    A: ActionWithNonce<T> + ToStateChange<T>,
    Sig: AuthorizeSignedAction<A>,
    Sig::Signer: AuthorizeTarget<A::Target, Sig::Key> + Deref,
    <Sig::Signer as Deref>::Target: AuthorizeTarget<A::Target, Sig::Key>,
{
    /// Verifies signer's signature and nonce, then executes given action without providing target data.
    /// In case of a successful result, increases the signer's nonce.
    pub fn execute_without_target_data<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, Sig::Signer) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let Self {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        ActionWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWrapper { action, .. }, _| f(action, signer))
            .map_err(Into::into)
    }

    /// Verifies signer's signature and nonce, then executes given action providing a reference to the
    /// value associated with the target.
    /// In case of a successful result, increases the signer's nonce.
    pub fn execute_view<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, <A::Target as StorageRef<T>>::Value, Sig::Signer) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let Self {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        ActionWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWrapper { action, .. }, _| {
                action.execute_view(|action, target_data| f(action, target_data, signer))
            })
            .map_err(Into::into)
    }

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
        let Self {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        ActionWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWrapper { action, .. }, _| {
                action.execute_removable(|action, target_data| f(action, target_data, signer))
            })
            .map_err(Into::into)
    }
}

impl<T: Config, A, SI, D> MultiSignedActionWithNonces<T, A, SI, D>
where
    SI: Iterator<Item = DidSignatureWithNonce<T::BlockNumber, D>>,
    A: Action,
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone + Ord,
{
    pub fn execute<R, E, S>(
        self,
        f: impl FnOnce(A, &mut <<A as Action>::Target as StorageRef<T>>::Value) -> Result<R, E>,
        signers: impl FnOnce(&<<A as Action>::Target as StorageRef<T>>::Value) -> AnyOfOrAll<D>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        <A as Action>::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        <D as Deref>::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.execute(|action, data| {
            Self::new(action, signatures).execute_inner(f, data, Some((signers)(&data)))
        })
    }

    pub fn execute_view<R, E, S>(
        self,
        f: impl FnOnce(A, <<A as Action>::Target as StorageRef<T>>::Value) -> Result<R, E>,
        signers: impl FnOnce(&<<A as Action>::Target as StorageRef<T>>::Value) -> AnyOfOrAll<D>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        <A as Action>::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        <D as Deref>::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.execute_view(|action, data| {
            Self::new(action, signatures).execute_inner(f, data, Some((signers)(&data)))
        })
    }

    pub fn execute_removable<R, E, S>(
        self,
        f: impl FnOnce(A, &mut Option<<<A as Action>::Target as StorageRef<T>>::Value>) -> Result<R, E>,
        signers: impl FnOnce(&<<A as Action>::Target as StorageRef<T>>::Value) -> AnyOfOrAll<D>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        <A as Action>::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        <D as Deref>::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.execute_removable(|action, data| {
            Self::new(action, signatures).execute_inner(
                f,
                data,
                Some((signers)(&data.as_ref().unwrap())),
            )
        })
    }

    fn execute_inner<Data, R, E, S>(
        self,
        f: impl FnOnce(A, Data) -> Result<R, E>,
        data: Data,
        required_signers: Option<AnyOfOrAll<D>>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        <D as Deref>::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action,
            mut signatures,
            ..
        } = self;

        if let Some(DidSignatureWithNonce { sig, nonce }) = signatures.next() {
            let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
            let signed_action = action_with_nonce.signed(sig);
            let signer = sig.signer().ok_or(ActionExecutionError::InvalidSigner)?;

            let signers = required_signers
                .map(|signers| {
                    signers
                        .exclude(&signer)
                        .map_err(|_| ActionExecutionError::InvalidSigner)
                })
                .transpose()?
                .flatten();

            signed_action.execute_without_target_data(|action, _| {
                Self::new(action.into_data(), signatures).execute_inner(f, data, signers)
            })
        } else {
            ensure!(
                required_signers.is_none(),
                ActionExecutionError::NotEnoughSignatures
            );

            f(action, data)
        }
    }
}
