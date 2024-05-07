use crate::{
    common::{Authorization, AuthorizeSignedAction, AuthorizeTarget, ToStateChange},
    did::*,
    util::{action::*, signature::Signature, with_nonce::*, ActionWithNonceWrapper, AnyOfOrAll},
};
use alloc::collections::BTreeSet;
use core::{iter::FusedIterator, ops::Deref};

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

        ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
                f(action, signer)
            })
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

        ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
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

        ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
                action.execute_removable(|action, target_data| f(action, target_data, signer))
            })
            .map_err(Into::into)
    }
}

impl<T: Config, A, SI, D> MultiSignedActionWithNonces<T, A, SI, D>
where
    SI: FusedIterator<Item = DidSignatureWithNonce<T::BlockNumber, D>>,
    A: Action,
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone + Ord,
{
    pub fn execute<R, E, S>(
        self,
        f: impl FnOnce(
            A,
            &mut <<A as Action>::Target as StorageRef<T>>::Value,
            BTreeSet<D>,
        ) -> Result<R, E>,
        required_signers: impl FnOnce(
            &<<A as Action>::Target as StorageRef<T>>::Value,
        ) -> Option<AnyOfOrAll<D>>,
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
            Self::new(action, signatures).execute_inner(
                f,
                data,
                BTreeSet::new(),
                (required_signers)(&data),
            )
        })
    }

    pub fn execute_view<R, E, S>(
        self,
        f: impl FnOnce(A, <<A as Action>::Target as StorageRef<T>>::Value, BTreeSet<D>) -> Result<R, E>,
        required_signers: impl FnOnce(
            &<<A as Action>::Target as StorageRef<T>>::Value,
        ) -> Option<AnyOfOrAll<D>>,
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
            let required_signers = (required_signers)(&data);

            Self::new(action, signatures).execute_inner(f, data, BTreeSet::new(), required_signers)
        })
    }

    pub fn execute_removable<R, E, S>(
        self,
        f: impl FnOnce(
            A,
            &mut Option<<<A as Action>::Target as StorageRef<T>>::Value>,
            BTreeSet<D>,
        ) -> Result<R, E>,
        required_signers: impl FnOnce(
            &<<A as Action>::Target as StorageRef<T>>::Value,
        ) -> Option<AnyOfOrAll<D>>,
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
            let required_signers = (required_signers)(&data.as_ref().unwrap());

            Self::new(action, signatures).execute_inner(f, data, BTreeSet::new(), required_signers)
        })
    }

    fn execute_inner<Data, R, E, S>(
        self,
        f: impl FnOnce(A, Data, BTreeSet<D>) -> Result<R, E>,
        data: Data,
        mut verified_signers: BTreeSet<D>,
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

        match (required_signers, signatures.next()) {
            (None, None) => f(action, data, verified_signers),
            (None, Some(_)) => Err(ActionExecutionError::TooManySignatures.into()),
            (Some(_), None) => Err(ActionExecutionError::NotEnoughSignatures.into()),
            (Some(signers), Some(DidSignatureWithNonce { sig, nonce })) => {
                let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
                let signer = sig.signer().ok_or(ActionExecutionError::InvalidSigner)?;
                let signed_action = action_with_nonce.signed(sig);

                verified_signers.insert(signer.clone());
                let required_signers = signers
                    .exclude(&signer)
                    .map_err(|_| ActionExecutionError::NotEnoughSignatures)?;

                signed_action.execute_without_target_data(|action, _| {
                    Self::new(action.into_data(), signatures).execute_inner(
                        f,
                        data,
                        verified_signers,
                        required_signers,
                    )
                })
            }
        }
    }
}
