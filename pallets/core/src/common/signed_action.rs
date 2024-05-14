use crate::{
    common::{Authorization, AuthorizeSignedAction, AuthorizeTarget, ToStateChange},
    did::*,
    util::{
        action::*, signature::Signature, with_nonce::*, ActionWithNonceWrapper, AnyOfOrAll, Types,
    },
};
use alloc::collections::BTreeSet;
use core::{iter::FusedIterator, marker::PhantomData, ops::Deref};

use super::DidSignatureWithNonce;

pub struct SignedActionWithNonce<T: Types, A, S>
where
    A: ActionWithNonce<T>,
{
    pub action: A,
    pub signature: S,
    _marker: PhantomData<T>,
}

impl<T: Types, A, S> SignedActionWithNonce<T, A, S>
where
    A: ActionWithNonce<T>,
{
    pub fn new(action: A, signature: S) -> Self {
        Self {
            action,
            signature,
            _marker: PhantomData,
        }
    }
}

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

    /// Verifies signer's signature and nonce, then executes given action providing a
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
                action.view(|action, target_data| f(action, target_data, signer))
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
        self.execute_removable(|action, data, actor| {
            let Some(data_ref) = data.as_mut() else {
                Err(ActionExecutionError::NoEntity)?
            };

            f(action, data_ref, actor)
        })
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
                action.modify_removable(|action, target_data| f(action, target_data, signer))
            })
            .map_err(Into::into)
    }
}

/// An action signed by multiple signers with their corresponding nonces.
pub struct MultiSignedAction<T: Types, A, SI, D>
where
    A: Action,
    D: Ord,
{
    pub action: A,
    pub signatures: SI,
    _marker: PhantomData<(T, D)>,
}

impl<T: Types, A, SI, D> MultiSignedAction<T, A, SI, D>
where
    A: Action,
    SI: FusedIterator<Item = DidSignatureWithNonce<T::BlockNumber, D>>,
    D: Into<DidOrDidMethodKey> + Ord,
{
    pub fn new<S>(action: A, signatures: S) -> Self
    where
        S: IntoIterator<IntoIter = SI>,
    {
        Self {
            action,
            signatures: signatures.into_iter(),
            _marker: PhantomData,
        }
    }
}

impl<T: Config, A, SI, D> MultiSignedAction<T, A, SI, D>
where
    SI: FusedIterator<Item = DidSignatureWithNonce<T::BlockNumber, D>>,
    A: Action,
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone + Ord,
{
    /// Verifies signature and nonce for all required signers, then executes given action providing a mutable reference to the
    /// value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers.
    pub fn execute<R, E, S>(
        self,
        f: impl FnOnce(A, &mut <A::Target as StorageRef<T>>::Value, BTreeSet<D>) -> Result<R, E>,
        required_signers: impl FnOnce(&<A::Target as StorageRef<T>>::Value) -> Option<AnyOfOrAll<D>>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        A::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        D::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.modify(|action, data| {
            Self::new(action, signatures).execute_inner(
                f,
                data,
                BTreeSet::new(),
                (required_signers)(&data),
            )
        })
    }

    /// Verifies signature and nonce for all required signers, then executes given action providing a
    /// value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers
    pub fn execute_view<R, E, S>(
        self,
        f: impl FnOnce(A, <A::Target as StorageRef<T>>::Value, BTreeSet<D>) -> Result<R, E>,
        required_signers: impl FnOnce(&<A::Target as StorageRef<T>>::Value) -> Option<AnyOfOrAll<D>>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        A::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        D::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.view(|action, data| {
            let required_signers = (required_signers)(&data);

            Self::new(action, signatures).execute_inner(f, data, BTreeSet::new(), required_signers)
        })
    }

    /// Verifies signature and nonce for all required signers, then executes given action providing  a mutable reference to the
    /// option containing value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers.
    pub fn execute_removable<R, E, S>(
        self,
        f: impl FnOnce(A, &mut Option<<A::Target as StorageRef<T>>::Value>, BTreeSet<D>) -> Result<R, E>,
        required_signers: impl FnOnce(
            Option<&<A::Target as StorageRef<T>>::Value>,
        ) -> Option<AnyOfOrAll<D>>,
    ) -> Result<R, E>
    where
        E: From<ActionExecutionError> + From<NonceError> + From<crate::did::Error<T>>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        A::Target: StorageRef<T>,
        DidOrDidMethodKeySignature<D>:
            AuthorizeSignedAction<WithNonce<T, A>> + Signature<Signer = D>,
        D: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + Deref,
        D::Target: AuthorizeTarget<
                <WithNonce<T, A> as Action>::Target,
                <DidOrDidMethodKeySignature<D> as Signature>::Key,
            > + StorageRef<T, Value = WithNonce<T, S>>
            + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.modify_removable(|action, data| {
            let required_signers = (required_signers)(data.as_ref());

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
        D::Target: AuthorizeTarget<
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
            (Some(required_signers), Some(DidSignatureWithNonce { sig, nonce })) => {
                let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
                let signer = sig.signer().ok_or(ActionExecutionError::InvalidSigner)?;
                let signed_action = action_with_nonce.signed(sig);

                let required_signers = required_signers
                    .exclude(&signer)
                    .map_err(|_| ActionExecutionError::NotEnoughSignatures)?;
                verified_signers.insert(signer);

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
