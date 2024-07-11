use crate::{
    common::{Authorization, AuthorizeSignedAction, AuthorizeTarget, ToStateChange},
    did::{self, *},
    util::{
        action::*, signature::Signature, with_nonce::*, ActionWithNonceWrapper, InclusionRule,
        Types,
    },
};
use alloc::collections::BTreeSet;
use core::{convert::Infallible, iter::FusedIterator, marker::PhantomData, ops::Deref};
use frame_support::dispatch::DispatchErrorWithPostInfo;
use sp_runtime::DispatchError;

use super::{PolicyValidationError, SignatureWithNonce};

/// `Value` type associated with the `Action`'s target.
type TargetValue<T, A> = <<A as Action>::Target as Associated<T>>::Value;

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
    Sig: AuthorizeSignedAction<T, A>,
    A::Target: Associated<T>,
    Sig::Signer: AuthorizeTarget<T, A::Target, Sig::Key> + Deref,
    <Sig::Signer as Deref>::Target: AuthorizeTarget<T, A::Target, Sig::Key>,
{
    /// Verifies signer's signature and nonce, then executes given action without providing target data.
    /// In case of a successful result, increases the signer's nonce.
    pub fn execute_without_target_data<F, S, R, E>(self, f: F) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, Sig::Signer) -> Result<R, E>,
        E: Into<IntermediateError<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let Self {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action, None)?
            .ok_or(Error::<T>::InvalidSignature)?;

        ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
            .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
                f(action, signer).map_err(Into::into)
            })
    }

    /// Verifies signer's signature and nonce, then executes given action providing a
    /// value associated with the target.
    /// In case of a successful result, increases the signer's nonce.
    pub fn execute_view<F, S, R, E>(self, f: F) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, TargetValue<T, A>, Sig::Signer) -> Result<R, E>,
        E: Into<IntermediateError<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let Self {
            action, signature, ..
        } = self;

        action.view(|action, target_data| {
            let Authorization { signer, .. } = signature
                .authorizes_signed_action(&action, Some(&target_data))?
                .ok_or(Error::<T>::InvalidSignature)?;

            ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
                .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
                    f(action, target_data, signer).map_err(Into::into)
                })
        })
    }

    /// Verifies signer's signature and nonce, then executes given action providing a mutable reference to the
    /// value associated with the target.
    /// In case of a successful result, commits all storage changes and increases the signer's nonce.
    pub fn execute<F, S, R, E>(self, f: F) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, &mut TargetValue<T, A>, Sig::Signer) -> Result<R, E>,
        E: Into<IntermediateError<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        self.execute_removable(|action, data, actor| {
            let data_ref = data.as_mut().ok_or(ActionExecutionError::NoEntity)?;

            f(action, data_ref, actor).map_err(Into::into)
        })
    }

    /// Verifies signer's signature and nonce, then executes given action providing a mutable reference to the
    /// option containing a value associated with the target.
    /// In case of a successful result, commits all storage changes and increases the signer's nonce.
    pub fn execute_removable<F, S, R, E>(self, f: F) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, &mut Option<TargetValue<T, A>>, Sig::Signer) -> Result<R, E>,
        E: Into<IntermediateError<T>>,
        A::Target: StorageRef<T>,
        <Sig::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, S>> + Clone,
    {
        let Self {
            action, signature, ..
        } = self;

        action
            .modify_removable(|action, target_data| {
                let Authorization { signer, .. } = signature
                    .authorizes_signed_action(&action, target_data.as_ref())?
                    .ok_or(Error::<T>::InvalidSignature)?;

                ActionWithNonceWrapper::<T, _, _>::new(action.nonce(), (*signer).clone(), action)
                    .execute_and_increase_nonce(|ActionWithNonceWrapper { action, .. }, _| {
                        f(action, target_data, signer).map_err(Into::into)
                    })
            })
            .map_err(Into::into)
    }
}

/// An action signed by multiple signers with their corresponding nonces.
pub struct MultiSignedAction<T: Types, A, S, SI>
where
    A: Action,
    S: Signature,
{
    pub action: A,
    pub signatures: SI,
    _marker: PhantomData<(T, S)>,
}

impl<T: Types, A, S, SI> MultiSignedAction<T, A, S, SI>
where
    A: Action,
    S: Signature,
    SI: FusedIterator<Item = SignatureWithNonce<T::BlockNumber, S>>,
{
    pub fn new<ISI>(action: A, signatures: ISI) -> Self
    where
        ISI: IntoIterator<IntoIter = SI>,
    {
        Self {
            action,
            signatures: signatures.into_iter(),
            _marker: PhantomData,
        }
    }
}

impl<T: Config, A, S, SI> MultiSignedAction<T, A, S, SI>
where
    A: Action,
    A::Target: StorageRef<T>,
    WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
    <WithNonce<T, A> as Action>::Target: StorageRef<T>,
    S: Signature + AuthorizeSignedAction<T, WithNonce<T, A>>,
    S::Signer: AuthorizeTarget<T, <WithNonce<T, A> as Action>::Target, S::Key> + Ord + Deref,
    <S::Signer as Deref>::Target: AuthorizeTarget<T, <WithNonce<T, A> as Action>::Target, S::Key>,
    SI: FusedIterator<Item = SignatureWithNonce<T::BlockNumber, S>>,
{
    /// Verifies signature and nonce for all required signers, then executes given action providing a mutable reference to the
    /// value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers.
    pub fn execute<F, R, E, V, RS>(
        self,
        f: F,
        get_required_signers: RS,
    ) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, &mut TargetValue<T, A>, BTreeSet<S::Signer>) -> Result<R, E>,
        RS: FnOnce(&TargetValue<T, A>) -> Option<InclusionRule<S::Signer>>,
        E: Into<IntermediateError<T>>,
        <S::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, V>> + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.modify(|action, data| {
            Self::new(action, signatures).execute_inner(
                f,
                data,
                BTreeSet::new(),
                (get_required_signers)(&data),
            )
        })
    }

    /// Verifies signature and nonce for all required signers, then executes given action providing a
    /// value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers
    pub fn execute_view<F, R, E, V, RS>(
        self,
        f: F,
        get_required_signers: RS,
    ) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, TargetValue<T, A>, BTreeSet<S::Signer>) -> Result<R, E>,
        RS: FnOnce(&TargetValue<T, A>) -> Option<InclusionRule<S::Signer>>,
        E: Into<IntermediateError<T>>,
        <S::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, V>> + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.view(|action, data| {
            let required_signers = (get_required_signers)(&data);

            Self::new(action, signatures).execute_inner(f, data, BTreeSet::new(), required_signers)
        })
    }

    /// Verifies signature and nonce for all required signers, then executes given action providing  a mutable reference to the
    /// option containing value associated with the target along with the set of actors that provided signatures.
    /// In case of a successful result, commits all storage changes and increases nonces for all signers.
    pub fn execute_removable<F, R, E, V, RS>(
        self,
        f: F,
        get_required_signers: RS,
    ) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, &mut Option<TargetValue<T, A>>, BTreeSet<S::Signer>) -> Result<R, E>,
        RS: FnOnce(Option<&TargetValue<T, A>>) -> Option<InclusionRule<S::Signer>>,
        E: Into<IntermediateError<T>>,
        <S::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, V>> + Clone,
    {
        let Self {
            action, signatures, ..
        } = self;

        action.modify_removable(|action, data| {
            let required_signers = (get_required_signers)(data.as_ref());

            Self::new(action, signatures).execute_inner(f, data, BTreeSet::new(), required_signers)
        })
    }

    fn execute_inner<F, D, R, E, V>(
        self,
        f: F,
        data: D,
        mut verified_signers: BTreeSet<S::Signer>,
        required_signers: Option<InclusionRule<S::Signer>>,
    ) -> Result<R, IntermediateError<T>>
    where
        F: FnOnce(A, D, BTreeSet<S::Signer>) -> Result<R, E>,
        E: Into<IntermediateError<T>>,
        <S::Signer as Deref>::Target: StorageRef<T, Value = WithNonce<T, V>> + Clone,
    {
        let Self {
            action,
            mut signatures,
            ..
        } = self;

        match (required_signers, signatures.next()) {
            (None, None) => f(action, data, verified_signers).map_err(Into::into),
            (None, Some(_)) => Err(ActionExecutionError::TooManySignatures.into()),
            (Some(_), None) => Err(ActionExecutionError::NotEnoughSignatures.into()),
            (Some(required_signers), Some(SignatureWithNonce { sig, nonce })) => {
                let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
                let signed_action = action_with_nonce.signed(sig);

                signed_action.execute_without_target_data(|action, signer| {
                    let required_signers = required_signers
                        .exclude(&signer)
                        .map_err(|_| ActionExecutionError::NotEnoughSignatures)?;
                    verified_signers.insert(signer);

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

/// Either `DispatchError` or `DispatchErrorWithPostInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntermediateError<T: Config> {
    Dispatch(DispatchError),
    DispatchWithPostInfo(DispatchErrorWithPostInfo),
    __Marker(PhantomData<Error<T>>, Infallible),
}

impl<T: Config> IntermediateError<T> {
    pub fn dispatch<E: Into<DispatchError>>(error: E) -> Self {
        Self::Dispatch(error.into())
    }

    pub fn did<E: Into<did::Error<T>>>(error: E) -> Self {
        Self::dispatch(error.into())
    }

    pub fn dispatch_with_post_info<E: Into<DispatchErrorWithPostInfo>>(error: E) -> Self {
        Self::DispatchWithPostInfo(error.into())
    }

    pub fn into_dispatch_with_post_info(self) -> DispatchErrorWithPostInfo {
        match self {
            Self::Dispatch(err) => err.into(),
            Self::DispatchWithPostInfo(err) => err,
            Self::__Marker(_, _) => unreachable!(),
        }
    }
}

impl<T: Config> From<Error<T>> for IntermediateError<T> {
    fn from(err: Error<T>) -> Self {
        Self::did(err)
    }
}

impl<T: Config> From<DispatchError> for IntermediateError<T> {
    fn from(dispatch_err: DispatchError) -> Self {
        Self::dispatch(dispatch_err)
    }
}

impl<T: Config> From<DispatchErrorWithPostInfo> for IntermediateError<T> {
    fn from(dispatch_with_post_info_err: DispatchErrorWithPostInfo) -> Self {
        Self::dispatch_with_post_info(dispatch_with_post_info_err)
    }
}

impl<T: Config> From<ActionExecutionError> for IntermediateError<T> {
    fn from(action_err: ActionExecutionError) -> Self {
        Self::did(action_err)
    }
}

impl<T: Config> From<PolicyValidationError> for IntermediateError<T> {
    fn from(policy_err: PolicyValidationError) -> Self {
        Self::did(policy_err)
    }
}

impl<T: Config> From<NonceError> for IntermediateError<T> {
    fn from(nonce_err: NonceError) -> Self {
        Self::did(nonce_err)
    }
}

impl<T: Config> From<IntermediateError<T>> for DispatchError {
    fn from(error: IntermediateError<T>) -> Self {
        match error {
            IntermediateError::Dispatch(err) => err,
            IntermediateError::DispatchWithPostInfo(err) => err.error,
            IntermediateError::__Marker(_, _) => unreachable!(),
        }
    }
}
