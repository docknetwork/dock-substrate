use core::iter::FusedIterator;
use frame_support::ensure;
use sp_runtime::DispatchError;

use crate::{
    common::{signed_action::*, SignatureWithNonce},
    util::{OptionExt, Signature, Types},
};

use super::{ActionWithNonceWrapper, NonceError, WithNonce};

/// Describes an action which can be performed on some `Target`.
pub trait Action: Sized {
    /// Action target.
    type Target;

    /// Returns underlying action target.
    fn target(&self) -> Self::Target;

    /// Returns action unit length.
    fn len(&self) -> u32;

    /// Returns `true` if the action unit count is equal to zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Calls supplied function accepting an action along with a mutable reference
    /// to the value associated with the target.
    fn modify<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut S) -> Result<R, E>,
        <Self::Target as Associated<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as Associated<T>>::Value>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|data_opt| {
            ensure!(data_opt.is_some(), ActionExecutionError::NoEntity);

            data_opt.update_with(|opt| {
                let Some(data) = opt else {
                    Err(ActionExecutionError::ConversionError)?
                };

                f(self, data)
            })
        })
    }

    /// Calls supplied function accepting an action along with a value associated with the target.
    fn view<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, S) -> Result<R, E>,
        <Self::Target as Associated<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as Associated<T>>::Value>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().view_associated(|data_opt| {
            let data = data_opt
                .ok_or(ActionExecutionError::NoEntity)?
                .try_into()
                .map_err(|_| ActionExecutionError::ConversionError)?;

            f(self, data)
        })
    }

    /// Calls supplied function accepting an action along with a mutable reference
    /// to the option possibly containing a value associated with the target.
    /// Modifying supplied `Option<_>` to `None` will lead to the value removal.
    fn modify_removable<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        <Self::Target as Associated<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as Associated<T>>::Value>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|data_opt| {
            let exists = data_opt.is_some();

            data_opt.update_with(|opt| {
                ensure!(
                    !exists || opt.is_some(),
                    ActionExecutionError::ConversionError
                );

                f(self, opt)
            })
        })
    }

    /// Combines underlying action with the provided signatures.
    fn multi_signed<T, S, SI>(self, signatures: SI) -> MultiSignedAction<T, Self, S, SI::IntoIter>
    where
        T: Types,
        S: Signature,
        SI: IntoIterator,
        SI::IntoIter: FusedIterator<Item = SignatureWithNonce<T::BlockNumber, S>>,
    {
        MultiSignedAction::new(self, signatures)
    }
}

/// Describes an action with nonce which can be performed on some `Target`
pub trait ActionWithNonce<T: Types>: Action {
    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;

    /// Executes an action providing a mutable reference to the option containing a value associated with the target.
    /// In case of a successful result, the nonce will be increased.
    fn execute_and_increase_nonce<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
        <Self::Target as Associated<T>>::Value: TryInto<WithNonce<T, S>>,
        WithNonce<T, S>: Into<<Self::Target as Associated<T>>::Value>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|details_opt| {
            ensure!(details_opt.is_some(), ActionExecutionError::NoEntity);

            details_opt
                .update_with(|opt| {
                    if opt.is_none() {
                        return Some(Err(ActionExecutionError::ConversionError.into()));
                    }

                    WithNonce::try_update_opt_with(opt, self.nonce(), |data_opt| f(self, data_opt))
                })
                .ok_or(ActionExecutionError::ConversionError)?
        })
    }

    /// Executes an action providing a mutable reference to the value associated with the target.
    /// Even in case of a successful result, the nonce won't be increased.
    fn execute_without_increasing_nonce<F, R, S, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        E: From<ActionExecutionError>,
        WithNonce<T, S>: TryFrom<<Self::Target as Associated<T>>::Value>
            + Into<<Self::Target as Associated<T>>::Value>,
        Self::Target: StorageRef<T>,
        <Self::Target as Associated<T>>::Value: TryInto<WithNonce<T, S>>,
        WithNonce<T, S>: Into<<Self::Target as Associated<T>>::Value>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|details_opt| {
            ensure!(details_opt.is_some(), ActionExecutionError::NoEntity);

            details_opt
                .update_with(|opt| {
                    if opt.is_none() {
                        return Some(Err(ActionExecutionError::ConversionError.into()));
                    }

                    WithNonce::try_update_opt_without_increasing_nonce_with(opt, |data_opt| {
                        f(self, data_opt)
                    })
                })
                .ok_or(ActionExecutionError::ConversionError)?
        })
    }

    /// Combines underlying action with the provided signature.
    fn signed<S>(self, signature: S) -> SignedActionWithNonce<T, Self, S> {
        SignedActionWithNonce::new(self, signature)
    }

    /// Wraps underlying action into an action targeting signer then combines result with the provided signature.
    #[allow(clippy::type_complexity)]
    fn signed_with_combined_target<S, F, Ta>(
        self,
        signature: S,
        build_target: F,
    ) -> Result<SignedActionWithNonce<T, ActionWithNonceWrapper<T, Self, Ta>, S>, InvalidSigner>
    where
        S: Signature,
        F: FnOnce(Self::Target, S::Signer) -> Ta,
        Ta: Clone,
    {
        let signer = signature.signer().ok_or(InvalidSigner)?;
        let target = build_target(self.target(), signer);
        let wrapped = ActionWithNonceWrapper::new(self.nonce(), target, self);

        Ok(wrapped.signed(signature))
    }

    /// Wraps underlying action into an action targeting signer then combines result with the provided signature.
    #[allow(clippy::type_complexity)]
    fn signed_with_signer_target<S>(
        self,
        signature: S,
    ) -> Result<
        SignedActionWithNonce<T, ActionWithNonceWrapper<T, Self, S::Signer>, S>,
        InvalidSigner,
    >
    where
        S: Signature,
    {
        self.signed_with_combined_target(signature, |_, signer| signer)
    }
}

pub struct InvalidSigner;

impl From<InvalidSigner> for DispatchError {
    fn from(InvalidSigner: InvalidSigner) -> Self {
        DispatchError::Other("Invalid signer")
    }
}

pub enum ActionExecutionError {
    NoEntity,
    EmptyPayload,
    InvalidSigner,
    NotEnoughSignatures,
    TooManySignatures,
    ConversionError,
}

#[cfg(test)]
impl From<ActionExecutionError> for DispatchError {
    fn from(error: ActionExecutionError) -> Self {
        use ActionExecutionError::*;

        match error {
            NoEntity => DispatchError::Other("NoEntity"),
            EmptyPayload => DispatchError::Other("EmptyPayload"),
            InvalidSigner => DispatchError::Other("InvalidSigner"),
            NotEnoughSignatures => DispatchError::Other("NotEnoughSignatures"),
            TooManySignatures => DispatchError::Other("TooManySignatures"),
            ConversionError => DispatchError::Other("ConversionError"),
        }
    }
}

/// Marker trait claiming that `Self` has an associated `Value`.
pub trait Associated<T>: Sized {
    /// Some type associated with `Self`.
    type Value;
}

/// Allows to view and mutate a value associated with `Self`.
pub trait StorageRef<T>: Associated<T> {
    /// Attempts to mutate a value associated with `Self`.
    /// If the value under the option is taken, the associated value will be removed.
    /// All updates will be applied only in case of a successful result.
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<Self::Value>) -> Result<R, E>;

    /// Calls provided function with an associated value as an argument.
    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<Self::Value>) -> R;
}

impl<T> Associated<T> for () {
    type Value = ();
}

impl<T> StorageRef<T> for () {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<()>) -> Result<R, E>,
    {
        f(&mut Some(()))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<()>) -> R,
    {
        f(Some(()))
    }
}
