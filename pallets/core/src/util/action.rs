use core::{iter::FusedIterator, marker::PhantomData};
use frame_support::ensure;
use sp_runtime::DispatchError;

use crate::{
    common::DidSignatureWithNonce,
    did::DidOrDidMethodKey,
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

    /// Calls supplied function providing an action along with a mutable reference to the value associated with the target.
    fn modify<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut S) -> Result<R, E>,
        <Self::Target as StorageRef<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as StorageRef<T>>::Value>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|data_opt| {
            ensure!(data_opt.is_some(), ActionExecutionError::NoEntity);

            data_opt.update_with(|opt| {
                ensure!(opt.is_some(), ActionExecutionError::ConversionError);

                f(self, opt.as_mut().unwrap())
            })
        })
    }

    /// Calls supplied function providing an action along with a value associated with the target.
    fn view<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, S) -> Result<R, E>,
        <Self::Target as StorageRef<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as StorageRef<T>>::Value>,
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

    /// Calls supplied function providing an action along with a mutable reference to the option containing a value associated with the target.
    fn modify_removable<T, S, F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        <Self::Target as StorageRef<T>>::Value: TryInto<S>,
        S: Into<<Self::Target as StorageRef<T>>::Value>,
        E: From<ActionExecutionError> + From<NonceError>,
        Self::Target: StorageRef<T>,
    {
        ensure!(!self.is_empty(), ActionExecutionError::EmptyPayload);

        self.target().try_mutate_associated(|data_opt| {
            ensure!(data_opt.is_some(), ActionExecutionError::NoEntity);

            data_opt.update_with(|opt| {
                ensure!(opt.is_some(), ActionExecutionError::ConversionError);

                f(self, opt)
            })
        })
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
        <Self::Target as StorageRef<T>>::Value: TryInto<WithNonce<T, S>>,
        WithNonce<T, S>: Into<<Self::Target as StorageRef<T>>::Value>,
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
        WithNonce<T, S>: TryFrom<<Self::Target as StorageRef<T>>::Value>
            + Into<<Self::Target as StorageRef<T>>::Value>,
        Self::Target: StorageRef<T>,
        <Self::Target as StorageRef<T>>::Value: TryInto<WithNonce<T, S>>,
        WithNonce<T, S>: Into<<Self::Target as StorageRef<T>>::Value>,
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
        let signer = signature.signer().ok_or(InvalidSigner)?;
        let wrapped = ActionWithNonceWrapper::new(self.nonce(), signer, self);

        Ok(wrapped.signed(signature))
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

impl From<ActionExecutionError> for DispatchError {
    fn from(error: ActionExecutionError) -> Self {
        match error {
            ActionExecutionError::NoEntity => DispatchError::Other("Entity doesn't exist"),
            ActionExecutionError::EmptyPayload => DispatchError::Other("Payload is empty"),
            ActionExecutionError::ConversionError => DispatchError::Other("Conversion failed"),
            ActionExecutionError::InvalidSigner => DispatchError::Other("Invalid signer"),
            ActionExecutionError::NotEnoughSignatures => {
                DispatchError::Other("Not enough signatures")
            }
            ActionExecutionError::TooManySignatures => DispatchError::Other("Too many signatures"),
        }
    }
}

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

/// Allows to view and mutate a value associated with `Self`.
pub trait StorageRef<T>: Sized {
    /// Some value type associated with `Self`.
    type Value;

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

impl<T> StorageRef<T> for () {
    type Value = ();

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
