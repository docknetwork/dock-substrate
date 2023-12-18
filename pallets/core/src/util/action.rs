use core::marker::PhantomData;
use frame_support::ensure;
use sp_runtime::DispatchError;

use crate::{common::Types, util::OptionExt};

use super::{NonceError, WithNonce};

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

    /// Executes an action providing a mutable reference to the option containing a value associated with the target.
    fn execute<T, S, F, R, E>(self, f: F) -> Result<R, E>
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

    /// Executes an action providing a reference to the option containing a value associated with the target.
    fn execute_readonly<T, S, F, R, E>(self, f: F) -> Result<R, E>
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

    /// Executes an action providing a mutable reference to the value associated with the target.
    fn execute_removable<T, S, F, R, E>(self, f: F) -> Result<R, E>
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

    fn signed<S>(self, signature: S) -> SignedActionWithNonce<T, Self, S> {
        SignedActionWithNonce::new(self, signature)
    }
}

pub enum ActionExecutionError {
    NoEntity,
    EmptyPayload,
    ConversionError,
}

impl From<ActionExecutionError> for DispatchError {
    fn from(error: ActionExecutionError) -> Self {
        match error {
            ActionExecutionError::NoEntity => DispatchError::Other("Entity doesn't exist"),
            ActionExecutionError::EmptyPayload => DispatchError::Other("Payload is empty"),
            ActionExecutionError::ConversionError => DispatchError::Other("Conversion failed"),
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

/// Allows mutating a value associated with `Self`.
pub trait StorageRef<T>: Sized {
    type Value;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<Self::Value>) -> Result<R, E>;

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