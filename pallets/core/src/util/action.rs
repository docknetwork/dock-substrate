use codec::FullCodec;
use frame_support::{ensure, StorageMap};
use sp_runtime::DispatchError;

use crate::common::Types;

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
}

/// Describes an action fpwith nonce which can be performed on some `Target`
pub trait ActionWithNonce<T: Types>: Action {
    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;

    fn execute<F, S, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError>,
        WithNonce<T, S>: TryFrom<<Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Value>
            + Into<<Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Value>,
        Self::Target: StorageMapRef<T, WithNonce<T, S>>,
    {
        ensure!(!self.is_empty(), UpdateWithNonceError::EmptyPayload);

        let key: <Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Key = self.target().into();

        <Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Storage::try_mutate_exists(
            key,
            |details_opt| {
                WithNonce::try_update_opt_with(details_opt, self.nonce(), |data_opt| {
                    f(self, data_opt)
                })
                .ok_or(UpdateWithNonceError::EntityDoesntExist)?
            },
        )
    }

    fn execute_without_increasing_nonce<F, R, S, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(Self, &mut Option<S>) -> Result<R, E>,
        E: From<UpdateWithNonceError>,
        WithNonce<T, S>: TryFrom<<Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Value>
            + Into<<Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Value>,
        Self::Target: StorageMapRef<T, WithNonce<T, S>>,
    {
        ensure!(!self.is_empty(), UpdateWithNonceError::EmptyPayload);

        let key: <Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Key = self.target().into();

        <Self::Target as StorageMapRef<T, WithNonce<T, S>>>::Storage::try_mutate_exists(
            key,
            |details_opt| {
                WithNonce::try_update_opt_without_increasing_nonce_with(details_opt, |data_opt| {
                    f(self, data_opt)
                })
                .ok_or(UpdateWithNonceError::EntityDoesntExist)?
            },
        )
    }
}

pub enum UpdateWithNonceError {
    EntityDoesntExist,
    EmptyPayload,
}

impl From<UpdateWithNonceError> for DispatchError {
    fn from(error: UpdateWithNonceError) -> Self {
        match error {
            UpdateWithNonceError::EntityDoesntExist => DispatchError::Other("Entity doesn't exist"),
            UpdateWithNonceError::EmptyPayload => DispatchError::Other("Payload is empty"),
        }
    }
}

pub trait StorageMapRef<T: Types, V>: Sized {
    type Key: From<Self> + FullCodec;
    type Value: From<V> + TryInto<V> + FullCodec;
    type Storage: StorageMap<Self::Key, Self::Value>;
}
