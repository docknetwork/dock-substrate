use codec::{Decode, Encode, MaxEncodedLen};
use sp_runtime::{traits::CheckedAdd, DispatchError};
use sp_std::{convert::TryInto, fmt::Debug};

use crate::common::Types;

/// Wrapper for any kind of entity with a nonce.
/// Nonces are mostly used for replay protection.
/// Initial nonce will be equal to the current block number provided by the system.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "T: Sized, D: serde::Serialize",
        deserialize = "T: Sized, D: serde::Deserialize<'de>"
    ))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
#[codec(encode_bound(D: Encode))]
pub struct WithNonce<T: Types, D> {
    pub nonce: T::BlockNumber,
    #[cfg(test)]
    pub data: D,
    #[cfg(not(test))]
    data: D,
}

impl<T: Types, D: core::fmt::Debug> core::fmt::Debug for WithNonce<T, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WithNonce")
            .field("nonce", &self.nonce)
            .field("data", &self.data)
            .finish()
    }
}

impl<T: Types, D: MaxEncodedLen> MaxEncodedLen for WithNonce<T, D> {
    fn max_encoded_len() -> usize {
        T::BlockNumber::max_encoded_len().saturating_add(D::max_encoded_len())
    }
}

/// A nonce handling-related error.
#[derive(Clone, Copy, Debug)]
pub enum NonceError {
    /// Provided nonce is incorrect, i.e. doesn't equal to the current plus 1.
    IncorrectNonce,
}

impl From<NonceError> for DispatchError {
    fn from(NonceError::IncorrectNonce: NonceError) -> Self {
        DispatchError::Other("Incorrect nonce")
    }
}

impl<T: Types, D> WithNonce<T, D> {
    /// Adds a nonce to the given `data`.
    /// Nonce will be equal to the current block number provided by the system.
    pub fn new(data: D) -> Self
    where
        T: frame_system::Config<BlockNumber = <T as Types>::BlockNumber>,
    {
        Self::new_with_nonce(data, <frame_system::Pallet<T>>::block_number())
    }

    /// Adds supplied nonce to the given `data`.
    pub fn new_with_nonce(data: D, nonce: T::BlockNumber) -> Self {
        Self { nonce, data }
    }

    /// Returns read-only reference to the underlying data.
    pub fn data(&self) -> &D {
        &self.data
    }

    /// Takes underlying data. If you would like to update an entity, use `try_update` instead.
    pub fn into_data(self) -> D {
        self.data
    }

    /// Returns next nonce for the given entity.
    pub fn next_nonce(&self) -> Option<T::BlockNumber> {
        self.nonce.checked_add(&1u8.into())
    }

    /// Returns `true` if given nonce is the next nonce for the given entity, i.e. is equal to current nonce plus 1.
    pub fn is_next_nonce(&self, nonce: T::BlockNumber) -> bool {
        Some(nonce) == self.next_nonce()
    }

    /// Returns mutable reference to the underlying data if provided nonce is equal to current nonce plus 1,
    /// otherwise returns an error.
    pub fn try_update(&mut self, nonce: T::BlockNumber) -> Result<&mut D, NonceError> {
        if self.is_next_nonce(nonce) {
            self.nonce = nonce;

            Ok(&mut self.data)
        } else {
            Err(NonceError::IncorrectNonce)
        }
    }

    /// If supplied value is `Some(_)`, attempts to increase current nonce - succeeds if provided nonce is equal to
    /// current nonce plus 1, otherwise returns an error. If value is `None`, `None` will be returned.
    pub fn try_update_opt_with<S, F, E, R>(
        this_opt: &mut Option<S>,
        nonce: T::BlockNumber,
        f: F,
    ) -> Option<Result<R, E>>
    where
        F: FnOnce(&mut Option<D>) -> Result<R, E>,
        E: From<NonceError> + From<S::Error>,
        S: TryInto<Self>,
        Self: Into<S>,
    {
        let this = match this_opt
            .take()?
            .try_into()
            .map_err(E::from)
            .and_then(|mut this| {
                this.try_update(nonce)
                    .map(drop)
                    .map(|()| this)
                    .map_err(E::from)
            }) {
            err @ Err(_) => return Some(err.map(|_| unreachable!())),
            Ok(this) => this,
        };

        let Self { data, nonce } = this;
        let mut data_opt = Some(data);
        let res = (f)(&mut data_opt).map_err(Into::into);
        *this_opt = data_opt.map(|data| Self { data, nonce }.into());

        Some(res)
    }

    /// If supplied value is `Some(_)`, will update given entity without increasing nonce.
    pub fn try_update_opt_without_increasing_nonce_with<S, F, E, R>(
        this_opt: &mut Option<S>,
        f: F,
    ) -> Option<Result<R, E>>
    where
        F: FnOnce(&mut Option<D>) -> Result<R, E>,
        E: From<NonceError> + From<S::Error>,
        S: TryInto<Self>,
        Self: Into<S>,
    {
        let this = match this_opt.take()?.try_into().map_err(E::from) {
            err @ Err(_) => return Some(err.map(|_| unreachable!())),
            Ok(this) => this,
        };

        let Self { data, nonce } = this;
        let mut data_opt = Some(data);
        let res = (f)(&mut data_opt).map_err(Into::into);
        *this_opt = data_opt.map(|data| Self { data, nonce }.into());

        Some(res)
    }
}
