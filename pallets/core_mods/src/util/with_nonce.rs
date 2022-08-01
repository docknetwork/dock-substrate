use codec::{Decode, Encode};
use core::fmt::Debug;
use sp_runtime::DispatchError;
use sp_std::convert::TryInto;

/// Wrapper for any kind of entity with a nonce.
/// Nonces are mostly used for replay protection.
/// Initial nonce will be equal to the current block number provided by the system.
#[derive(Encode, Decode, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "T: Sized, D: serde::Serialize",
        deserialize = "T: Sized, D: serde::Deserialize<'de>"
    ))
)]
pub struct WithNonce<T: frame_system::Config, D> {
    pub nonce: T::BlockNumber,
    #[cfg_attr(feature = "serde", serde(flatten))]
    #[cfg(test)]
    pub data: D,
    #[cfg_attr(feature = "serde", serde(flatten))]
    #[cfg(not(test))]
    data: D,
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

impl<T: frame_system::Config, D> WithNonce<T, D> {
    /// Adds a nonce to the given `data`.
    /// Nonce will be equal to the current block number provided by the system.
    pub fn new(data: D) -> Self {
        Self::new_with_nonce(data, <frame_system::Module<T>>::block_number())
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
    pub fn next_nonce(&self) -> T::BlockNumber {
        self.nonce + 1u8.into()
    }

    /// Returns `true` if given nonce is the next nonce for the given entity, i.e. is equal to current nonce plus 1.
    pub fn is_next_nonce(&self, nonce: T::BlockNumber) -> bool {
        nonce == self.next_nonce()
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
        E: From<NonceError>,
        S: TryInto<Self>,
        Self: Into<S>,
    {
        let mut this = this_opt.take()?.try_into().ok()?;
        if let err @ Err(_) = this.try_update(nonce) {
            return Some(err.map(|_| unreachable!()).map_err(Into::into));
        }

        let mut this_data_opt = Some(this);
        let res = WithNonce::try_update_opt_without_increasing_nonce_with::<Self, _, _, _>(
            &mut this_data_opt,
            f,
        );
        *this_opt = this_data_opt.map(Into::into);

        res
    }

    /// If supplied value is `Some(_)`, will update given entity without increasing nonce.
    pub fn try_update_opt_without_increasing_nonce_with<S, F, E, R>(
        this_opt: &mut Option<S>,
        f: F,
    ) -> Option<Result<R, E>>
    where
        F: FnOnce(&mut Option<D>) -> Result<R, E>,
        E: From<NonceError>,
        S: TryInto<Self>,
        Self: Into<S>,
    {
        let this = this_opt.take()?.try_into().ok()?;

        let Self { data, nonce } = this;
        let mut data_opt = Some(data);
        let res = (f)(&mut data_opt).map_err(Into::into);
        *this_opt = data_opt.map(|data| Self { data, nonce }.into());

        Some(res)
    }
}
