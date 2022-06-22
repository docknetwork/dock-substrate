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

    /// Attempts to increase current nonce if provided nonce is equal to current nonce plus 1, otherwise
    /// returns an error.
    pub fn try_inc_nonce(&mut self, nonce: T::BlockNumber) -> Result<&mut D, DispatchError> {
        if nonce == self.next_nonce() {
            self.nonce = nonce;

            Ok(&mut self.data)
        } else {
            Err(DispatchError::Other("Incorrect nonce"))
        }
    }

    /// If supplied value is `Some(_)`, attempts to increase current nonce if provided nonce is equal to
    /// current nonce plus 1, otherwise returns an error.
    /// If value is `None`, `None` will be returned.
    ///
    pub fn try_inc_opt_nonce_with<S, F, E, R>(
        this_opt: &mut Option<S>,
        nonce: T::BlockNumber,
        f: F,
    ) -> Option<Result<R, DispatchError>>
    where
        F: FnOnce(&mut Option<D>) -> Result<R, E>,
        E: Into<DispatchError>,
        S: From<Self> + TryInto<Self>,
    {
        let mut this = this_opt.take()?.try_into().ok()?;

        if let err @ Err(_) = this.try_inc_nonce(nonce) {
            return Some(err.map(|_| unreachable!()));
        }

        let Self { data, nonce } = this;
        let mut data_opt = Some(data);
        let res = (f)(&mut data_opt).map_err(Into::into);
        *this_opt = data_opt.map(|data| Self { data, nonce }.into());

        Some(res)
    }

    /// Returns next nonce for the given entity.
    pub fn next_nonce(&self) -> T::BlockNumber {
        self.nonce + 1u8.into()
    }
}
