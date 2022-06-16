use codec::{Decode, Encode};
use core::{fmt::Debug, ops::Deref, ops::DerefMut};
use sp_runtime::DispatchError;

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
    pub data: D,
}

impl<T: frame_system::Config, D> Deref for WithNonce<T, D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: frame_system::Config, D> DerefMut for WithNonce<T, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: frame_system::Config, D> WithNonce<T, D> {
    /// Adds a nonce to the given `data`.
    /// Nonce will be equal to the current block number provided by the system. 
    pub fn new(data: D) -> Self {
        Self {
            nonce: <frame_system::Module<T>>::block_number(),
            data,
        }
    }

    /// Attempts to increase current nonce if provided nonce is equal to current nonce plus 1, otherwise
    /// returns an error.
    pub fn try_inc_nonce(&mut self, nonce: T::BlockNumber) -> Result<&mut Self, DispatchError> {
        if nonce == self.next_nonce() {
            self.nonce = nonce;

            Ok(self)
        } else {
            Err(DispatchError::Other("Incorrect nonce"))
        }
    }

    /// Returns next nonce for the given entity.
    pub fn next_nonce(&self) -> T::BlockNumber {
        self.nonce + 1u8.into()
    }
}
