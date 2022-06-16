use codec::{Decode, Encode};
use core::{fmt::Debug, ops::Deref, ops::DerefMut};
use sp_runtime::DispatchError;

#[derive(Encode, Decode, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "T: Sized, D: serde::Serialize",
        deserialize = "T: Sized, D: serde::Deserialize<'de>"
    ))
)]
pub struct Nonced<T: frame_system::Config, D> {
    pub nonce: T::BlockNumber,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub data: D,
}

impl<T: frame_system::Config, D> Deref for Nonced<T, D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: frame_system::Config, D> DerefMut for Nonced<T, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: frame_system::Config, D> Nonced<T, D> {
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