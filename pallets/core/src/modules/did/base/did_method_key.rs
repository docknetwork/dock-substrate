use crate::{
    common::AuthorizeTarget,
    did::*,
    util::{StorageRef, WithNonce},
};
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::{Index, RangeFull};
use frame_support::ensure;

/// The `public_key` in `did:key:<public_key>`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum DidMethodKey {
    /// Public key for Ed25519 is 32 bytes
    Ed25519(Bytes32),
    /// Compressed public key for Secp256k1 is 33 bytes
    Secp256k1(Bytes33),
}

impl From<sp_core::ed25519::Public> for DidMethodKey {
    fn from(key: sp_core::ed25519::Public) -> Self {
        Self::Ed25519(key.0.into())
    }
}

impl<T: Config> StorageRef<T> for DidMethodKey {
    type Value = WithNonce<T, ()>;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<WithNonce<T, ()>>) -> Result<R, E>,
    {
        DidMethodKeys::<T>::try_mutate_exists(self, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<WithNonce<T, ()>>) -> R,
    {
        f(DidMethodKeys::<T>::get(self))
    }
}

impl<Target> AuthorizeTarget<Target, Self> for DidMethodKey {}

impl Index<RangeFull> for DidMethodKey {
    type Output = [u8];

    fn index(&self, _: RangeFull) -> &Self::Output {
        match self {
            Self::Ed25519(bytes) => &bytes[..],
            Self::Secp256k1(bytes) => &bytes[..],
        }
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn new_did_method_key_(did_key: DidMethodKey) -> Result<(), Error<T>> {
        ensure!(
            !DidMethodKeys::<T>::contains_key(did_key),
            Error::<T>::DidMethodKeyExists
        );

        DidMethodKeys::<T>::insert(did_key, WithNonce::new(()));

        crate::deposit_indexed_event!(DidMethodKeyAdded(did_key));
        Ok(())
    }
}
