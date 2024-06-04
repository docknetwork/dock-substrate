//! Generic immutable single-owner storage.

#[cfg(feature = "serde")]
use crate::util::serde_hex;
use crate::{
    common::{signatures::ForSigType, AuthorizeTarget, Limits, Types},
    did::{self, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature},
    util::{ActionWithNonce, Associated, BoundedBytes, Bytes, StorageRef},
};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_std::fmt::Debug;

use frame_support::{
    dispatch::DispatchResult, ensure, weights::Weight, CloneNoBound, DebugNoBound, EqNoBound,
    PartialEqNoBound,
};
use sp_std::prelude::*;
use weights::*;

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

/// Owner of a Blob.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct BlobOwner(pub DidOrDidMethodKey);

impl AuthorizeTarget<BlobId, DidKey> for BlobOwner {}
impl AuthorizeTarget<BlobId, DidMethodKey> for BlobOwner {}

crate::impl_wrapper!(BlobOwner(DidOrDidMethodKey));

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct BlobId(#[cfg_attr(feature = "serde", serde(with = "serde_hex"))] pub [u8; ID_BYTE_SIZE]);

crate::impl_wrapper!(BlobId([u8; 32]));
crate::hex_debug!(BlobId);

impl<T: Limits> Associated<T> for BlobId {
    type Value = StoredBlob<T>;
}

impl<T: Config> StorageRef<T> for BlobId {
    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<Self::Value>) -> R,
    {
        f(Blobs::<T>::get(self))
    }

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<Self::Value>) -> Result<R, E>,
    {
        Blobs::<T>::try_mutate_exists(self, f)
    }
}

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, DebugNoBound, EqNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Blob {
    pub id: BlobId,
    pub blob: Bytes,
}

pub type StoredBlob<T> = (BlobOwner, BoundedBytes<<T as Limits>::MaxBlobSize>);

#[derive(Encode, Decode, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddBlob<T: Types> {
    pub blob: Blob,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    AddBlob for BlobId: with 1 as len, blob.id as target
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {}

    /// Error for the blob module.
    #[pallet::error]
    pub enum Error<T> {
        /// There is already a blob with same id
        BlobAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        TooBig,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn blob)]
    pub type Blobs<T: Config> = StorageMap<_, Blake2_128Concat, BlobId, StoredBlob<T>>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new immutable blob.
        #[pallet::weight(SubstrateWeight::<T>::new(add_blob, signature))]
        pub fn new(
            origin: OriginFor<T>,
            add_blob: AddBlob<T>,
            signature: DidOrDidMethodKeySignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            add_blob
                .signed(signature)
                .execute_removable(Self::new_)
                .map_err(Into::into)
        }
    }

    impl<T: Config> Pallet<T> {
        fn new_(
            AddBlob { blob, .. }: AddBlob<T>,
            blob_opt: &mut Option<StoredBlob<T>>,
            signer: BlobOwner,
        ) -> DispatchResult {
            let blob_bytes = blob.blob.try_into().map_err(|_| Error::<T>::TooBig)?;

            // check
            ensure!(
                blob_opt.replace((signer, blob_bytes)).is_none(),
                Error::<T>::BlobAlreadyExists
            );

            Ok(())
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        AddBlob { blob, .. }: &AddBlob<T>,
        sig: &DidOrDidMethodKeySignature<BlobOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            || Self::new_sr25519(blob.blob.len() as u32),
            || Self::new_ed25519(blob.blob.len() as u32),
            || Self::new_secp256k1(blob.blob.len() as u32),
        )
    }
}
