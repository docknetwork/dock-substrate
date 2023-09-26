//! Generic immutable single-owner storage.

use crate::{
    common::{Limits, SigValue, TypesAndLimits},
    did,
    did::{Did, DidSignature},
    util::BoundedBytes,
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
pub struct BlobOwner(pub Did);

crate::impl_wrapper!(BlobOwner(Did), for rand use Did(rand::random()), with tests as blob_owner_tests);

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
pub type BlobId = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, DebugNoBound, EqNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct Blob<T: Limits> {
    pub id: BlobId,
    pub blob: BoundedBytes<T::MaxBlobSize>,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddBlob<T: TypesAndLimits> {
    pub blob: Blob<T>,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    AddBlob for (): with 1 as len, () as target
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
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn blob)]
    pub type Blobs<T: Config> =
        StorageMap<_, Blake2_128Concat, BlobId, (BlobOwner, BoundedBytes<T::MaxBlobSize>)>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new immutable blob.
        #[pallet::weight(SubstrateWeight::<T>::new(blob, signature))]
        pub fn new(
            origin: OriginFor<T>,
            blob: AddBlob<T>,
            signature: DidSignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::new_, blob, signature)
        }
    }

    impl<T: Config> Pallet<T> {
        fn new_(AddBlob { blob, .. }: AddBlob<T>, signer: BlobOwner) -> DispatchResult {
            // check
            ensure!(
                !Blobs::<T>::contains_key(blob.id),
                Error::<T>::BlobAlreadyExists
            );

            // execute
            Blobs::<T>::insert(blob.id, (signer, blob.blob));

            Ok(())
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        AddBlob { blob, .. }: &AddBlob<T>,
        DidSignature { sig, .. }: &DidSignature<BlobOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::new_sr25519,
            SigValue::Ed25519(_) => Self::new_ed25519,
            SigValue::Secp256k1(_) => Self::new_secp256k1,
        }(blob.blob.len() as u32))
    }
}
