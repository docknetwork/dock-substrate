//! Generic immutable single-owner storage.

use crate::{
    common::{signatures::ForSigType, Limits, TypesAndLimits},
    did,
    did::{
        AuthorizeAction, Did, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature,
        SignedActionWithNonce,
    },
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
pub struct BlobOwner(pub DidOrDidMethodKey);

impl AuthorizeAction<(), DidKey> for BlobOwner {}
impl AuthorizeAction<(), DidMethodKey> for BlobOwner {}

crate::impl_wrapper!(BlobOwner(DidOrDidMethodKey));

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
pub type BlobId = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, DebugNoBound, EqNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        #[pallet::weight(SubstrateWeight::<T>::new(add_blob, signature))]
        pub fn new(
            origin: OriginFor<T>,
            add_blob: AddBlob<T>,
            signature: DidOrDidMethodKeySignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            SignedActionWithNonce::new(add_blob, signature).execute(Self::new_)
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

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let mut reads_writes = 0;

            Blobs::<T>::translate_values(|(did, blob): (Did, BoundedBytes<T::MaxBlobSize>)| {
                reads_writes += 1;

                Some((BlobOwner(did.into()), blob))
            });

            T::DbWeight::get().reads_writes(reads_writes, reads_writes)
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
