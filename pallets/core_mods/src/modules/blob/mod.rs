//! Generic immutable single-owner storage.

use crate as dock;
use crate::{
    did,
    did::{Did, DidSignature},
    keys_and_sigs::SigValue,
    util::WrappedBytes,
};
use codec::{Decode, Encode};
use core::fmt::Debug;

use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_std::prelude::*;
use weights::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

/// Owner of a Blob.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
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
#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Blob {
    pub id: BlobId,
    pub blob: WrappedBytes,
}

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AddBlob<T: frame_system::Config> {
    pub blob: Blob,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    AddBlob for (): with 1 as len, () as target
}

pub trait Config: system::Config + did::Config {
    /// Blobs larger than this will not be accepted.
    type MaxBlobSize: Get<u32>;
    /// The cost charged by the network to store a single byte in chain-state for the life of the
    /// chain.
    type StorageWeight: Get<Weight>;
}

decl_error! {
    /// Error for the blob module.
    pub enum BlobError for Module<T: Config> where T: Debug {
        /// The blob is greater than `MaxBlobSize`
        BlobTooBig,
        /// There is already a blob with same id
        BlobAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Blob where T: Debug {
        Blobs get(fn get_blob): map hasher(blake2_128_concat)
            dock::blob::BlobId => Option<(BlobOwner, WrappedBytes)>;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        const MaxBlobSize: u32 = T::MaxBlobSize::get();

        const StorageWeight: Weight = T::StorageWeight::get();

        /// Create a new immutable blob.
        #[weight = SubstrateWeight::<T>::new(&blob, &signature)]
        pub fn new(
            origin,
            blob: AddBlob<T>,
            signature: DidSignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::new_, blob, signature)
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn new_(AddBlob { blob, .. }: AddBlob<T>, signer: BlobOwner) -> DispatchResult {
        // check
        ensure!(
            T::MaxBlobSize::get() as usize >= blob.blob.len(),
            BlobError::<T>::BlobTooBig
        );
        ensure!(
            !Blobs::contains_key(&blob.id),
            BlobError::<T>::BlobAlreadyExists
        );

        // execute
        Blobs::insert(blob.id, (signer, blob.blob));

        Ok(())
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
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
