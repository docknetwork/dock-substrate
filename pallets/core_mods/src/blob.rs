//! Generic immutable single-owner storage.

use crate as dock;
use crate::did;
use crate::did::{Did, DidSignature};
use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::fmt::Debug;

use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};

/// Owner of a Blob.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BlobOwner(pub Did);

crate::impl_wrapper!(BlobOwner, Did, for test use blob_owner_tests with rand Did(rand::random()));

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
pub type BlobId = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Blob {
    pub id: BlobId,
    pub blob: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
            dock::blob::BlobId => Option<(BlobOwner, Vec<u8>)>;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        const MaxBlobSize: u32 = T::MaxBlobSize::get();

        const StorageWeight: Weight = T::StorageWeight::get();

        /// Create a new immutable blob.
        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight() +
          (blob.blob.blob.len() as Weight * T::StorageWeight::get())]
        pub fn new(
            origin,
            blob: AddBlob<T>,
            signature: DidSignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(blob, signature, Self::new_)
            // Self::new_(blob, signature.did)?;
            // Ok(())
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

#[cfg(test)]
mod tests {

    use super::{did, Blob, BlobError, BlobId, BlobOwner, Blobs, DispatchResult};
    use crate::{blob::AddBlob, did::Did, test_common::*};
    use frame_support::StorageMap;
    use sp_core::{sr25519, Pair};

    fn create_blob(
        id: BlobId,
        content: Vec<u8>,
        author: BlobOwner,
        author_kp: sr25519::Pair,
        nonce: u64,
    ) -> DispatchResult {
        let bl = Blob {
            id,
            blob: content.clone(),
        };
        println!("did: {:?}", author);
        println!("pk: {:?}", author_kp.public().0);
        println!("id: {:?}", id);
        println!("content: {:?}", content.clone());

        BlobMod::new(
            Origin::signed(ABBA),
            AddBlob {
                blob: bl.clone(),
                nonce,
            },
            did_sig::<Test, _, _>(&AddBlob { blob: bl, nonce }, &author_kp, author, 1),
        )
    }

    fn get_max_blob_size() -> usize {
        <Test as crate::blob::Config>::MaxBlobSize::get() as usize
    }

    #[test]
    fn add_blob() {
        fn add(size: usize, block_no: u64) {
            run_to_block(block_no);

            let id: BlobId = rand::random();
            let noise = random_bytes(size);
            let (author, author_kp) = newdid();
            assert_eq!(Blobs::get(id), None);
            create_blob(
                id,
                noise.clone(),
                BlobOwner(author),
                author_kp,
                block_no + 1,
            )
            .unwrap();
            // Can retrieve a valid blob and the blob contents and author match the given ones.
            assert_eq!(Blobs::get(id), Some((BlobOwner(author), noise)));
        }

        ext().execute_with(|| {
            // Can add a blob with unique id, blob data of < MaxBlobSize bytes and a valid signature.
            add(get_max_blob_size() - 1, 10);
            add(get_max_blob_size() - 2, 20);
            add(0, 30);
            // Can add a blob with unique id, blob data of MaxBlobSize bytes and a valid signature.
            add(get_max_blob_size(), 40);
        });
    }

    #[test]
    fn err_blob_too_big() {
        fn add_too_big(size: usize, block_no: u64) {
            run_to_block(block_no);

            let (author, author_kp) = newdid();
            let noise = random_bytes(size);
            let id = rand::random();
            assert_eq!(Blobs::get(id), None);
            let err =
                create_blob(id, noise, BlobOwner(author), author_kp, block_no + 1).unwrap_err();
            assert_eq!(err, BlobError::<Test>::BlobTooBig.into());
            assert_eq!(Blobs::get(id), None);
        }

        ext().execute_with(|| {
            add_too_big(get_max_blob_size() + 1, 10);
            add_too_big(get_max_blob_size() + 2, 20);
        });
    }

    #[test]
    fn err_blob_already_exists() {
        ext().execute_with(|| {
            run_to_block(10);

            // Adding a blob with already used id fails with error BlobAlreadyExists.
            let id = rand::random();
            let (author, author_kp) = newdid();
            assert_eq!(Blobs::get(id), None);
            create_blob(
                id,
                random_bytes(10),
                BlobOwner(author),
                author_kp.clone(),
                10 + 1,
            )
            .unwrap();
            let err = create_blob(id, random_bytes(10), BlobOwner(author), author_kp, 11 + 1)
                .unwrap_err();
            assert_eq!(err, BlobError::<Test>::BlobAlreadyExists.into());
        });
    }

    #[test]
    fn err_did_does_not_exist() {
        ext().execute_with(|| {
            run_to_block(10);

            // Adding a blob with an unregistered DID fails with error DidDoesNotExist.
            let author = BlobOwner(Did(rand::random()));
            let author_kp = gen_kp();
            let err = create_blob(rand::random(), random_bytes(10), author, author_kp, 10 + 1)
                .unwrap_err();
            assert_eq!(err, did::Error::<Test>::NoKeyForDid.into());
        });
    }

    #[test]
    fn err_invalid_sig() {
        ext().execute_with(|| {
            {
                run_to_block(10);
                // An invalid signature while adding a blob should fail with error InvalidSignature.
                let (author, author_kp) = newdid();
                let bl = Blob {
                    id: rand::random(),
                    blob: random_bytes(10),
                };
                let att = crate::attest::SetAttestationClaim::<Test> {
                    attest: crate::attest::Attestation {
                        priority: 1,
                        iri: None,
                    },
                    nonce: 10 + 1,
                };
                let err = BlobMod::new(
                    Origin::signed(ABBA),
                    AddBlob {
                        blob: bl.clone(),
                        nonce: 10 + 1,
                    },
                    did_sig(&att, &author_kp, BlobOwner(author), 1),
                )
                .unwrap_err();
                assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
            }

            {
                run_to_block(20);

                // signature by other party
                let (author, _) = newdid();
                let (_, author_kp) = newdid();
                let bl = Blob {
                    id: rand::random(),
                    blob: random_bytes(10),
                };
                let err = BlobMod::new(
                    Origin::signed(ABBA),
                    AddBlob {
                        blob: bl.clone(),
                        nonce: 20 + 1,
                    },
                    did_sig::<Test, _, _>(
                        &AddBlob {
                            blob: bl,
                            nonce: 20 + 1,
                        },
                        &author_kp,
                        BlobOwner(author),
                        1,
                    ),
                )
                .unwrap_err();
                assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
            }
        })
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use crate::benchmark_utils::{get_data_for_blob, BLOB_DATA_SIZE};
    use crate::did::{BlobOwners, KeyDetail};
    use frame_benchmarking::{account, benchmarks};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const SEED: u32 = 0;
    const MAX_USER_INDEX: u32 = 1000;

    benchmarks! {
        _ {
            // Origin
            let u in 1 .. MAX_USER_INDEX => ();
            let i in 0 .. (BLOB_DATA_SIZE - 1) as u32 => ();
        }

        new {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);
            let n = 0;

            let (did, pk, id, content, sig) = get_data_for_blob(i as usize);

            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            BlobOwners::<T>::insert(did.clone(), (detail, block_number));

            let blob = Blob {
                id,
                blob: content,
                author: did,
            };
        }: _(RawOrigin::Signed(caller), blob, sig)
        verify {
            let value = Blobs::get(id);
            assert!(value.is_some());
        }
    }
}
