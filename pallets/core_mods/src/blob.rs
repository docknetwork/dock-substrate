//! Generic immutable single-owner storage.

use crate as dock;
use crate::did;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchResult, ensure, traits::Get,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_std::borrow::Cow;

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
pub type BlobId = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Blob {
    pub id: BlobId,
    pub blob: Vec<u8>,
}

pub trait Trait: system::Config + did::Trait {
    /// Blobs larger than this will not be accepted.
    type MaxBlobSize: Get<u32>;
    /// The cost charged by the network to store a single byte in chain-state for the life of the
    /// chain.
    type StorageWeight: Get<Weight>;
}

decl_error! {
    /// Error for the blob module.
    pub enum BlobError for Module<T: Trait> where T: Debug {
        /// The blob is greater than `MaxBlobSize`
        BlobTooBig,
        /// There is already a blob with same id
        BlobAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        /// Signature verification failed while adding blob
        InvalidSig
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Blob where T: Debug {
        Blobs get(fn get_blob): map hasher(blake2_128_concat)
            dock::blob::BlobId => Option<(dock::did::Did, Vec<u8>)>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin, T: Debug {
        const MaxBlobSize: u32 = T::MaxBlobSize::get();

        const StorageWeight: Weight = T::StorageWeight::get();

        /// Create a new immutable blob.
        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight() +
          (blob.blob.len() as Weight * T::StorageWeight::get())]
        pub fn new(
            origin,
            blob: dock::blob::Blob,
            signature: dock::did::DidSignature,
        ) -> DispatchResult {
            Module::<T>::new_(origin, blob, signature)
        }
    }
}

impl<T: Trait + Debug> Module<T> {
    fn new_(
        origin: <T as system::Config>::Origin,
        blob: Blob,
        signature: did::DidSignature,
    ) -> DispatchResult {
        ensure_signed(origin)?;

        // check
        ensure!(
            T::MaxBlobSize::get() as usize >= blob.blob.len(),
            BlobError::<T>::BlobTooBig
        );
        ensure!(
            !Blobs::contains_key(&blob.id),
            BlobError::<T>::BlobAlreadyExists
        );
        let payload = crate::StateChange::<T>::Blob(Cow::Borrowed(&blob)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            BlobError::<T>::InvalidSig
        );

        // execute
        Blobs::insert(blob.id, (signature.did, blob.blob));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{did, Blob, BlobError, BlobId, Blobs, DispatchResult};
    use crate::test_common::*;
    use frame_support::StorageMap;
    use sp_core::{sr25519, Pair};
    use sp_std::borrow::Cow;

    fn create_blob(
        id: BlobId,
        content: Vec<u8>,
        author: did::Did,
        author_kp: sr25519::Pair,
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
            bl.clone(),
            did_sig::<Test>(
                &crate::StateChange::Blob(Cow::Borrowed(&bl)),
                &author_kp,
                author,
                1,
            ),
        )
    }

    fn get_max_blob_size() -> usize {
        <Test as crate::blob::Trait>::MaxBlobSize::get() as usize
    }

    #[test]
    fn add_blob() {
        fn add(size: usize) {
            let id: BlobId = rand::random();
            let noise = random_bytes(size);
            let (author, author_kp) = newdid();
            assert_eq!(Blobs::get(id), None);
            create_blob(id, noise.clone(), author, author_kp).unwrap();
            // Can retrieve a valid blob and the blob contents and author match the given ones.
            assert_eq!(Blobs::get(id), Some((author, noise)));
        }

        ext().execute_with(|| {
            // Can add a blob with unique id, blob data of < MaxBlobSize bytes and a valid signature.
            add(get_max_blob_size() - 1);
            add(get_max_blob_size() - 2);
            add(0);
            // Can add a blob with unique id, blob data of MaxBlobSize bytes and a valid signature.
            add(get_max_blob_size());
        });
    }

    #[test]
    fn err_blob_too_big() {
        fn add_too_big(size: usize) {
            let (author, author_kp) = newdid();
            let noise = random_bytes(size);
            let id = rand::random();
            assert_eq!(Blobs::get(id), None);
            let err = create_blob(id, noise, author, author_kp).unwrap_err();
            assert_eq!(err, BlobError::<Test>::BlobTooBig.into());
            assert_eq!(Blobs::get(id), None);
        }

        ext().execute_with(|| {
            add_too_big(get_max_blob_size() + 1);
            add_too_big(get_max_blob_size() + 2);
        });
    }

    #[test]
    fn err_blob_already_exists() {
        ext().execute_with(|| {
            // Adding a blob with already used id fails with error BlobAlreadyExists.
            let id = rand::random();
            let (author, author_kp) = newdid();
            assert_eq!(Blobs::get(id), None);
            create_blob(id, random_bytes(10), author, author_kp.clone()).unwrap();
            let err = create_blob(id, random_bytes(10), author, author_kp).unwrap_err();
            assert_eq!(err, BlobError::<Test>::BlobAlreadyExists.into());
        });
    }

    #[test]
    fn err_did_does_not_exist() {
        ext().execute_with(|| {
            // Adding a blob with an unregistered DID fails with error DidDoesNotExist.
            let author = rand::random();
            let author_kp = gen_kp();
            let err = create_blob(rand::random(), random_bytes(10), author, author_kp).unwrap_err();
            assert_eq!(err, did::Error::<Test>::NoKeyForDid.into());
        });
    }

    #[test]
    fn err_invalid_sig() {
        ext().execute_with(|| {
            {
                // An invalid signature while adding a blob should fail with error InvalidSig.
                let (author, author_kp) = newdid();
                let bl = Blob {
                    id: rand::random(),
                    blob: random_bytes(10),
                };
                let remreg = crate::revoke::RemoveRegistry::<Test> {
                    registry_id: rand::random(),
                    nonce: 10,
                };
                let err = BlobMod::new(
                    Origin::signed(ABBA),
                    bl.clone(),
                    did_sig(
                        &crate::StateChange::RemoveRegistry(Cow::Borrowed(&remreg)),
                        &author_kp,
                        author,
                        1,
                    ),
                )
                .unwrap_err();
                assert_eq!(err, BlobError::<Test>::InvalidSig.into());
            }

            {
                // signature by other party
                let (author, _) = newdid();
                let (_, author_kp) = newdid();
                let bl = Blob {
                    id: rand::random(),
                    blob: random_bytes(10),
                };
                let err = BlobMod::new(
                    Origin::signed(ABBA),
                    bl.clone(),
                    did_sig::<Test>(
                        &crate::StateChange::Blob(Cow::Borrowed(&bl)),
                        &author_kp,
                        author,
                        1,
                    ),
                )
                .unwrap_err();
                assert_eq!(err, BlobError::<Test>::InvalidSig.into());
            }
        })
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use crate::benchmark_utils::{get_data_for_blob, BLOB_DATA_SIZE};
    use crate::did::{Dids, KeyDetail};
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
            Dids::<T>::insert(did.clone(), (detail, block_number));

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
