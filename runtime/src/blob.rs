use crate as dock;

use frame_support::{
    decl_error, decl_module, decl_storage, dispatch::DispatchError,
    dispatch::DispatchResult, ensure, fail,
};
use system::ensure_signed;
use codec::{Decode, Encode};
use alloc::vec::Vec;

use crate::did::{self, Did, DidSignature};

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;
/// Maximum size of the blob in bytes
// implementer may choose to implement this as a dynamic config option settable with the `parameter_type!` macro
pub const BLOB_MAX_BYTE_SIZE: usize = 1024;

/// The type of the blob id
pub type Id = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent
/// When a blob is queried, the following object is returned.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct Blob {
    id: dock::blob::Id,
    blob: Vec<u8>,
    author: dock::did::Did,
}

pub trait Trait: system::Trait + did::Trait {}

decl_error! {
    /// Error for the token module.
    pub enum Error for Module<T: Trait> {
        /// The blob is greater than `BLOB_MAX_BYTE_SIZE`
        BlobTooBig,
        /// There is already a blob with same id
        BlobAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        /// Signature verification failed while adding blob
        InvalidSig
    }
}

/// For each blob id, its author's DID and the blob is stored in the map
decl_storage! {
    trait Store for Module<T: Trait> as BlobModule {
        Blobs get(fn id): map hasher(blake2_128_concat) dock::blob::Id => Option<(dock::did::Did, Vec<u8>)>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        type Error = Error<T>;

        /// Register a new blob after ensuring blob with the same id is not registered and then
        /// verifying `did`'s signature on the blob
        /// `schema_detail` contains the id, author DID and the blob. The size of blob should be at
        /// most `BLOB_MAX_BYTE_SIZE` bytes. The `blob` is wrapped in a [StateChange][statechange] before
        /// serializing for signature verification.
        /// `signature` is the signature of the blob author on the `blob`
        // TODO: Use weight proportional to blob size
        #[weight = 10_000]
        pub fn new(origin, blob: dock::blob::Blob, signature: dock::did::DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            // TODO: Write the API
            Ok(())
        }

    }
}