use super::{BlockNumber, DID, DID_BYTE_SIZE, PK_MAX_BYTE_SIZE};
use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError, dispatch::DispatchResult, ensure, traits::Get};
use sp_std::prelude::Vec;
use system::ensure_signed;
use sp_std::convert::TryFrom;
use sp_core::{ed25519, sr25519, ecdsa};
use sp_runtime::traits::Verify;

/// The module's configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    //type DIDByteSize: Get<u8>;
}

decl_error! {
	/// Error for the token module.
	pub enum Error for Module<T: Trait> {
		/// Given public key is larger than the maximum supported size
		LargePublicKey,
		/// There is already a DID with same value
		DIDAlreadyExists,
		/// There is no such DID
		DIDDoesNotExist,
		/// For replay protection, an update to state is required to contain the same block number
		/// in which the last update was performed.
		DifferentBlockNumber,
		/// Signature verification failed while key update
		InvalidSigForKeyUpdate,
		/// Signature verification failed while DID removal
		InvalidSigForDIDRemoval
	}
}

/// Cryptographic algorithm of public key
/// like `Ed25519VerificationKey2018`, `Secp256k1VerificationKey2018` and `Sr25519VerificationKey2018`
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyType {
    Sr25519,
    Ed25519,
    // TODO: Uncomment
    //Secp256k1,
}

/// Default is chosen since its Parity's default algo and due to Parity's reasoning.
impl Default for PublicKeyType {
    fn default() -> Self {
        PublicKeyType::Sr25519
    }
}

// TODO: Consider combining the public key and its type in a enum. That way the enum variant can know the public key
// size as well and i don't have to rely on checking input vector length.

/// `controller` is the controller DID and its value might be same as `did`. When that is the case, pass `controller` as None.
/// `public_key_type` is the type of the key
/// `public_key` is the public key and it is accepted and stored as raw bytes.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct KeyDetail {
    controller: DID,
    //controller: [u8; DID_BYTE_SIZE],
    //controller: [u8; 32],
    public_key_type: PublicKeyType,
    public_key: Vec<u8>,
}

// XXX: Map requires having a default value for DIDDetail
impl Default for KeyDetail {
    fn default() -> Self {
        KeyDetail {
            controller: DID::default(),
            //controller: [0; 32],
            //controller: DID,
            public_key_type: PublicKeyType::default(),
            public_key: Vec::new(),
        }
    }
}

impl KeyDetail {
    /// Create new key detail
    pub fn new(controller: DID, public_key_type: PublicKeyType, public_key: Vec<u8>) -> Self {
        // XXX: size of public_key can be checked here as well. But this will require making the return
        // type a result and an attacker can craft a struct without using this method anyway.
        // This can be addressed later
        KeyDetail {
            controller, public_key, public_key_type
        }
    }

    /// Check if the public key is not bigger than the maximum allowed size
    pub fn is_public_key_size_acceptable(&self) -> bool {
        self.public_key.len() <= PK_MAX_BYTE_SIZE
    }
}

/// This struct is passed as an argument while updating the key
/// `did` is the DID whose key is being updated.
/// `public_key_type` is new public key type
/// `public_key` the new public key
/// `controller` If provided None, the controller is unchanged. While serializing, use literal "None" when controller is None
/// The last_modified_in_block is the block number when this DID was last modified is present to prevent replay attack.
/// This approach allows only 1 update transaction in a block (don't see it as a problem as key updates are rare).
/// An alternate approach can be to have a nonce associated to each detail which is incremented on each
/// successful extrinsic and the chain requiring the extrinsic's nonce to be higher than current. This is
/// little more involved as it involves a ">" check
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct KeyUpdate {
    //did: [u8; DID_BYTE_SIZE],
    did: DID,
    public_key_type: PublicKeyType,
    public_key: Vec<u8>,
    controller: Option<DID>,
    last_modified_in_block: BlockNumber,
}

impl KeyUpdate {
    /// Create new key update to update key of the `did`.
    /// Pass `controller` as None when not wishing to change the existing controller
    pub fn new(did: DID, public_key_type: PublicKeyType, public_key: Vec<u8>, controller: Option<DID>, last_modified_in_block: BlockNumber) -> Self {
        // XXX: size of public_key can be checked here as well. But this will require making the return
        // type a result and an attacker can craft a struct without using this method anyway.
        // This can be addressed later
        KeyUpdate {
            did, public_key_type, public_key, controller, last_modified_in_block
        }
    }

    /// Check if the public key is not bigger than the maximum allowed size
    pub fn is_public_key_size_acceptable(&self) -> bool {
        self.public_key.len() <= PK_MAX_BYTE_SIZE
    }
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
/// `last_modified_in_block` is the block number when this DID was last modified. The last modified time is present to prevent replay attack.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct DIDRemoval {
    did: DID,
    last_modified_in_block: BlockNumber,
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        DIDAdded(DID),
        KeyUpdated(DID),
        DummyEvent(AccountId),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule {
        DIDs get(did): map DID => (KeyDetail, T::BlockNumber);
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        type Error = Error<T>;

        //fn new(_origin, did: [u8; DID_BYTE_SIZE], detail: KeyDetail) -> DispatchResult {
        /// Create a new DID.
        /// `did` is the new DID to create. The method will throw exception if `did` is already registered.
        /// `detail` is the details of the key like its type, controller and value
        fn new(origin, did: DID, detail: KeyDetail) -> DispatchResult {
            ensure_signed(origin)?;

            // public key is not huge
            ensure!(
                detail.is_public_key_size_acceptable(),
                Error::<T>::LargePublicKey
            );

            // DID is not registered already
            ensure!(
                !DIDs::<T>::exists(did),
                Error::<T>::DIDAlreadyExists
            );

            let current_block_no = <system::Module<T>>::block_number();
            DIDs::<T>::insert(did, (detail, current_block_no));
            Self::deposit_event(RawEvent::DIDAdded(did));
            Ok(())
        }

        /// `key_update` specifies which DID's which key needs to be updated
        /// `signature` is the signature on the serialized `KeyUpdate`.
        /// The node while processing this extrinsic, should create the above serialized `KeyUpdate`
        /// using the stored data and try to verify the given signature with the stored key.
        pub fn update_key(origin, key_update: KeyUpdate, signature: Vec<u8>) -> DispatchResult {
            ensure_signed(origin)?;

            // public key is not huge
            ensure!(
                key_update.is_public_key_size_acceptable(),
                Error::<T>::LargePublicKey
            );

            // Not checking for signature size as its not stored

            // DID must be registered
            ensure!(
                DIDs::<T>::exists(key_update.did),
                Error::<T>::DIDAlreadyExists
            );

            let (mut current_key_detail, last_modified_in_block) = DIDs::<T>::get(key_update.did);

            // replay protection: the key update should contain the last block in which the key was modified
            ensure!(
                last_modified_in_block == T::BlockNumber::from(key_update.last_modified_in_block),
                Error::<T>::DifferentBlockNumber
            );

            // serialize to bytes
            let serz_key_update = key_update.encode();

            let sig_ver = Self::verify_sig(&signature, &serz_key_update, &current_key_detail.public_key_type, &current_key_detail.public_key)?;

            // Signature should be valid
            ensure!(sig_ver == true, Error::<T>::InvalidSigForKeyUpdate);

            // Key update is safe to do
            let current_block_no = <system::Module<T>>::block_number();
            current_key_detail.public_key_type = key_update.public_key_type;
            current_key_detail.public_key = key_update.public_key;

            // If key update specified a controller, then only update the current controller
            if let Some(ctrl) = key_update.controller {
                current_key_detail.controller = ctrl;
            }

            DIDs::<T>::insert(key_update.did, (current_key_detail, current_block_no));
            Self::deposit_event(RawEvent::KeyUpdated(key_update.did));
            Ok(())
        }

        /// `to_remove` contains the DID to be removed
        /// `signature` is the signature on the serialized `DIDRemoval`.
        /// The node while processing this extrinsic, should create the above serialized `DIDRemoval`
        /// using the stored data and try to verify the given signature with the stored key.
        pub fn remove(origin, to_remove: DIDRemoval, signature: Vec<u8>) -> DispatchResult {
            ensure_signed(origin)?;

            // DID must be registered
            ensure!(
                DIDs::<T>::exists(to_remove.did),
                Error::<T>::DIDAlreadyExists
            );

            // TODO:
            Ok(())
        }

        // TODO: Add sig verification method that can be used by any other module as well.
    }
}

impl<T: Trait> Module<T> {
    pub fn verify_sig(signature: &[u8], message: &[u8], public_key_type: &PublicKeyType, public_key: &[u8]) -> Result<bool, DispatchError> {
        Ok(
            match *public_key_type {
                // Fixme: Remove unwraps
                PublicKeyType::Sr25519 => {
                    // XXX: `&` does not work for taking reference
                    //let signature = sr25519::Signature::try_from(&signature).unwrap();
                    let signature = sr25519::Signature::try_from(signature).map_err(|_| Error::<T>::InvalidSigForKeyUpdate)?;
                    let mut pk_bytes: [u8; 32] = [0; 32];
                    // Fixme: Assuming key has same length
                    pk_bytes.clone_from_slice(public_key);
                    let pk = sr25519::Public(pk_bytes);
                    signature.verify(message, &pk)
                }
                PublicKeyType::Ed25519 => {
                    let signature = ed25519::Signature::try_from(signature).map_err(|_| Error::<T>::InvalidSigForKeyUpdate)?;
                    let mut pk_bytes: [u8; 32] = [0; 32];
                    // Fixme: Assuming key has same length
                    pk_bytes.clone_from_slice(public_key);
                    let pk = ed25519::Public(pk_bytes);
                    signature.verify(message, &pk)
                }
                /*case PublicKeyType::Secp256k1 => {

                }*/
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{
        assert_err, assert_ok, impl_outer_origin, parameter_types, weights::Weight,
    };
    use sp_core::{H256, Pair};
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup, OnFinalize, OnInitialize},
        Perbill,
    };

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    #[derive(Clone, Eq, Debug, PartialEq)]
    pub struct Test;

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::one();
    }

    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        // XXX: Why is it u64 when in lib.rs its u32
        type BlockNumber = u64;
        type Call = ();
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type AvailableBlockRatio = AvailableBlockRatio;
        type MaximumBlockLength = MaximumBlockLength;
        type Version = ();
        type ModuleToIndex = ();
    }

    /*impl balances::Trait for Test {
        type Balance = u64;
        type OnNewAccount = ();
        type OnFreeBalanceZero = ();
        type Event = ();
        type TransferPayment = ();
        type DustRemoval = ();
        type ExistentialDeposit = ExistentialDeposit;
        type TransferFee = TransferFee;
        type CreationFee = CreationFee;
    }*/

    impl super::Trait for Test {
        type Event = ();
    }

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    type DIDModule = super::Module<Test>;

    // TODO: Add test for Event DIDAdded
    // TODO: Add test for Event KeyUpdated
    // TODO: Add test for public key len check in KeyUpdate

    #[test]
    fn public_key_must_have_acceptable_size() {
        // Public key must not be very large

        // Smaller public key is fine
        let did = [1; DID_BYTE_SIZE];
        let pk = vec![2u8; PK_MAX_BYTE_SIZE-1];
        let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);
        assert!(detail.is_public_key_size_acceptable());

        // public key with max size is fine
        let pk = vec![2u8; PK_MAX_BYTE_SIZE];
        let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);
        assert!(detail.is_public_key_size_acceptable());

        // public key with larger than max size is not fine
        let pk = vec![2u8; PK_MAX_BYTE_SIZE+1];
        let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);
        assert!(!detail.is_public_key_size_acceptable());
    }

    #[test]
    fn did_creation() {
        // DID must be unique. It must have an acceptable public size
        new_test_ext().execute_with(|| {
            let alice = 10u64;

            let did = [1; DID_BYTE_SIZE];
            let pk = vec![0, 1];
            let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);

            // Add a DID
            assert_ok!(
                DIDModule::new(
                    Origin::signed(alice),
                    did.clone(),
                    detail.clone()
                )
            );

            // Try to add the same DID and same key detail again and fail
            assert_err!(
                DIDModule::new(
                    Origin::signed(alice),
                    did.clone(),
                    detail.clone()
                ),
                Error::<Test>::DIDAlreadyExists
            );

            // Try to add the same DID again but with different key detail and fail
            let pk = vec![0, 1, 9, 10, 12];
            let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);
            assert_err!(
                DIDModule::new(
                    Origin::signed(alice),
                    did,
                    detail
                ),
                Error::<Test>::DIDAlreadyExists
            );

            // public key with larger than max size is not fine
            let pk = vec![2u8; PK_MAX_BYTE_SIZE+1];
            let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);
            assert_err!(
                DIDModule::new(
                    Origin::signed(alice),
                    did,
                    detail
                ),
                Error::<Test>::LargePublicKey
            );
        });
    }

    #[test]
    fn did_key_update() {
        // DID must be unique. It must have an acceptable public size
        new_test_ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];
            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0.to_vec();

            let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk_1.clone());

            // Add a DID
            assert_ok!(
                DIDModule::new(
                    Origin::signed(alice),
                    did.clone(),
                    detail.clone()
                )
            );

            let (_, modified_in_block) = DIDModule::did(did.clone());

            // Correctly update DID's key.
            // Prepare a key update
            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0.to_vec();
            let key_update = KeyUpdate::new(did.clone(), PublicKeyType::Sr25519, pk_2.clone(), None, modified_in_block as u32);
            let sig = pair_1.sign(&key_update.encode());

            // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
            assert_ok!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    sig.0.to_vec()
                )
            );

            let (_, modified_in_block) = DIDModule::did(did.clone());

            // Maliciously update DID's key.
            // Signing with the old key (`pair_1`) to update to the new key (`pair_2`)
            let key_update = KeyUpdate::new(did.clone(), PublicKeyType::Sr25519, pk_1.clone(), None, modified_in_block as u32);
            let sig = pair_1.sign(&key_update.encode());

            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    sig.0.to_vec()
                ),
                Error::<Test>::InvalidSigForKeyUpdate
            );
        });
    }
}
