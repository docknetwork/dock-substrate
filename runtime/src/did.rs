use super::{BlockNumber, DID, DID_BYTE_SIZE};
use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError, dispatch::DispatchResult, ensure, traits::Get};
use sp_std::prelude::Vec;
use system::ensure_signed;
use sp_std::convert::TryFrom;
use sp_core::{ed25519, sr25519, ecdsa};
use sp_runtime::traits::Verify;
use sp_std::fmt;

/// The module's configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    //type DIDByteSize: Get<u8>;
}

decl_error! {
	/// Error for the token module.
	pub enum Error for Module<T: Trait> {
		/// Given public key is not of the correct size
		PublicKeySizeIncorrect,
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
    Secp256k1,
}

/// Default is chosen since its Parity's default algo and due to Parity's reasoning.
impl Default for PublicKeyType {
    fn default() -> Self {
        PublicKeyType::Sr25519
    }
}

/// Size of a Sr25519 public key in bytes.
pub const Sr25519_PK_BYTE_SIZE: usize = 32;
/// Size of a Ed25519 public key in bytes.
pub const Ed25519_PK_BYTE_SIZE: usize = 32;

// XXX: This could have been a tuple struct. Keeping it a normal struct for Substrate UI
/// A wrapper over 32-byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Bytes32 {
    value: [u8; 32]
}

impl Default for Bytes32 {
    fn default() -> Self {
        Self {value: [0; 32]}
    }
}

// XXX: This could have been a tuple struct. Keeping it a normal struct for Substrate UI
/// A wrapper over 33-byte array
#[derive(Encode, Decode, Clone)]
pub struct Bytes33 {
    value: [u8; 33]
}

impl Default for Bytes33 {
    fn default() -> Self {
        Self {value: [0; 33]}
    }
}

/// Implementing Debug for Bytes33 as it cannot be automatically derived for arrays of size > 32
impl fmt::Debug for Bytes33 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value[..].fmt(f)
    }
}

/// Implementing PartialEq for Bytes33 as it cannot be automatically derived for arrays of size > 32
impl PartialEq for Bytes33 {
    fn eq(&self, other: &Bytes33) -> bool {
        self.value[..] == other.value[..]
    }
}
impl Eq for Bytes33 {}

/// An abstraction for a public key. Abstracts the type and value of the public key where the value is a
/// byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// Public key for Sr25519 is 32 bytes
    Sr25519(Bytes32),
    /// Public key for Ed25519 is 32 bytes
    Ed25519(Bytes32),
    /// Compressed public key for Secp256k1 is 33 bytes
    Secp256k1(Bytes33)
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey::Sr25519(Bytes32::default())
    }
}

// XXX: Substrate UI can't parse them. Maybe later versions will fix it.
/*#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Sr25519([u8; 32]),
    Ed25519([u8; 32])
}*/

/*#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Sr25519(Bytes32),
    Ed25519(Bytes32)
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Bytes32(pub [u8;32]);*/

/// `controller` is the controller DID and its value might be same as `did`. When that is the case, pass `controller` as None.
/// `public_key_type` is the type of the key
/// `public_key` is the public key and it is accepted and stored as raw bytes.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct KeyDetail {
    controller: DID,
    public_key: PublicKey
}

// XXX: Map requires having a default value for DIDDetail
impl Default for KeyDetail {
    fn default() -> Self {
        KeyDetail {
            controller: DID::default(),
            public_key: PublicKey::default(),
        }
    }
}

impl KeyDetail {
    /// Create new key detail
    pub fn new(controller: DID, public_key: PublicKey) -> Self {
        KeyDetail {
            controller, public_key
        }
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
    did: DID,
    public_key: PublicKey,
    controller: Option<DID>,
    last_modified_in_block: BlockNumber,
}

impl KeyUpdate {
    /// Create new key update to update key of the `did`.
    /// Pass `controller` as None when not wishing to change the existing controller
    pub fn new(did: DID, public_key: PublicKey, controller: Option<DID>,
               last_modified_in_block: BlockNumber) -> Self {
        // XXX: size of public_key can be checked here as well. But this will require making the return
        // type a result and an attacker can craft a struct without using this method anyway.
        // This can be addressed later
        KeyUpdate {
            did, public_key, controller, last_modified_in_block
        }
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

        /// Create a new DID.
        /// `did` is the new DID to create. The method will throw exception if `did` is already registered.
        /// `detail` is the details of the key like its type, controller and value
        fn new(origin, did: DID, detail: KeyDetail) -> DispatchResult {
            ensure_signed(origin)?;

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

            // Not checking for signature size as its not stored

            // DID must be registered
            ensure!(
                DIDs::<T>::exists(key_update.did),
                Error::<T>::DIDDoesNotExist
            );

            let (mut current_key_detail, last_modified_in_block) = DIDs::<T>::get(key_update.did);

            // replay protection: the key update should contain the last block in which the key was modified
            ensure!(
                last_modified_in_block == T::BlockNumber::from(key_update.last_modified_in_block),
                Error::<T>::DifferentBlockNumber
            );

            // serialize `KeyUpdate` to bytes
            let serz_key_update = key_update.encode();

            // Verify signature on the serialized `KeyUpdate` with the current public key
            let sig_ver = Self::verify_sig(&signature, &serz_key_update, &current_key_detail.public_key)?;

            // Throw error if signature is invalid
            ensure!(sig_ver == true, Error::<T>::InvalidSigForKeyUpdate);

            // Key update is safe to do, update the block number as well.
            let current_block_no = <system::Module<T>>::block_number();
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
    }
}

impl<T: Trait> Module<T> {
    /// Verify given signature on the given message with given public key
    pub fn verify_sig(signature: &[u8], message: &[u8], public_key: &PublicKey) -> Result<bool, DispatchError> {
        Ok(
            match public_key {
                PublicKey::Sr25519(bytes) => {
                    let signature = sr25519::Signature::try_from(signature).map_err(|_| Error::<T>::InvalidSigForKeyUpdate)?;
                    let pk = sr25519::Public(bytes.value.clone());
                    signature.verify(message, &pk)
                }
                PublicKey::Ed25519(bytes) => {
                    let signature = ed25519::Signature::try_from(signature).map_err(|_| Error::<T>::InvalidSigForKeyUpdate)?;
                    let pk = ed25519::Public(bytes.value.clone());
                    signature.verify(message, &pk)
                }
                PublicKey::Secp256k1(bytes) => {
                    let signature = ecdsa::Signature::try_from(signature).map_err(|_| Error::<T>::InvalidSigForKeyUpdate)?;
                    let pk = ecdsa::Public::Compressed(bytes.value.clone());
                    signature.verify(message, &pk)
                }
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
    use crate::did::PublicKeyType::Sr25519;

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

    #[test]
    fn did_creation() {
        // DID must be unique. It must have an acceptable public size
        new_test_ext().execute_with(|| {
            let alice = 10u64;

            let did = [1; DID_BYTE_SIZE];
            let pk = PublicKey::default();
            let detail = KeyDetail::new(did.clone(), pk);

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
            let pk = PublicKey::Ed25519(Bytes32::default());
            let detail = KeyDetail::new(did.clone(), pk);
            assert_err!(
                DIDModule::new(
                    Origin::signed(alice),
                    did,
                    detail
                ),
                Error::<Test>::DIDAlreadyExists
            );
        });
    }

    #[test]
    fn did_key_update_for_unregistered_did() {
        // Updating a DID that has not been registered yet should fail
        new_test_ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];

            let (pair, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk = pair.public().0;
            let key_update = KeyUpdate::new(did.clone(), PublicKey::Sr25519(Bytes32 {value: pk }), None, 2u32);
            let sig = pair.sign(&key_update.encode());

            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    sig.0.to_vec()
                ),
                Error::<Test>::DIDDoesNotExist
            );
        });
    }

    #[test]
    fn did_key_update_with_sr25519_ed25519_keys() {
        // DID's key must be updatable with the authorized key only. Check for sr25519 and ed25519
        new_test_ext().execute_with(|| {
            let alice = 100u64;

            /// Macro to check the key update for ed25519 and sr25519
            macro_rules! check_key_update {
                ( $did:ident, $module:ident, $pk:expr ) => {{
                    let (pair_1, _, _) = $module::Pair::generate_with_phrase(None);
                    let pk_1 = pair_1.public().0;

                    let detail = KeyDetail::new($did.clone(), $pk(Bytes32 {value: pk_1}));

                    // Add a DID
                    assert_ok!(
                        DIDModule::new(
                            Origin::signed(alice),
                            $did.clone(),
                            detail.clone()
                        )
                    );

                    let (_, modified_in_block) = DIDModule::did($did.clone());

                    // Correctly update DID's key.
                    // Prepare a key update
                    let (pair_2, _, _) = $module::Pair::generate_with_phrase(None);
                    let pk_2 = pair_2.public().0;
                    let key_update = KeyUpdate::new($did.clone(), $pk(Bytes32 {value: pk_2}), None, modified_in_block as u32);
                    let sig = pair_1.sign(&key_update.encode());

                    // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
                    assert_ok!(
                        DIDModule::update_key(
                            Origin::signed(alice),
                            key_update.clone(),
                            sig.0.to_vec()
                        )
                    );

                    let (_, modified_in_block) = DIDModule::did($did.clone());

                    // Maliciously update DID's key.
                    // Signing with the old key (`pair_1`) to update to the new key (`pair_2`)
                    let key_update = KeyUpdate::new($did.clone(), $pk(Bytes32 {value: pk_1}), None, modified_in_block as u32);
                    let sig = pair_1.sign(&key_update.encode());

                    assert_err!(
                        DIDModule::update_key(
                            Origin::signed(alice),
                            key_update.clone(),
                            sig.0.to_vec()
                        ),
                        Error::<Test>::InvalidSigForKeyUpdate
                    );

                    // Check key update with signature of incorrect size
                    // Use the correct key
                    let key_update = KeyUpdate::new($did.clone(), $pk(Bytes32 {value: pk_1}), None, modified_in_block as u32);
                    let sig = pair_2.sign(&key_update.encode());

                    // Truncate the signature to be of shorter size
                    let mut short_sig = sig.0.to_vec();
                    short_sig.truncate(10);

                    assert_err!(
                        DIDModule::update_key(
                            Origin::signed(alice),
                            key_update.clone(),
                            short_sig
                        ),
                        Error::<Test>::InvalidSigForKeyUpdate
                    );

                    // Add extra bytes to the signature to be of longer size
                    let mut long_sig = sig.0.to_vec();
                    long_sig.append(&mut vec![0, 1, 2, 0]);

                    assert_err!(
                        DIDModule::update_key(
                            Origin::signed(alice),
                            key_update.clone(),
                            long_sig
                        ),
                        Error::<Test>::InvalidSigForKeyUpdate
                    );
                }};
            }

            let did = [1; DID_BYTE_SIZE];
            check_key_update!(did, sr25519, PublicKey::Sr25519);

            let did = [2; DID_BYTE_SIZE];
            check_key_update!(did, ed25519, PublicKey::Ed25519);
        });
    }

    #[test]
    fn did_key_update_with_ecdsa_key() {
        // DID's key must be updatable with the authorized key only. Check for secp256k1.
        // The logic is same as above test but the way to generate keys, sig is little different. By creating abstractions
        // just for testing, above and this test can be merged.
        new_test_ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];

            let (pair_1, _, _) = ecdsa::Pair::generate_with_phrase(None);
            let pk_1= pair_1.public().as_compressed().unwrap();
            let detail = KeyDetail::new(did.clone(), PublicKey::Secp256k1(Bytes33 {value: pk_1}));

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
            let (pair_2, _, _) = ecdsa::Pair::generate_with_phrase(None);
            let pk_2= pair_2.public().as_compressed().unwrap();
            let key_update = KeyUpdate::new(did.clone(), PublicKey::Secp256k1(Bytes33 {value: pk_2}), None, modified_in_block as u32);
            let sig: [u8; 65] = pair_1.sign(&key_update.encode()).into();
            // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
            assert_ok!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    sig.to_vec()
                )
            );

            let (_, modified_in_block) = DIDModule::did(did.clone());

            // Maliciously update DID's key.
            // Signing with the old key (`pair_1`) to update to the new key (`pair_2`)
            let key_update = KeyUpdate::new(did.clone(), PublicKey::Secp256k1(Bytes33 {value: pk_1}), None, modified_in_block as u32);
            let sig: [u8; 65] = pair_1.sign(&key_update.encode()).into();

            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    sig.to_vec()
                ),
                Error::<Test>::InvalidSigForKeyUpdate
            );

            // Truncate the signature to be of shorter size
            let mut short_sig = sig.to_vec();
            short_sig.truncate(10);

            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    short_sig
                ),
                Error::<Test>::InvalidSigForKeyUpdate
            );

            // Add extra bytes to the signature to be of longer size
            let mut long_sig = sig.to_vec();
            long_sig.append(&mut vec![0, 1, 2, 0]);

            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update.clone(),
                    long_sig
                ),
                Error::<Test>::InvalidSigForKeyUpdate
            );
        });
    }
}
