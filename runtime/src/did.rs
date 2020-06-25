use super::{BlockNumber, StateChange};
use crate as dock;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError,
    dispatch::DispatchResult, ensure, fail,
};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::traits::Verify;
use sp_std::convert::TryFrom;
use sp_std::fmt;
use system::ensure_signed;

/// Size of the Dock DID in bytes
const DID_BYTE_SIZE: usize = 32;
/// The type of the Dock DID
pub type Did = [u8; DID_BYTE_SIZE];

/// The module's configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

decl_error! {
    /// Error for the token module.
    pub enum Error for Module<T: Trait> {
        /// Given public key is not of the correct size
        PublicKeySizeIncorrect,
        /// There is already a DID with same value
        DidAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        /// For replay protection, an update to state is required to contain the same block number
        /// in which the last update was performed.
        DifferentBlockNumber,
        /// Signature type does not match public key type
        InvalidSigType,
        /// Signature verification failed while key update or did removal
        InvalidSig
    }
}

// XXX: This could have been a tuple struct. Keeping it a normal struct for Substrate UI
/// A wrapper over 32-byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bytes32 {
    pub value: [u8; 32],
}

impl Bytes32 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

#[cfg(feature = "serde")]
serde_big_array::big_array! {
    BigArray;
    33, 64, 65
}

// XXX: These could have been a tuple structs. Keeping them normal struct for Substrate UI
/// Creates a struct named `$name` which contains only 1 element which is a bytearray, useful when
/// wrapping arrays of size > 32. `$size` is the size of the underlying bytearray. Implements the `Default`,
/// `sp_std::fmt::Debug`, `PartialEq` and `Eq` trait as they will not be automatically implemented for arrays of size > 32.
macro_rules! struct_over_byte_array {
    ( $name:ident, $size:tt ) => {
        /// A wrapper over a byte array
        #[derive(Encode, Decode, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
            pub value: [u8; $size],
        }

        /// Implementing Default as it cannot be automatically derived for arrays of size > 32
        impl Default for $name {
            fn default() -> Self {
                Self { value: [0; $size] }
            }
        }

        /// Implementing Debug as it cannot be automatically derived for arrays of size > 32
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.value[..].fmt(f)
            }
        }

        /// Implementing PartialEq as it cannot be automatically derived for arrays of size > 32
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.value[..] == other.value[..]
            }
        }

        impl Eq for $name {}

        impl $name {
            /// Return a slice to the underlying bytearray
            pub fn as_bytes(&self) -> &[u8] {
                &self.value
            }
        }
    };
}

struct_over_byte_array!(Bytes33, 33);
struct_over_byte_array!(Bytes64, 64);
struct_over_byte_array!(Bytes65, 65);

/// An abstraction for a public key. Abstracts the type and value of the public key where the value is a
/// byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PublicKey {
    /// Public key for Sr25519 is 32 bytes
    Sr25519(Bytes32),
    /// Public key for Ed25519 is 32 bytes
    Ed25519(Bytes32),
    /// Compressed public key for Secp256k1 is 33 bytes
    Secp256k1(Bytes33),
}

/// An abstraction for a signature.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DidSignature {
    /// Signature for Sr25519 is 64 bytes
    Sr25519(Bytes64),
    /// Signature for Ed25519 is 64 bytes
    Ed25519(Bytes64),
    /// Signature for Secp256k1 is 65 bytes
    Secp256k1(Bytes65),
}

impl DidSignature {
    /// Try to get reference to the bytes if its a Sr25519 signature. Return error if its not.
    fn as_sr25519_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            DidSignature::Sr25519(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }

    /// Try to get reference to the bytes if its a Ed25519 signature. Return error if its not.
    fn as_ed25519_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            DidSignature::Ed25519(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }

    /// Try to get reference to the bytes if its a Secp256k1 signature. Return error if its not.
    fn as_secp256k1_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            DidSignature::Secp256k1(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }
}

// XXX: Substrate UI can't parse them. Maybe later versions will fix it.
/*
/// Size of a Sr25519 public key in bytes.
pub const Sr25519_PK_BYTE_SIZE: usize = 32;
/// Size of a Ed25519 public key in bytes.
pub const Ed25519_PK_BYTE_SIZE: usize = 32;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
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

/// `controller` is the controller DID and its value might be same as `did`.
/// `public_key` is the public key and it is accepted and stored as raw bytes.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyDetail {
    controller: Did,
    public_key: PublicKey,
}

impl KeyDetail {
    /// Create new key detail
    pub fn new(controller: Did, public_key: PublicKey) -> Self {
        KeyDetail {
            controller,
            public_key,
        }
    }
}

/// This struct is passed as an argument while updating the key for a DID.
/// `did` is the DID whose key is being updated.
/// `public_key` the new public key
/// `controller` If provided None, the controller is unchanged. While serializing, use literal
/// "None" when controller is None.
/// The last_modified_in_block is the block number when this DID was last modified. It is used to
/// prevent replay attacks. This approach allows easy submission of 1 update transaction in a block.
/// It's theoretically possible to submit more than one txn per block, but the method is
/// non-trivial and potentially unreliable.
/// An alternate approach can be to have a nonce associated to each detail which is incremented on each
/// successful extrinsic and the chain requiring the extrinsic's nonce to be higher than current.
/// This is little more involved as it involves a ">" check
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyUpdate {
    pub did: Did,
    pub public_key: PublicKey,
    pub controller: Option<Did>,
    pub last_modified_in_block: BlockNumber,
}

impl KeyUpdate {
    /// Create new key update to update key of the `did`.
    /// Pass `controller` as None when not wishing to change the existing controller
    pub fn new(
        did: Did,
        public_key: PublicKey,
        controller: Option<Did>,
        last_modified_in_block: BlockNumber,
    ) -> Self {
        KeyUpdate {
            did,
            public_key,
            controller,
            last_modified_in_block,
        }
    }
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
/// `last_modified_in_block` is the block number when this DID was last modified. The last modified time is present to prevent replay attack.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidRemoval {
    pub did: Did,
    pub last_modified_in_block: BlockNumber,
}

impl DidRemoval {
    /// Remove an existing DID `did`
    pub fn new(did: Did, last_modified_in_block: BlockNumber) -> Self {
        DidRemoval {
            did,
            last_modified_in_block,
        }
    }
}

decl_event!(
    pub enum Event {
        DidAdded(dock::did::Did),
        KeyUpdated(dock::did::Did),
        DidRemoved(dock::did::Did),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule {
        Dids get(fn did): map hasher(blake2_128_concat) dock::did::Did => Option<(dock::did::KeyDetail, T::BlockNumber)>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        type Error = Error<T>;

        /// Create a new DID.
        /// `did` is the new DID to create. The method will fail if `did` is already registered.
        /// `detail` is the details of the key like its type, controller and value
        // TODO: Use correct weight
        #[weight = 10_000]
        pub fn new(origin, did: dock::did::Did, detail: dock::did::KeyDetail) -> DispatchResult {
            ensure_signed(origin)?;

            // DID is not registered already
            ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

            let current_block_no = <system::Module<T>>::block_number();
            Dids::<T>::insert(did, (detail, current_block_no));
            Self::deposit_event(Event::DidAdded(did));
            Ok(())
        }

        /// Sets the single publicKey (and possibly its controller) stored in this DID.
        ///
        /// `key_update` specifies which DID's key needs to be updated
        /// `signature` is the signature on a serialized [StateChange][statechange] that wraps the
        /// [KeyUpdate][keyupdate] struct
        ///
        /// During execution this function checks for a signature over [StateChange][statechange]
        /// and verifies the given signature with the stored key.
        ///
        /// [statechange]: ../enum.StateChange.html
        /// [keyupdate]: ./struct.KeyUpdate.html
        #[weight = 10_000]
        pub fn update_key(
            origin,
            key_update: dock::did::KeyUpdate,
            signature: dock::did::DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // DID is registered and the update is not being replayed
            let mut current_key_detail = Self::ensure_did_registered_and_payload_fresh(
                &key_update.did,
                key_update.last_modified_in_block,
            )?;

            // serialize `KeyUpdate` to bytes
            let serz_key_update = StateChange::KeyUpdate(key_update.clone()).encode();

            // Verify signature on the serialized `KeyUpdate` with the current public key
            let sig_ver = Self::verify_sig_with_public_key(
                &signature,
                &serz_key_update,
                &current_key_detail.public_key,
            )?;

            // Throw error if signature is invalid
            ensure!(sig_ver, Error::<T>::InvalidSig);

            // Key update is safe to do, update the block number as well.
            let current_block_no = <system::Module<T>>::block_number();
            current_key_detail.public_key = key_update.public_key;

            // If key update specified a controller, then only update the current controller
            if let Some(ctrl) = key_update.controller {
                current_key_detail.controller = ctrl;
            }

            Dids::<T>::insert(key_update.did, (current_key_detail, current_block_no));
            Self::deposit_event(Event::KeyUpdated(key_update.did));
            Ok(())
        }

        /// Deletes a DID from chain storage. Once the DID is deleted, anyone can call new to claim
        /// it for their own.
        ///
        /// `to_remove` contains the DID to be removed
        /// `signature` is the signature on a serialized [StateChange][statechange] that wraps the
        /// [DidRemoval][didremoval] struct
        ///
        /// During execution this function checks for a signature over [StateChange][statechange]
        /// and verifies the given signature with the stored key.
        ///
        /// [statechange]: ../enum.StateChange.html
        /// [didremoval]: ./struct.DidRemoval.html
        #[weight = 10_000]
        pub fn remove(
            origin,
            to_remove: dock::did::DidRemoval,
            signature: dock::did::DidSignature
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // DID is registered and the removal is not being replayed
            let current_key_detail =
                Self::ensure_did_registered_and_payload_fresh(&to_remove.did, to_remove.last_modified_in_block)?;

            let did = to_remove.did;
            // serialize `DIDRemoval` to bytes
            let serz_rem = StateChange::DIDRemoval(to_remove).encode();

            // Verify signature on the serialized `KeyUpdate` with the current public key
            let sig_ver = Self::verify_sig_with_public_key(
                &signature,
                &serz_rem,
                &current_key_detail.public_key,
            )?;

            // Throw error if signature is invalid
            ensure!(sig_ver, Error::<T>::InvalidSig);

            // Remove DID
            Dids::<T>::remove(did);
            Self::deposit_event(Event::DidRemoved(did));
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    /// Ensure that the DID is registered and this is not a replayed payload by checking the equality
    /// with stored block number when the DID was last modified.
    fn ensure_did_registered_and_payload_fresh(
        did: &Did,
        last_modified_in_block: BlockNumber,
    ) -> Result<KeyDetail, DispatchError> {
        let (current_key_detail, last_modified) = Self::get_key_detail(did)?;

        // replay protection: the command should contain the last block in which the DID was modified
        ensure!(
            last_modified == T::BlockNumber::from(last_modified_in_block),
            Error::<T>::DifferentBlockNumber
        );

        Ok(current_key_detail)
    }

    /// Get the key detail and the block number of last modification of the given DID.
    /// It assumes that the DID has only 1 public key which is true for now but will change later.
    /// This function will then be modified to indicate which key(s) of the DID should be used.
    /// If DID is not registered an error is raised.
    pub fn get_key_detail(did: &Did) -> Result<(KeyDetail, T::BlockNumber), DispatchError> {
        if let Some((current_key_detail, last_modified)) = Dids::<T>::get(did) {
            Ok((current_key_detail, last_modified))
        } else {
            fail!(Error::<T>::DidDoesNotExist)
        }
    }

    /// Verify given signature on the given message with the given DID's only public key.
    /// It assumes that the DID has only 1 public key which is true for now but will change later.
    /// This function will then be modified to indicate which key(s) of the DID should be used.
    /// If DID is not registered an error is raised.
    /// This function is intended to be used by other modules as well to check the signature from a DID.
    pub fn verify_sig_from_did(
        signature: &DidSignature,
        message: &[u8],
        did: &Did,
    ) -> Result<bool, DispatchError> {
        let (current_key_detail, _) = Self::get_key_detail(did)?;
        Self::verify_sig_with_public_key(signature, message, &current_key_detail.public_key)
    }

    /// Verify given signature on the given message with given public key
    pub fn verify_sig_with_public_key(
        signature: &DidSignature,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, DispatchError> {
        Ok(match public_key {
            PublicKey::Sr25519(bytes) => {
                let signature = sr25519::Signature::try_from(
                    signature
                        .as_sr25519_sig_bytes()
                        .map_err(|_| Error::<T>::InvalidSigType)?,
                )
                .map_err(|_| Error::<T>::InvalidSig)?;
                let pk = sr25519::Public(bytes.value.clone());
                signature.verify(message, &pk)
            }
            PublicKey::Ed25519(bytes) => {
                let signature = ed25519::Signature::try_from(
                    signature
                        .as_ed25519_sig_bytes()
                        .map_err(|_| Error::<T>::InvalidSigType)?,
                )
                .map_err(|_| Error::<T>::InvalidSig)?;
                let pk = ed25519::Public(bytes.value.clone());
                signature.verify(message, &pk)
            }
            PublicKey::Secp256k1(bytes) => {
                let signature = ecdsa::Signature::try_from(
                    signature
                        .as_secp256k1_sig_bytes()
                        .map_err(|_| Error::<T>::InvalidSigType)?,
                )
                .map_err(|_| Error::<T>::InvalidSig)?;
                let pk = ecdsa::Public::from_raw(bytes.value.clone());
                signature.verify(message, &pk)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{
        assert_err, assert_ok, impl_outer_origin, parameter_types,
        traits::{OnFinalize, OnInitialize},
        weights::Weight,
    };
    use sp_core::{Pair, H256};
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
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
        type Call = ();
        type Index = u64;
        // XXX: Why is it u64 when in lib.rs its u32
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type DbWeight = ();
        type BlockExecutionWeight = ();
        type ExtrinsicBaseWeight = ();
        type MaximumExtrinsicWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
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

    pub type System = system::Module<Test>;

    /// Changes the block number. Calls `on_finalize` and `on_initialize`
    pub fn run_to_block(n: u64) {
        while System::block_number() < n {
            if System::block_number() > 1 {
                System::on_finalize(System::block_number());
            }
            System::set_block_number(System::block_number() + 1);
            System::on_initialize(System::block_number());
        }
    }

    #[test]
    fn signature_verification() {
        // Check that the signature should be wrapped in correct variant of enum `Signature`.
        // Trying to wrap a Sr25519 signature in a Signature::Ed25519 should fail.
        // Trying to wrap a Ed25519 signature in a Signature::Sr25519 should fail.
        // Not checking for Signature::Secp256k1 as it has a different size
        // XXX: The following test should not have been wrapped in a Externalities-provided environment but
        // ed25519_verify needs it.
        new_test_ext().execute_with(|| {
            let msg = vec![1, 2, 4, 5, 7];

            // The macro checks that a signature verification only passes when sig wrapped in `$correct_sig_type`
            // but fails when wrapped in `$incorrect_sig_type`
            macro_rules! check_sig_verification {
                ( $module:ident, $pk_type:expr, $correct_sig_type:expr, $incorrect_sig_type:expr ) => {{

                    let (pair, _, _) = $module::Pair::generate_with_phrase(None);
                    let pk = $pk_type(Bytes32 { value: pair.public().0 });
                    let sig_bytes = pair.sign(&msg).0;
                    let correct_sig = $correct_sig_type(Bytes64 {value: sig_bytes});

                    // Valid signature wrapped in a correct type works
                    assert!(DIDModule::verify_sig_with_public_key(&correct_sig, &msg, &pk).unwrap());

                    // Valid signature wrapped in an incorrect type does not work
                    let incorrect_sig = $incorrect_sig_type(Bytes64 {value: sig_bytes});
                    assert_err!(
                            DIDModule::verify_sig_with_public_key(&incorrect_sig, &msg, &pk),
                            Error::<Test>::InvalidSigType
                    );
                }}
            }

            check_sig_verification!(sr25519, PublicKey::Sr25519, DidSignature::Sr25519, DidSignature::Ed25519);
            check_sig_verification!(ed25519, PublicKey::Ed25519, DidSignature::Ed25519, DidSignature::Sr25519);
        });
    }

    #[test]
    fn did_creation() {
        // DID must be unique. It must have an acceptable public size
        new_test_ext().execute_with(|| {
            let alice = 10u64;

            let did = [1; DID_BYTE_SIZE];
            let pk = PublicKey::Sr25519(Bytes32 { value: [0; 32] });
            let detail = KeyDetail::new(did.clone(), pk);

            // Add a DID
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            // Try to add the same DID and same key detail again and fail
            assert_err!(
                DIDModule::new(Origin::signed(alice), did.clone(), detail.clone()),
                Error::<Test>::DidAlreadyExists
            );

            // Try to add the same DID again but with different key detail and fail
            let pk = PublicKey::Ed25519(Bytes32 { value: [0; 32] });
            let detail = KeyDetail::new(did.clone(), pk);
            assert_err!(
                DIDModule::new(Origin::signed(alice), did, detail),
                Error::<Test>::DidAlreadyExists
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
            let key_update = KeyUpdate::new(
                did.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk }),
                None,
                2u32,
            );
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair
                    .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                    .0,
            });

            assert_err!(
                DIDModule::update_key(Origin::signed(alice), key_update, sig),
                Error::<Test>::DidDoesNotExist
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
                ( $did:ident, $module:ident, $pk:expr, $sig_type:expr, $sig_bytearray_type:ident ) => {{
                    let (pair_1, _, _) = $module::Pair::generate_with_phrase(None);
                    let pk_1 = pair_1.public().0;

                    let detail = KeyDetail::new($did.clone(), $pk(Bytes32 { value: pk_1 }));

                    // Add a DID
                    assert_ok!(DIDModule::new(
                        Origin::signed(alice),
                        $did.clone(),
                        detail.clone()
                    ));

                    let (current_detail, modified_in_block) = DIDModule::get_key_detail(&$did).unwrap();
                    assert_eq!(current_detail.controller, $did);

                    // Correctly update DID's key.
                    // Prepare a key update
                    let (pair_2, _, _) = $module::Pair::generate_with_phrase(None);
                    let pk_2 = pair_2.public().0;
                    let key_update = KeyUpdate::new(
                        $did.clone(),
                        $pk(Bytes32 { value: pk_2 }),
                        None,
                        modified_in_block as u32,
                    );
                    let sig = $sig_type($sig_bytearray_type {value: pair_1.sign(&StateChange::KeyUpdate(key_update.clone()).encode()).0});

                    // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
                    assert_ok!(DIDModule::update_key(
                        Origin::signed(alice),
                        key_update,
                        sig
                    ));

                    let (current_detail, modified_in_block) = DIDModule::get_key_detail(&$did).unwrap();
                    // Since key update passed None for the controller, it should not change
                    assert_eq!(current_detail.controller, $did);

                    // Maliciously update DID's key.
                    // Signing with the old key (`pair_1`) to update to the new key (`pair_2`)
                    let key_update = KeyUpdate::new(
                        $did.clone(),
                        $pk(Bytes32 { value: pk_1 }),
                        None,
                        modified_in_block as u32,
                    );
                    let sig = $sig_type($sig_bytearray_type {value: pair_1.sign(&StateChange::KeyUpdate(key_update.clone()).encode()).0});

                    assert_err!(
                        DIDModule::update_key(Origin::signed(alice), key_update, sig),
                        Error::<Test>::InvalidSig
                    );

                    // Keep the public key same but update the controller
                    let new_controller = [9; DID_BYTE_SIZE];
                    let key_update = KeyUpdate::new(
                        $did.clone(),
                        $pk(Bytes32 { value: pk_2 }),
                        Some(new_controller),
                        modified_in_block as u32,
                    );
                    let sig = $sig_type($sig_bytearray_type {value: pair_2.sign(&StateChange::KeyUpdate(key_update.clone()).encode()).0});
                    assert_ok!(DIDModule::update_key(
                        Origin::signed(alice),
                        key_update,
                        sig
                    ));

                    // Since key update passed a new controller, it should be reflected
                    let (current_detail, _) = DIDModule::get_key_detail(&$did).unwrap();
                    assert_eq!(current_detail.controller, new_controller);
                }};
            }

            let did = [1; DID_BYTE_SIZE];
            check_key_update!(did, sr25519, PublicKey::Sr25519, DidSignature::Sr25519, Bytes64);

            let did = [2; DID_BYTE_SIZE];
            check_key_update!(did, ed25519, PublicKey::Ed25519, DidSignature::Ed25519, Bytes64);
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
            let mut pk_1: [u8; 33] = [0; 33];
            pk_1.clone_from_slice(pair_1.public().as_ref());
            let detail = KeyDetail::new(did.clone(), PublicKey::Secp256k1(Bytes33 { value: pk_1 }));

            // Add a DID
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();

            // Correctly update DID's key.
            // Prepare a key update
            let (pair_2, _, _) = ecdsa::Pair::generate_with_phrase(None);
            let mut pk_2: [u8; 33] = [0; 33];
            pk_2.clone_from_slice(pair_2.public().as_ref());
            let key_update = KeyUpdate::new(
                did.clone(),
                PublicKey::Secp256k1(Bytes33 { value: pk_2 }),
                None,
                modified_in_block as u32,
            );

            // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
            let value: [u8; 65] = pair_1
                .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                .into();
            let sig = DidSignature::Secp256k1(Bytes65 { value });
            assert_ok!(DIDModule::update_key(
                Origin::signed(alice),
                key_update,
                sig
            ));

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();

            // Maliciously update DID's key.
            // Signing with the old key (`pair_1`) to update to the new key (`pair_2`)
            let key_update = KeyUpdate::new(
                did.clone(),
                PublicKey::Secp256k1(Bytes33 { value: pk_1 }),
                None,
                modified_in_block as u32,
            );
            let value: [u8; 65] = pair_1
                .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                .into();
            let sig = DidSignature::Secp256k1(Bytes65 { value });
            assert_err!(
                DIDModule::update_key(Origin::signed(alice), key_update.clone(), sig),
                Error::<Test>::InvalidSig
            );
        });
    }

    #[test]
    fn did_key_update_replay_protection() {
        // A `KeyUpdate` payload should not be replayable
        // Add a DID with `pk_1`.
        // `pk_1` changes key to `pk_2` and `pk_2` changes key to `pk_3` and `pk_3` changes key back to `pk_1`.
        // It should not be possible to replay `pk_1`'s original message and change key to `pk_2`.

        new_test_ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];

            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0;

            let detail = KeyDetail::new(did.clone(), PublicKey::Sr25519(Bytes32 { value: pk_1 }));

            // Add a DID with key `pk_1`
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            // Block number should increase to 1 as extrinsic is successful
            run_to_block(1);
            assert_eq!(System::block_number(), 1);

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();

            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0;

            // The following key update and signature will be included in a replay attempt to change key to `pk_2` without `pk_1`'s intent
            let key_update_to_be_replayed = KeyUpdate::new(
                did.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_2 }),
                None,
                modified_in_block as u32,
            );

            // Update key from `pk_1` to `pk_2` using `pk_1`'s signature
            let sig_to_be_replayed = DidSignature::Sr25519(Bytes64 {
                value: pair_1
                    .sign(&StateChange::KeyUpdate(key_update_to_be_replayed.clone()).encode())
                    .0,
            });
            assert_ok!(DIDModule::update_key(
                Origin::signed(alice),
                key_update_to_be_replayed.clone(),
                sig_to_be_replayed.clone()
            ));

            // Block number should increase to 2 as extrinsic is successful
            run_to_block(2);
            assert_eq!(System::block_number(), 2);

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();

            let (pair_3, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_3 = pair_3.public().0;

            let key_update = KeyUpdate::new(
                did.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_3 }),
                None,
                modified_in_block as u32,
            );

            // Update key from `pk_2` to `pk_3` using `pk_2`'s signature
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair_2
                    .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                    .0,
            });
            assert_ok!(DIDModule::update_key(
                Origin::signed(alice),
                key_update,
                sig
            ));

            // Block number should increase to 3 as extrinsic is successful
            run_to_block(3);
            assert_eq!(System::block_number(), 3);

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();

            let key_update = KeyUpdate::new(
                did.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_1 }),
                None,
                modified_in_block as u32,
            );

            // Update key from `pk_3` to `pk_1` using `pk_3`'s signature
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair_3
                    .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                    .0,
            });
            assert_ok!(DIDModule::update_key(
                Origin::signed(alice),
                key_update,
                sig
            ));

            // Block number should increase to 4 as extrinsic is successful
            run_to_block(4);
            assert_eq!(System::block_number(), 4);

            // Attempt to replay `pk_1`'s older payload for key update to `pk_2`
            assert_err!(
                DIDModule::update_key(
                    Origin::signed(alice),
                    key_update_to_be_replayed,
                    sig_to_be_replayed
                ),
                Error::<Test>::DifferentBlockNumber
            );
        });
    }

    #[test]
    fn did_remove() {
        // Remove DID. Unregistered Dids cannot be removed.
        // Registered Dids can only be removed by the authorized key
        // Removed Dids can be added again

        new_test_ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];

            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0;
            let to_remove = DidRemoval::new(did.clone(), 2u32);
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair_1
                    .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                    .0,
            });

            // Trying to remove the DID before it was added will fail
            assert_err!(
                DIDModule::remove(Origin::signed(alice), to_remove, sig),
                Error::<Test>::DidDoesNotExist
            );

            // Add a DID
            let detail = KeyDetail::new(did.clone(), PublicKey::Sr25519(Bytes32 { value: pk_1 }));
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();
            // The block number will be non zero as write was successful and will be 1 since its the first extrinsic
            assert_eq!(modified_in_block, 0);

            // A key not controlling the DID but trying to remove the DID should fail
            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0;
            let to_remove = DidRemoval::new(did.clone(), modified_in_block as u32);
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair_2
                    .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                    .0,
            });
            assert_err!(
                DIDModule::remove(Origin::signed(alice), to_remove, sig),
                Error::<Test>::InvalidSig
            );

            // The key controlling the DID should be able to remove the DID
            let to_remove = DidRemoval::new(did.clone(), modified_in_block as u32);
            let sig = DidSignature::Sr25519(Bytes64 {
                value: pair_1
                    .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                    .0,
            });
            assert_ok!(DIDModule::remove(Origin::signed(alice), to_remove, sig));

            // Error as the did has been removed
            assert!(DIDModule::get_key_detail(&did).is_err());

            // A different public key than previous owner of the DID should be able to register the DID
            // Add the same DID but with different public key
            let detail = KeyDetail::new(did.clone(), PublicKey::Sr25519(Bytes32 { value: pk_2 }));
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            // Ok as the did has been written
            assert!(DIDModule::get_key_detail(&did).is_ok());
        });
    }

    // TODO: Add test for events DidAdded, KeyUpdated, DIDRemoval
}
