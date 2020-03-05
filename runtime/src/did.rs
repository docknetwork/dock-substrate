use super::{BlockNumber, DID, DID_BYTE_SIZE};
use codec::{Decode, Encode};
use frame_support::{decl_event, decl_module, decl_storage, dispatch::DispatchResult, traits::Get};
use sp_std::prelude::Vec;

/// The module's configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    //type DIDByteSize: Get<u8>;
}


/// Cryptographic algorithm of public key
/// like `Ed25519VerificationKey2018`, `Secp256k1VerificationKey2018` and `Sr25519VerificationKey2018`
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyType {
    Sr25519,
    Ed25519,
    Secp256k1,
}

impl Default for PublicKeyType {
    fn default() -> Self {
        PublicKeyType::Sr25519
    }
}

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
    pub fn new(controller: DID, public_key_type: PublicKeyType, public_key: Vec<u8>) -> Self {
        KeyDetail {
            controller, public_key, public_key_type
        }
    }
}

/// This struct is passed as an argument while updating the key
/// `cmd` is the command, in case of key update it will be 1.
/// `did` is the DID whose key is being updated.
/// `public_key_type` is new public key type
/// `public_key` the new public key
/// `controller` If provided None, the controller is unchanged. While serializing, use literal "None" when controller is None
/// The last_modified_in_block is the block number when this DID was last modified is present to prevent replay attack
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct KeyUpdate {
    cmd: u8,
    //did: [u8; DID_BYTE_SIZE],
    did: DID,
    public_key_type: PublicKeyType,
    public_key: Vec<u8>,
    controller: Option<DID>,
    last_modified_in_block: BlockNumber,
}

/// This struct is passed as an argument while removing the DID
/// `cmd` is the command, in case of DID removal it is 2.
/// `did` is the DID which is being removed.
/// `last_modified_in_block` is the block number when this DID was last modified. The last modified time is present to prevent replay attack.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct DIDRemoval {
    cmd: u8,
    did: DID,
    last_modified_in_block: BlockNumber,
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
    {
        DIDAdded(Vec<u8>),
        // TODO: Remove event
        DIDAlreadyExists(Vec<u8>),
        DummyEvent(AccountId),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule {
        Dids get(did): map DID => (KeyDetail, T::BlockNumber);
        //Dids: map [u8; 32] => (KeyDetail, T::BlockNumber);
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        //fn new(_origin, did: [u8; DID_BYTE_SIZE], detail: KeyDetail) -> DispatchResult {
        /// Create a new DID.
        /// `did` is the new DID to create. The method will throw exception if `did` is already registered.
        /// `detail` is the details of the key like its type, controller and value
        fn new(_origin, did: DID, detail: KeyDetail) -> DispatchResult {
            if Dids::<T>::exists(did) {
                Self::deposit_event(RawEvent::DIDAlreadyExists(did.to_vec()));
            } else {
                let current_block_no = <system::Module<T>>::block_number();
                Dids::<T>::insert(did, (detail, current_block_no));
                Self::deposit_event(RawEvent::DIDAdded(did.to_vec()));
            }
            Ok(())
        }

        /// `signature` is the signature on the serialized `KeyUpdate`.
        /// The node while processing this extrinsic, should create the above serialized `KeyUpdate`
        /// using the stored data and try to verify the given signature with the stored key.
        pub fn update_key(_origin, key_update: KeyUpdate, signature: Vec<u8>) -> DispatchResult {
            // TODO:
            Ok(())
        }

        /// `to_remove` contains the DID to be removed
        /// `signature` is the signature on the serialized `DIDRemoval`.
        /// The node while processing this extrinsic, should create the above serialized `DIDRemoval` using the stored data and try to verify the given signature with the stored key.
        pub fn remove(_origin, to_remove: DIDRemoval, signature: Vec<u8>) -> DispatchResult {
            // TODO:
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{
        assert_err, assert_ok, impl_outer_origin, parameter_types, weights::Weight,
    };
    use sp_core::H256;
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

    #[test]
    fn new_did_test_case() {
        new_test_ext().execute_with(|| {
            let alice = 10u64;

            let did = [1; DID_BYTE_SIZE];
            let pk = vec![0, 1];
            let detail = KeyDetail::new(did.clone(), PublicKeyType::Sr25519, pk);

            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            // TODO
        });
    }
}
