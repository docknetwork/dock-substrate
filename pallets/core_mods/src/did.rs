use super::{BlockNumber, StateChange};
use crate as dock;
use crate::keys_and_sigs::{PublicKey, SigValue};
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError,
    dispatch::DispatchResult, ensure, fail, traits::Get, weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{Hash, One};

// TODO: This module is getting too big and might be useful to others without all the other stuff in this pallet. Consider making it a separate pallet

/// Size of the Dock DID in bytes
pub const DID_BYTE_SIZE: usize = 32;
/// The type of the Dock DID
pub type Did = [u8; DID_BYTE_SIZE];

/// The module's configuration trait.
pub trait Trait: system::Config {
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
    /// Maximum byte size of URI of an off-chain DID Doc.
    type MaxDidDocUriSize: Get<u32>;
    type DidDocUriPerByteWeight: Get<Weight>;
}

decl_error! {
    /// Error for the DID module.
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
        IncompatSigPubkey,
        /// Signature verification failed while key update or did removal
        InvalidSig,
        DidDocUriTooBig,
        NotAnOffChainDid,
        DidNotOwnedByAccount,
        NoControllerProvided,
        IncompatableVerificationRelation,
        CannotGetDetailForOffChainDid,
        NoKeyProvided,
        IncorrectNonce,
        OnlyControllerCanUpdate,
        NoKeyForDid,
        InsufficientVerificationRelationship
    }
}

/// Different verification relation types specified in the DID spec
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VerRelType {
    Authentication,
    Assertion,
    CapabilityInvocation,
    KeyAgreement,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidKey {
    /// The public key
    key: PublicKey,
    /// The different verification relationships the above key has with the DID.
    ver_rels: Vec<VerRelType>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidSignature {
    /// The DID that created this signature
    did: Did,
    /// The key-id of above DID used to verify the signature
    key_id: u32,
    /// The actual signature
    sig: SigValue,
}

/// Stores details of an on-chain DID
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidDetail<T: Trait> {
    /// The nonce is set to the current block number when a DID is registered. Subsequent updates/removal
    /// should supply a nonce 1 more than the current nonce of the DID and on successful update, the
    /// new nonce is stored with the DID. The reason for starting the nonce with current block number
    /// and not 0 is to prevent replay attack where a signed payload of removed DID is used to perform
    /// replay on the same DID created again as nonce would be reset to 0 for new DIDs.
    nonce: T::BlockNumber,
    /// No of keys added for this DID so far.
    key_counter: u32,
    /// No of controllers added for this DID so far.
    controller_counter: u32,
}

/// Enum describing the storage of the DID
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DidDetailStorage<T: Trait> {
    /// Off-chain DID has no need of nonce as the signature is made on the whole transaction by
    /// the caller account and Substrate takes care of replay protection. This it stores the data
    /// about off-chain DID (URI or anything) and the account that owns it.
    OffChain(T::AccountId, Vec<u8>),
    /// For on-chain DID, all data is stored on the chain.
    OnChain(DidDetail<T>),
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddKeys {
    did: Did,
    keys: Vec<DidKey>,
    nonce: BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveKeys {
    did: Did,
    /// Key ids to remove
    keys: Vec<u32>,
    nonce: BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddControllers {
    did: Did,
    controllers: Vec<Did>,
    nonce: BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveControllers {
    did: Did,
    /// Controllers ids to remove
    controllers: Vec<u32>,
    nonce: BlockNumber,
}

impl<T: Trait> DidDetailStorage<T> {
    pub fn is_on_chain(&self) -> bool {
        match self {
            DidDetailStorage::OnChain(_) => true,
            _ => false,
        }
    }

    pub fn is_off_chain(&self) -> bool {
        !self.is_on_chain()
    }

    pub fn to_on_chain_did_detail(self) -> DidDetail<T> {
        match self {
            DidDetailStorage::OnChain(d) => d,
            _ => panic!("This should never happen"),
        }
    }

    pub fn from_on_chain_detail(
        key_counter: u32,
        controller_counter: u32,
        nonce: T::BlockNumber,
    ) -> Self {
        DidDetailStorage::OnChain(DidDetail {
            key_counter,
            controller_counter,
            nonce,
        })
    }

    pub fn to_off_chain_did_owner_and_uri(self) -> (T::AccountId, Vec<u8>) {
        match self {
            DidDetailStorage::OffChain(owner, uri) => (owner, uri),
            _ => panic!("This should never happen"),
        }
    }
}

impl VerRelType {
    pub fn is_for_signing(&self) -> bool {
        match self {
            VerRelType::KeyAgreement => false,
            _ => true,
        }
    }
}

impl DidKey {
    /// Add all possible verification relationships for a given key
    pub fn new_with_all_relationships(public_key: PublicKey) -> Self {
        let ver_rels = if public_key.can_sign() {
            // We might add more relationships in future but these 3 are all we care about now.
            let mut rels = Vec::with_capacity(3);
            rels.push(VerRelType::Authentication);
            rels.push(VerRelType::Assertion);
            rels.push(VerRelType::CapabilityInvocation);
            rels
        } else {
            // This is true for the current key type, X25519, used for key agreement but might
            // change in future.
            let mut rels = Vec::with_capacity(1);
            rels.push(VerRelType::KeyAgreement);
            rels
        };
        DidKey {
            key: public_key,
            ver_rels,
        }
    }

    /// Checks if the public key has valid verification relationships. Currently, the keys used for
    /// key-agreement cannot (without converting) be used for signing and vice versa
    pub fn is_valid(&self) -> bool {
        if self.key.can_sign() {
            self.ver_rels.iter().all(|v| v.is_for_signing())
        } else {
            self.ver_rels.iter().all(|v| !v.is_for_signing())
        }
    }

    pub fn can_control(&self) -> bool {
        self.key.can_sign()
            && self.ver_rels.iter().any(|v| match v {
                VerRelType::CapabilityInvocation => true,
                _ => false,
            })
    }

    pub fn can_authenticate(&self) -> bool {
        self.key.can_sign()
            && self.ver_rels.iter().any(|v| match v {
                VerRelType::Authentication => true,
                _ => false,
            })
    }

    pub fn can_sign(&self) -> bool {
        self.key.can_sign()
    }

    pub fn for_key_agreement(&self) -> bool {
        self.ver_rels.iter().any(|v| match v {
            VerRelType::KeyAgreement => true,
            _ => false,
        })
    }

    pub fn can_authenticate_or_control(&self) -> bool {
        self.key.can_sign()
            && self.ver_rels.iter().any(|v| match v {
                VerRelType::Authentication | VerRelType::CapabilityInvocation => true,
                _ => false,
            })
    }
}

impl DidSignature {
    fn verify<T: Trait>(
        &self,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, DispatchError> {
        self.sig
            .verify(message, public_key)
            .map_err(|_| Error::<T>::IncompatSigPubkey.into())
    }
}

impl AddKeys {
    pub fn len(&self) -> u32 {
        self.keys.len() as u32
    }
}

impl RemoveKeys {
    pub fn len(&self) -> u32 {
        self.keys.len() as u32
    }
}

impl AddControllers {
    pub fn len(&self) -> u32 {
        self.controllers.len() as u32
    }
}

impl RemoveControllers {
    pub fn len(&self) -> u32 {
        self.controllers.len() as u32
    }
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
/// `last_modified_in_block` is the block number when this DID was last modified. The last modified time is present to prevent replay attack.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidRemoval {
    pub did: Did,
    // TODO: `BlockNumber` should be changed to `T::BlockNumber` to guard against accidental change
    // to BlockNumber type. Will require this struct to be typed
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
        OffChainDidAdded(dock::did::Did, Vec<u8>),
        OffChainDidUpdated(dock::did::Did, Vec<u8>),
        OffChainDidRemoved(dock::did::Did),
        OnChainDidAdded(dock::did::Did),
        DidKeysAdded(dock::did::Did),
        DidControllersAdded(dock::did::Did),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule {
        /// Stores details of off-chain and on-chain DIDs
        pub Dids get(fn did): map hasher(blake2_128_concat) dock::did::Did
            => Option<DidDetailStorage<T>>;
        /// Stores keys of a DID as (DID, counter) -> DidKey. Does not check if the same key is being added multiple times to the same DID.
        pub DidKeys get(fn did_key): double_map hasher(blake2_128_concat) dock::did::Did, hasher(identity) u32 => Option<DidKey>;
        /// Stores controllers of a DID as (DID, counter) -> DID.
        pub DidControllers get(fn did_contoller): double_map hasher(blake2_128_concat) dock::did::Did, hasher(identity) u32 => Option<Did>;
    }
    // TODO: Uncomment and fix genesis format to accept a public key and a DID. Chain spec needs to be updated as well
    /*add_extra_genesis {
        config(dids): Vec<(Did, DidDetail)>;
        build(|slef: &Self| {
            debug_assert!({
                let mut dedup: Vec<&Did> = slef.dids.iter().map(|(d, _kd)| d).collect();
                dedup.sort();
                dedup.dedup();
                slef.dids.len() == dedup.len()
            });
            let block_no: T::BlockNumber = 0u32.into();
            for (did, deet) in slef.dids.iter() {
                Dids::<T>::insert(did, (deet, block_no));
            }
        })
    }*/
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        type Error = Error<T>;

        const MaxDidDocUriSize: u32 = T::MaxDidDocUriSize::get();
        const DidDocUriPerByteWeight: Weight = T::DidDocUriPerByteWeight::get();

        #[weight = T::DbWeight::get().reads_writes(1, 1) + did_doc_uri.len() as u64 * T::DidDocUriPerByteWeight::get()]
        pub fn new_offchain(origin, did: dock::did::Did, did_doc_uri: Vec<u8>) -> DispatchResult {
            // Only `did_owner` can update or remove this DID
            let did_owner = ensure_signed(origin)?;
            ensure!(
                T::MaxDidDocUriSize::get() as usize >= did_doc_uri.len(),
                Error::<T>::DidDocUriTooBig
            );
            Self::new_offchain_(did_owner, did, did_doc_uri)
        }

        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1) + did_doc_uri.len() as u64 * T::DidDocUriPerByteWeight::get()]
        pub fn set_offchain_did_uri(origin, did: dock::did::Did, did_doc_uri: Vec<u8>) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            ensure!(
                T::MaxDidDocUriSize::get() as usize >= did_doc_uri.len(),
                Error::<T>::DidDocUriTooBig
            );
            Self::set_offchain_did_uri_(caller, did, did_doc_uri)
        }

        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_offchain_did(origin, did: dock::did::Did) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            Self::remove_offchain_did_(caller, did)
        }

        /// Create new DID.
        /// If no `keys` are provided, then its a keyless DID and at least 1 `controllers` must be provided.
        /// If any `keys` are provided, but they have an empty `ver_rel`, then its set to a vector with variants
        /// `Authentication`, `Assertion` and `CapabilityInvocation`. This is because keys without any verification
        /// relation won't be usable and these 3 keep the logic most similar to before. Avoiding more
        /// explicit argument to keep the caller's experience simple.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight + controllers.len() as Weight + 1)]
        pub fn new_onchain(origin, did: dock::did::Did, keys: Vec<DidKey>, controllers: Vec<Did>) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::new_onchain_(did, keys, controllers)
        }

        /// Add more keys from DID doc.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        fn add_keys(origin, keys: AddKeys, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(keys.len() > 0, Error::<T>::NoKeyProvided);
            Module::<T>::add_keys_(keys, sig)
        }

        /// Add new controllers
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn add_controllers(origin, controllers: AddControllers, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(controllers.len() > 0, Error::<T>::NoControllerProvided);
            Module::<T>::add_controllers_(controllers, sig)
        }
    }
}

impl<T: Trait> Module<T> {
    fn new_offchain_(caller: T::AccountId, did: Did, did_doc_uri: Vec<u8>) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        Dids::<T>::insert(did, DidDetailStorage::OffChain(caller, did_doc_uri.clone()));
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OffChainDidAdded(did, did_doc_uri)).into(),
        );
        Ok(())
    }

    fn set_offchain_did_uri_(
        caller: T::AccountId,
        did: Did,
        did_doc_uri: Vec<u8>,
    ) -> DispatchResult {
        Self::ensure_offchain_did_be_updated(&caller, &did)?;
        Dids::<T>::insert(did, DidDetailStorage::OffChain(caller, did_doc_uri.clone()));
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OffChainDidUpdated(did, did_doc_uri)).into(),
        );
        Ok(())
    }

    fn remove_offchain_did_(caller: T::AccountId, did: Did) -> DispatchResult {
        Self::ensure_offchain_did_be_updated(&caller, &did)?;
        Dids::<T>::remove(did);
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OffChainDidRemoved(did)).into(),
        );
        Ok(())
    }

    fn new_onchain_(did: Did, keys: Vec<DidKey>, mut controllers: Vec<Did>) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        if keys.is_empty() && controllers.is_empty() {
            fail!(Error::<T>::NoControllerProvided)
        }

        let (keys_to_insert, is_self_controlled) = Self::prepare_keys_to_insert(keys, false)?;

        if is_self_controlled {
            controllers.push(did);
        }

        // Nonce will start from current block number
        let nonce = <system::Module<T>>::block_number();
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                keys_to_insert.len() as u32,
                controllers.len() as u32,
                nonce,
            ),
        );

        for (i, key) in keys_to_insert.into_iter().enumerate() {
            DidKeys::insert(&did, i as u32 + 1, key)
        }
        for (i, cnt) in controllers.into_iter().enumerate() {
            DidControllers::insert(&did, i as u32 + 1, cnt)
        }

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OnChainDidAdded(did)).into(),
        );
        Ok(())
    }

    fn add_keys_(keys: AddKeys, sig: DidSignature) -> DispatchResult {
        let did = &keys.did;
        let signer = &sig.did;

        let did_detail = Self::get_on_chain_did_detail_for_update(did, keys.nonce)?;

        let serz_add_keys = StateChange::AddKeys(keys.clone()).encode();

        ensure!(
            Self::verify_sig_from_controller(did, &serz_add_keys, signer, &sig)?,
            Error::<T>::InvalidSig
        );

        // If DID was not self controlled first, check if it can become by looking
        let was_self_controlled = Self::is_self_controlled(did);
        let (keys_to_insert, is_self_controlled) =
            Self::prepare_keys_to_insert(keys.keys, was_self_controlled)?;

        // Make self controlled if need be
        let mut controller_counter = did_detail.controller_counter;
        if !was_self_controlled && is_self_controlled {
            DidControllers::insert(&did, controller_counter + 1, did);
            controller_counter += 1;
        }

        let old_key_count = did_detail.key_counter;
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                old_key_count + (keys_to_insert.len() as u32),
                controller_counter,
                T::BlockNumber::from(keys.nonce),
            ),
        );

        for (i, key) in keys_to_insert.into_iter().enumerate() {
            DidKeys::insert(did, i as u32 + old_key_count + 1, key)
        }
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidKeysAdded(*did)).into(),
        );
        Ok(())
    }

    fn add_controllers_(controllers: AddControllers, sig: DidSignature) -> DispatchResult {
        let did = &controllers.did;
        let signer = &sig.did;

        let did_detail = Self::get_on_chain_did_detail_for_update(did, controllers.nonce)?;

        let serz_add_controllers = StateChange::AddControllers(controllers.clone()).encode();

        ensure!(
            Self::verify_sig_from_controller(did, &serz_add_controllers, signer, &sig)?,
            Error::<T>::InvalidSig
        );

        let old_cnt_count = did_detail.controller_counter;

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.key_counter,
                old_cnt_count + (controllers.len() as u32),
                T::BlockNumber::from(controllers.nonce),
            ),
        );

        for (i, cnt) in controllers.controllers.into_iter().enumerate() {
            DidControllers::insert(&did, i as u32 + old_cnt_count + 1, cnt)
        }

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidControllersAdded(*did)).into(),
        );

        Ok(())
    }

    /// Prepare `DidKey`s to insert. The DID is assumed to be self controlled as well if there is any key
    /// that is capable of either authenticating or invoking a capability. Returns the keys and whether any
    /// key can make the DID a controller. The following logic is contentious
    fn prepare_keys_to_insert(
        keys: Vec<DidKey>,
        is_self_controlled: bool,
    ) -> Result<(Vec<DidKey>, bool), DispatchError> {
        let mut keys_to_insert = Vec::with_capacity(keys.len());
        let mut is_self_controlled = is_self_controlled;
        for key in keys {
            if key.ver_rels.is_empty() {
                is_self_controlled = is_self_controlled || key.can_sign();
                keys_to_insert.push(DidKey::new_with_all_relationships(key.key));
            } else {
                if !key.is_valid() {
                    fail!(Error::<T>::IncompatableVerificationRelation)
                }
                if !is_self_controlled && key.can_control() {
                    is_self_controlled = true;
                }
                keys_to_insert.push(key);
            }
        }
        Ok((keys_to_insert, is_self_controlled))
    }

    /// Throw an error if `controller` is not the controller of `controlled`
    pub fn ensure_controller(controlled: &Did, controller: &Did) -> DispatchResult {
        if !Self::is_controller(controlled, controller) {
            fail!(Error::<T>::OnlyControllerCanUpdate)
        }
        Ok(())
    }

    /// Is `controller` the controller of `controlled`
    pub fn is_controller(controlled: &Did, controller: &Did) -> bool {
        let mut found = false;
        for (_, val) in DidControllers::iter_prefix(controlled) {
            if val == *controller {
                found = true;
                break;
            }
        }
        found
    }

    /// Returns true if `did` controls itself, else false.
    pub fn is_self_controlled(did: &Did) -> bool {
        Self::is_controller(did, did)
    }

    /// Return `did`'s key with id `key_id` only if it can control otherwise throw error
    pub fn get_key_for_control(did: &Did, key_id: u32) -> Result<PublicKey, DispatchError> {
        if let Some(did_key) = DidKeys::get(did, key_id) {
            if did_key.can_control() {
                Ok(did_key.key)
            } else {
                fail!(Error::<T>::InsufficientVerificationRelationship)
            }
        } else {
            fail!(Error::<T>::NoKeyForDid)
        }
    }

    /// Verify a `DidSignature` created by `signer` only if `signer` is a controller of `did` and has an
    /// appropriate key. To update a DID (add/remove keys, add/remove controllers), the updater must be a
    /// controller of the DID and must have a key with `CapabilityInvocation` verification relationship
    pub fn verify_sig_from_controller(
        did: &Did,
        msg: &[u8],
        signer: &Did,
        sig: &DidSignature,
    ) -> Result<bool, DispatchError> {
        Self::ensure_controller(did, signer)?;
        let signer_pubkey = Self::get_key_for_control(signer, sig.key_id)?;

        sig.verify::<T>(msg, &signer_pubkey)
    }

    /// Get DID detail for on-chain DID if given nonce is correct, i.e. 1 more than the current nonce.
    /// This is used for update
    pub fn get_on_chain_did_detail_for_update(
        did: &Did,
        new_nonce: u32,
    ) -> Result<DidDetail<T>, DispatchError> {
        let did_detail_storage = Self::get_on_chain_did_detail(did)?;
        let new_nonce = T::BlockNumber::from(new_nonce);
        if new_nonce != (did_detail_storage.nonce + T::BlockNumber::one()) {
            fail!(Error::<T>::IncorrectNonce)
        }
        Ok(did_detail_storage)
    }

    /// Get DID detail of an on-chain DID. Throws error if DID does not exist or is off-chain.
    pub fn get_on_chain_did_detail(did: &Did) -> Result<DidDetail<T>, DispatchError> {
        if let Some(did_detail_storage) = Dids::<T>::get(did) {
            if did_detail_storage.is_off_chain() {
                fail!(Error::<T>::CannotGetDetailForOffChainDid)
            }
            Ok(did_detail_storage.to_on_chain_did_detail())
        } else {
            fail!(Error::<T>::DidDoesNotExist)
        }
    }

    pub fn is_onchain_did(did: &Did) -> Result<bool, Error<T>> {
        if let Some(did_detail_storage) = Dids::<T>::get(did) {
            Ok(did_detail_storage.is_on_chain())
        } else {
            fail!(Error::<T>::DidDoesNotExist)
        }
    }

    pub fn is_offchain_did(did: &Did) -> Result<bool, Error<T>> {
        Self::is_onchain_did(did).map(|r| !r)
    }

    /// Check that given DID is off-chain and owned by the caller
    pub fn ensure_offchain_did_be_updated(
        caller: &T::AccountId,
        did: &Did,
    ) -> Result<(), DispatchError> {
        if let Some(did_detail_storage) = Dids::<T>::get(did) {
            match did_detail_storage {
                DidDetailStorage::OnChain(_) => fail!(Error::<T>::NotAnOffChainDid),
                DidDetailStorage::OffChain(account, _) => {
                    ensure!(account == *caller, Error::<T>::DidNotOwnedByAccount);
                    Ok(())
                }
            }
        } else {
            fail!(Error::<T>::DidDoesNotExist)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keys_and_sigs::get_secp256k1_keypair;
    use crate::test_common::*;
    use crate::util::{Bytes64, Bytes65};
    use frame_support::{assert_err, assert_ok};
    use sp_core::{ed25519, sr25519, Pair};

    fn not_key_agreement(key: &DidKey) {
        assert!(key.can_sign());
        assert!(key.can_authenticate());
        assert!(key.can_control());
        assert!(key.can_authenticate_or_control());
        assert!(!key.for_key_agreement());
    }

    fn only_key_agreement(key: &DidKey) {
        assert!(!key.can_sign());
        assert!(!key.can_authenticate());
        assert!(!key.can_control());
        assert!(!key.can_authenticate_or_control());
        assert!(key.for_key_agreement());
    }

    fn check_did_detail(did: &Did, key_counter: u32, controller_counter: u32, nonce: BlockNumber) {
        let did_detail = DIDModule::get_on_chain_did_detail(did).unwrap();
        assert_eq!(did_detail.key_counter, key_counter);
        assert_eq!(did_detail.controller_counter, controller_counter);
        assert_eq!(
            did_detail.nonce,
            <Test as system::Config>::BlockNumber::from(nonce)
        );
    }

    #[test]
    fn off_chain_did() {
        // Creating an off-chain DID
        ext().execute_with(|| {
            let alice = 1u64;
            let did = [5; DID_BYTE_SIZE];
            let uri = vec![129; 60];
            let too_big_uri = vec![129; 300];

            assert_err!(
                DIDModule::new_offchain(Origin::signed(alice), did.clone(), too_big_uri.clone()),
                Error::<Test>::DidDocUriTooBig
            );

            // Add a DID
            assert_ok!(DIDModule::new_offchain(
                Origin::signed(alice),
                did.clone(),
                uri.clone()
            ));

            // Try to add the same DID and same uri again and fail
            assert_err!(
                DIDModule::new_offchain(Origin::signed(alice), did.clone(), uri.clone()),
                Error::<Test>::DidAlreadyExists
            );

            // Try to add the same DID and different uri and fail
            let uri_1 = vec![205; 99];
            assert_err!(
                DIDModule::new_offchain(Origin::signed(alice), did, uri_1),
                Error::<Test>::DidAlreadyExists
            );

            assert!(DIDModule::is_offchain_did(&did).unwrap());
            assert!(!DIDModule::is_onchain_did(&did).unwrap());

            assert_err!(
                DIDModule::get_on_chain_did_detail(&did),
                Error::<Test>::CannotGetDetailForOffChainDid
            );

            let did_detail_storage = Dids::<Test>::get(&did).unwrap();
            let (owner, fetched_uri) = did_detail_storage.to_off_chain_did_owner_and_uri();
            assert_eq!(owner, alice);
            assert_eq!(fetched_uri, uri);

            let bob = 2u64;
            let new_uri = vec![235; 99];
            assert_err!(
                DIDModule::set_offchain_did_uri(Origin::signed(bob), did, new_uri.clone()),
                Error::<Test>::DidNotOwnedByAccount
            );

            assert_err!(
                DIDModule::set_offchain_did_uri(Origin::signed(alice), did.clone(), too_big_uri),
                Error::<Test>::DidDocUriTooBig
            );

            assert_ok!(DIDModule::set_offchain_did_uri(
                Origin::signed(alice),
                did.clone(),
                new_uri.clone()
            ));
            let did_detail_storage = Dids::<Test>::get(&did).unwrap();
            let (_, fetched_uri) = did_detail_storage.to_off_chain_did_owner_and_uri();
            assert_eq!(fetched_uri, new_uri);

            assert_err!(
                DIDModule::remove_offchain_did(Origin::signed(bob), did),
                Error::<Test>::DidNotOwnedByAccount
            );

            assert_ok!(DIDModule::remove_offchain_did(Origin::signed(alice), did));
            assert!(Dids::<Test>::get(&did).is_none());
        });
    }

    #[test]
    fn on_chain_keyless_did_creation() {
        // Creating an on-chain DID with no keys but only controllers, i.e. DID is controlled by other DIDs
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [5; DID_BYTE_SIZE];
            let did_2 = [3; DID_BYTE_SIZE];
            let controller_1 = [7; DID_BYTE_SIZE];
            let controller_2 = [20; DID_BYTE_SIZE];

            assert_err!(
                DIDModule::new_onchain(Origin::signed(alice), did_1.clone(), vec![], vec![]),
                Error::<Test>::NoControllerProvided
            );

            run_to_block(20);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![],
                vec![controller_1]
            ));

            assert!(!DIDModule::is_offchain_did(&did_1).unwrap());
            assert!(DIDModule::is_onchain_did(&did_1).unwrap());

            assert!(!DIDModule::is_self_controlled(&did_1));
            assert!(!DIDModule::is_controller(&did_1, &controller_2));
            assert!(DIDModule::is_controller(&did_1, &controller_1));

            check_did_detail(&did_1, 0, 1, 20);

            assert_err!(
                DIDModule::new_onchain(
                    Origin::signed(alice),
                    did_1.clone(),
                    vec![],
                    vec![controller_1]
                ),
                Error::<Test>::DidAlreadyExists
            );

            run_to_block(55);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![],
                vec![did_1, controller_1, controller_2]
            ));

            assert!(!DIDModule::is_offchain_did(&did_2).unwrap());
            assert!(DIDModule::is_onchain_did(&did_2).unwrap());

            assert!(!DIDModule::is_self_controlled(&did_2));
            assert!(DIDModule::is_controller(&did_2, &did_1));
            assert!(DIDModule::is_controller(&did_2, &controller_1));
            assert!(DIDModule::is_controller(&did_2, &controller_2));

            check_did_detail(&did_2, 0, 3, 55);
        });
    }

    #[test]
    fn on_chain_keyed_did_creation_with_self_control() {
        // Creating an on-chain DID with keys but no other controllers
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [5; DID_BYTE_SIZE];
            let did_2 = [4; DID_BYTE_SIZE];
            let did_3 = [3; DID_BYTE_SIZE];
            let did_4 = [2; DID_BYTE_SIZE];
            let did_5 = [11; DID_BYTE_SIZE];
            let did_6 = [111; DID_BYTE_SIZE];
            let did_7 = [71; DID_BYTE_SIZE];
            let did_8 = [82; DID_BYTE_SIZE];
            let did_9 = [83; DID_BYTE_SIZE];
            let did_10 = [84; DID_BYTE_SIZE];
            let did_11 = [85; DID_BYTE_SIZE];

            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;
            let (_, pk_secp) = get_secp256k1_keypair(&[21; 32]);

            run_to_block(5);

            // DID controls itself when adding keys capable of signing without specifying any verificatiion relationship
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![]
                }],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 5);

            let key_1 = DidKeys::get(&did_1, 1).unwrap();
            not_key_agreement(&key_1);

            run_to_block(6);

            // DID controls itself and specifies another controller as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: vec![]
                }],
                vec![did_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 2, 6);

            let key_2 = DidKeys::get(&did_2, 1).unwrap();
            not_key_agreement(&key_2);

            run_to_block(7);

            // DID controls itself and specifies multiple another controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: vec![]
                }],
                vec![did_1, did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 3, 7);

            let key_3 = DidKeys::get(&did_3, 1).unwrap();
            not_key_agreement(&key_3);

            run_to_block(8);

            // Adding x25519 key does not make the DID self controlled
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: vec![]
                }],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 0, 8);

            let key_4 = DidKeys::get(&did_4, 1).unwrap();
            only_key_agreement(&key_4);

            // x25519 key cannot be added for incompatible relationship types
            for vr in vec![
                VerRelType::Authentication,
                VerRelType::Assertion,
                VerRelType::CapabilityInvocation,
            ] {
                assert_err!(
                    DIDModule::new_onchain(
                        Origin::signed(alice),
                        did_5.clone(),
                        vec![DidKey {
                            key: PublicKey::x25519(pk_ed),
                            ver_rels: vec![vr]
                        }],
                        vec![]
                    ),
                    Error::<Test>::IncompatableVerificationRelation
                );
            }

            for pk in vec![
                PublicKey::sr25519(pk_sr),
                PublicKey::ed25519(pk_ed),
                pk_secp.clone(),
            ] {
                assert_err!(
                    DIDModule::new_onchain(
                        Origin::signed(alice),
                        did_5.clone(),
                        vec![DidKey {
                            key: pk,
                            ver_rels: vec![VerRelType::KeyAgreement]
                        }],
                        vec![]
                    ),
                    Error::<Test>::IncompatableVerificationRelation
                );
            }

            run_to_block(10);

            // Add single key and specify relationship as `capabilityInvocation`
            for (did, pk) in vec![
                (did_5, PublicKey::sr25519(pk_sr)),
                (did_6, PublicKey::ed25519(pk_ed)),
                (did_7, pk_secp.clone()),
            ] {
                assert_ok!(DIDModule::new_onchain(
                    Origin::signed(alice),
                    did.clone(),
                    vec![DidKey {
                        key: pk,
                        ver_rels: vec![VerRelType::CapabilityInvocation]
                    }],
                    vec![]
                ));
                assert!(DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, 1).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_authenticate());
                assert!(key.can_control());
                assert!(key.can_authenticate_or_control());
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 1, 10);
            }

            run_to_block(13);

            // Add single key with single relationship and but do not specify relationship as `capabilityInvocation`
            for (did, pk, vr) in vec![
                (
                    [72; DID_BYTE_SIZE],
                    PublicKey::sr25519(pk_sr),
                    VerRelType::Assertion,
                ),
                (
                    [73; DID_BYTE_SIZE],
                    PublicKey::ed25519(pk_ed),
                    VerRelType::Assertion,
                ),
                ([74; DID_BYTE_SIZE], pk_secp.clone(), VerRelType::Assertion),
                (
                    [75; DID_BYTE_SIZE],
                    PublicKey::sr25519(pk_sr),
                    VerRelType::Authentication,
                ),
                (
                    [76; DID_BYTE_SIZE],
                    PublicKey::ed25519(pk_ed),
                    VerRelType::Authentication,
                ),
                (
                    [77; DID_BYTE_SIZE],
                    pk_secp.clone(),
                    VerRelType::Authentication,
                ),
            ] {
                assert_ok!(DIDModule::new_onchain(
                    Origin::signed(alice),
                    did.clone(),
                    vec![DidKey {
                        key: pk,
                        ver_rels: vec![vr.clone()]
                    }],
                    vec![]
                ));
                assert!(!DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, 1).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_control());
                if vr == VerRelType::Authentication {
                    assert!(key.can_authenticate());
                    assert!(key.can_authenticate_or_control());
                }
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 0, 13);
            }

            run_to_block(19);

            // Add single key, specify multiple relationships and but do not specify relationship as `capabilityInvocation`
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_8.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: vec![VerRelType::Authentication, VerRelType::Assertion]
                }],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_8));
            let key_8 = DidKeys::get(&did_8, 1).unwrap();
            assert!(key_8.can_sign());
            assert!(key_8.can_authenticate());
            assert!(!key_8.can_control());
            check_did_detail(&did_8, 1, 0, 19);

            run_to_block(20);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_9.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Authentication]
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: vec![VerRelType::Assertion]
                    },
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: vec![VerRelType::Assertion, VerRelType::Authentication]
                    },
                ],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_9));
            let key_9_1 = DidKeys::get(&did_9, 1).unwrap();
            assert!(key_9_1.can_sign());
            assert!(key_9_1.can_authenticate());
            assert!(!key_9_1.can_control());
            let key_9_2 = DidKeys::get(&did_9, 2).unwrap();
            assert!(key_9_2.can_sign());
            assert!(!key_9_2.can_authenticate());
            assert!(!key_9_2.can_control());
            let key_9_3 = DidKeys::get(&did_9, 3).unwrap();
            assert!(key_9_3.can_sign());
            assert!(key_9_3.can_authenticate());
            assert!(!key_9_3.can_control());
            check_did_detail(&did_9, 3, 0, 20);

            run_to_block(22);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_10.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Authentication, VerRelType::Assertion]
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: vec![VerRelType::Assertion]
                    },
                    DidKey {
                        key: pk_secp,
                        ver_rels: vec![VerRelType::CapabilityInvocation]
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_10));
            let key_10_1 = DidKeys::get(&did_10, 1).unwrap();
            assert!(key_10_1.can_sign());
            assert!(key_10_1.can_authenticate());
            assert!(!key_10_1.can_control());
            let key_10_2 = DidKeys::get(&did_10, 2).unwrap();
            assert!(key_10_2.can_sign());
            assert!(!key_10_2.can_authenticate());
            assert!(!key_10_2.can_control());
            let key_10_3 = DidKeys::get(&did_10, 3).unwrap();
            assert!(key_10_3.can_sign());
            assert!(!key_10_3.can_authenticate());
            assert!(key_10_3.can_control());
            check_did_detail(&did_10, 3, 1, 22);

            run_to_block(23);

            // Add multiple keys, specify multiple relationships and other controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_11.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Authentication, VerRelType::Assertion]
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: vec![VerRelType::CapabilityInvocation]
                    },
                ],
                vec![did_1, did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_11));
            let key_11_1 = DidKeys::get(&did_11, 1).unwrap();
            assert!(key_11_1.can_sign());
            assert!(key_11_1.can_authenticate());
            assert!(!key_11_1.can_control());
            let key_11_2 = DidKeys::get(&did_11, 2).unwrap();
            assert!(key_11_2.can_sign());
            assert!(!key_11_2.can_authenticate());
            assert!(key_11_2.can_control());
            check_did_detail(&did_11, 2, 3, 23);
        });
    }

    #[test]
    fn on_chain_keyed_did_creation_with_and_without_self_control() {
        // Creating an on-chain DID with keys and other controllers
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];
            let did_3 = [54; DID_BYTE_SIZE];
            let did_4 = [55; DID_BYTE_SIZE];
            let did_5 = [56; DID_BYTE_SIZE];
            let did_6 = [57; DID_BYTE_SIZE];

            let controller_1 = [61; DID_BYTE_SIZE];
            let controller_2 = [62; DID_BYTE_SIZE];
            let controller_3 = [63; DID_BYTE_SIZE];
            let controller_4 = [64; DID_BYTE_SIZE];

            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;
            let (_, pk_secp) = get_secp256k1_keypair(&[21; 32]);

            run_to_block(10);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![VerRelType::Authentication]
                }],
                vec![controller_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_1));
            assert!(DIDModule::is_controller(&did_1, &controller_1));
            check_did_detail(&did_1, 1, 1, 10);

            run_to_block(11);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: vec![VerRelType::Assertion]
                }],
                vec![controller_2]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            assert!(DIDModule::is_controller(&did_2, &controller_2));
            check_did_detail(&did_2, 1, 1, 11);

            run_to_block(12);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: vec![VerRelType::KeyAgreement]
                }],
                vec![controller_3]
            ));
            assert!(!DIDModule::is_self_controlled(&did_3));
            assert!(DIDModule::is_controller(&did_3, &controller_3));
            check_did_detail(&did_3, 1, 1, 12);

            run_to_block(13);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: vec![VerRelType::Authentication]
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Assertion]
                    }
                ],
                vec![controller_4]
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            assert!(DIDModule::is_controller(&did_4, &controller_4));
            check_did_detail(&did_4, 2, 1, 13);

            run_to_block(14);

            // DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_5.clone(),
                vec![
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: vec![
                            VerRelType::Authentication,
                            VerRelType::CapabilityInvocation
                        ]
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Assertion]
                    }
                ],
                vec![controller_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_5));
            assert!(DIDModule::is_controller(&did_5, &controller_1));
            check_did_detail(&did_5, 2, 2, 14);

            run_to_block(15);

            // DID has 2 keys to control itself and another DID
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_6.clone(),
                vec![
                    DidKey {
                        key: pk_secp,
                        ver_rels: vec![
                            VerRelType::Authentication,
                            VerRelType::CapabilityInvocation
                        ]
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Assertion, VerRelType::CapabilityInvocation]
                    }
                ],
                vec![controller_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_6));
            assert!(DIDModule::is_controller(&did_6, &controller_1));
            check_did_detail(&did_6, 2, 2, 15);
        });
    }

    #[test]
    fn add_keys_to_did() {
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];

            // Add keys to a DID that has not been registered yet should fail
            let (pair_sr_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr_1 = pair_sr_1.public().0;
            let (pair_sr_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr_2 = pair_sr_2.public().0;
            let (pair_ed_1, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed_1 = pair_ed_1.public().0;
            let (pair_ed_2, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed_2 = pair_ed_2.public().0;
            let (_, pk_secp_1) = get_secp256k1_keypair(&[21; 32]);
            let (_, pk_secp_2) = get_secp256k1_keypair(&[22; 32]);

            run_to_block(5);

            // At least one key must be provided
            let add_keys = AddKeys {
                did: did_1.clone(),
                keys: vec![],
                nonce: 5,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::NoKeyProvided
            );

            // DID must exist for keys to be added
            let add_keys = AddKeys {
                did: did_1.clone(),
                keys: vec![DidKey {
                    key: PublicKey::sr25519(pk_sr_1),
                    ver_rels: vec![],
                }],
                nonce: 5,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::DidDoesNotExist
            );

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr_1),
                        ver_rels: vec![]
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr_2),
                        ver_rels: vec![]
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_2),
                        ver_rels: vec![VerRelType::Authentication]
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 3, 1, 5);

            run_to_block(7);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed_1),
                    ver_rels: vec![VerRelType::Authentication]
                }],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 7);

            run_to_block(10);

            // Since did_2 does not control itself, it cannot add keys to itself
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: vec![],
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed_1);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::OnlyControllerCanUpdate
            );

            // Nonce should be 1 greater than existing 7, i.e. 8
            for nonce in vec![6, 7, 9, 10, 100, 10245] {
                let add_keys = AddKeys {
                    did: did_2.clone(),
                    keys: vec![DidKey {
                        key: pk_secp_1.clone(),
                        ver_rels: vec![],
                    }],
                    nonce,
                };
                let sig =
                    SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
                assert_err!(
                    DIDModule::add_keys(
                        Origin::signed(alice),
                        add_keys,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1,
                            sig
                        }
                    ),
                    Error::<Test>::IncorrectNonce
                );
            }

            // Invalid signature should fail
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: vec![],
                }],
                nonce: 7 + 1,
            };
            // Using some arbitrary bytes as signature
            let sig = SigValue::Sr25519(Bytes64 { value: [109; 64] });
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::InvalidSig
            );

            // Using wrong key_id should fail
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: vec![],
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 2,
                        sig
                    }
                ),
                Error::<Test>::InvalidSig
            );

            // Using wrong key type should fail
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: vec![VerRelType::KeyAgreement],
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::IncompatableVerificationRelation
            );

            // Add x25519 key
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: PublicKey::x25519(pk_ed_1),
                    ver_rels: vec![VerRelType::KeyAgreement],
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1,
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 2, 1, 8);

            // Add many keys
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![
                    DidKey {
                        key: PublicKey::x25519(pk_sr_2),
                        ver_rels: vec![VerRelType::KeyAgreement],
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: vec![VerRelType::Assertion],
                    },
                    DidKey {
                        key: pk_secp_2,
                        ver_rels: vec![VerRelType::Authentication, VerRelType::Assertion],
                    },
                ],
                nonce: 8 + 1,
            };

            // Controller uses a key without the capability to update DID
            let sig =
                SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed_2);
            assert_err!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys.clone(),
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 3,
                        sig
                    }
                ),
                Error::<Test>::InsufficientVerificationRelationship
            );

            // Controller uses the correct key
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_2);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 2,
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 5, 1, 9);
        });
    }

    #[test]
    fn add_controllers_to_did() {
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];
            let did_3 = [53; DID_BYTE_SIZE];
            let did_4 = [54; DID_BYTE_SIZE];
            let did_5 = [55; DID_BYTE_SIZE];

            // Add keys to a DID that has not been registered yet should fail
            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;
            let (sk_secp_1, pk_secp_1) = get_secp256k1_keypair(&[21; 32]);
            let (sk_secp_2, pk_secp_2) = get_secp256k1_keypair(&[22; 32]);

            run_to_block(5);

            // At least one controller must be provided
            let add_controllers = AddControllers {
                did: did_1.clone(),
                controllers: vec![],
                nonce: 5,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &pair_sr,
            );
            assert_err!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::NoControllerProvided
            );

            // DID must exist for controllers to be added
            let add_controllers = AddControllers {
                did: did_1.clone(),
                controllers: vec![did_2],
                nonce: 5,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &pair_sr,
            );
            assert_err!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::DidDoesNotExist
            );

            // This DID controls itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey {
                        key: pk_secp_1.clone(),
                        ver_rels: vec![]
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: vec![VerRelType::Authentication]
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 2, 1, 5);

            run_to_block(6);

            // This DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp_2.clone(),
                    ver_rels: vec![]
                },],
                vec![did_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_3, 1, 2, 6);

            run_to_block(10);
            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![VerRelType::Authentication]
                }],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 10);

            run_to_block(15);

            // Since did_2 does not control itself, it cannot controller to itself
            let add_controllers = AddControllers {
                did: did_2.clone(),
                controllers: vec![did_3],
                nonce: 10 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &pair_sr,
            );
            assert_err!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::OnlyControllerCanUpdate
            );

            // Nonce should be 1 greater than existing 10, i.e. 11
            for nonce in vec![8, 9, 10, 12, 25000] {
                let add_controllers = AddControllers {
                    did: did_2.clone(),
                    controllers: vec![did_3],
                    nonce,
                };
                let sig = SigValue::secp256k1(
                    &StateChange::AddControllers(add_controllers.clone()).encode(),
                    &sk_secp_1,
                );
                assert_err!(
                    DIDModule::add_controllers(
                        Origin::signed(alice),
                        add_controllers,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1,
                            sig
                        }
                    ),
                    Error::<Test>::IncorrectNonce
                );
            }

            // Invalid signature should fail
            let add_controllers = AddControllers {
                did: did_2.clone(),
                controllers: vec![did_3],
                nonce: 10 + 1,
            };
            let sig = SigValue::Secp256k1(Bytes65 { value: [35; 65] });
            assert_err!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers.clone(),
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1,
                        sig
                    }
                ),
                Error::<Test>::InvalidSig
            );

            // Valid signature should work
            let sig = SigValue::secp256k1(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &sk_secp_1,
            );
            assert_ok!(DIDModule::add_controllers(
                Origin::signed(alice),
                add_controllers,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1,
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 2, 11);

            run_to_block(15);

            // Add many controllers
            let add_controllers = AddControllers {
                did: did_2.clone(),
                controllers: vec![did_4, did_5],
                nonce: 11 + 1,
            };
            let sig = SigValue::secp256k1(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &sk_secp_2,
            );
            assert_ok!(DIDModule::add_controllers(
                Origin::signed(alice),
                add_controllers,
                DidSignature {
                    did: did_3.clone(),
                    key_id: 1,
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 4, 12);
        });
    }

    #[test]
    fn becoming_controller() {
        // A DID that was not a controller of its DID during creation can become one
        // when either a key is added with `capabilityInvocation`
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];

            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;
            let (sk_secp, pk_secp) = get_secp256k1_keypair(&[21; 32]);

            run_to_block(5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![]
                },],
                vec![]
            ));

            run_to_block(10);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: vec![VerRelType::KeyAgreement]
                },],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 10);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: vec![VerRelType::Assertion],
                }],
                nonce: 10 + 1,
            };
            let sig = SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1,
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 2, 1, 11);

            run_to_block(20);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: vec![VerRelType::CapabilityInvocation],
                }],
                nonce: 11 + 1,
            };
            let sig = SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1,
                    sig
                }
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 3, 2, 12);
        });

        // TODO:
    }

    #[test]
    fn any_controller_can_update() {
        // For a DID with many controllers, any controller can update it by adding keys, controllers.
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];
            let did_3 = [53; DID_BYTE_SIZE];
            let did_4 = [54; DID_BYTE_SIZE];

            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;
            let (_, pk_secp) = get_secp256k1_keypair(&[21; 32]);

            run_to_block(5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: vec![]
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![]
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: vec![]
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 1, 5);

            run_to_block(7);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: vec![]
                },],
                vec![did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 2, 7);

            run_to_block(14);

            let add_controllers = AddControllers {
                did: did_4.clone(),
                controllers: vec![did_1],
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(add_controllers.clone()).encode(),
                &pair_sr,
            );
            assert_ok!(DIDModule::add_controllers(
                Origin::signed(alice),
                add_controllers,
                DidSignature {
                    did: did_2.clone(),
                    key_id: 1,
                    sig
                }
            ));
            check_did_detail(&did_4, 1, 3, 8);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_4.clone(),
                keys: vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: vec![],
                }],
                nonce: 8 + 1,
            };
            let sig = SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1,
                    sig
                }
            ));
        });
    }

    #[test]
    fn any_controller_can_remove() {
        // For a DID with many controllers, any controller can remove it.
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];

            // TODO:
        });
    }

    /*#[test]
    fn did_remove() {
        // Remove DID. Unregistered Dids cannot be removed.
        // Registered Dids can only be removed by the authorized key
        // Removed Dids can be added again

        ext().execute_with(|| {
            let alice = 100u64;

            let did = [1; DID_BYTE_SIZE];

            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0;
            let to_remove = DidRemoval::new(did.clone(), 2u32);
            let sig = SigValue::Sr25519(Bytes64 {
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
            println!("remove pk:{:?}", pk_1.to_vec());
            let detail = KeyDetail::new(did.clone(), PublicKey::Sr25519(Bytes32 { value: pk_1 }));
            assert_ok!(DIDModule::new(
                Origin::signed(alice),
                did.clone(),
                detail.clone()
            ));

            let (_, modified_in_block) = DIDModule::get_key_detail(&did).unwrap();
            // The block number will be non zero as write was successful and will be 1 since its the first extrinsic
            assert_eq!(modified_in_block, 1);

            // A key not controlling the DID but trying to remove the DID should fail
            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0;
            let to_remove = DidRemoval::new(did.clone(), modified_in_block as u32);
            let sig = SigValue::Sr25519(Bytes64 {
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
            let sig_value = pair_1
                .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                .0;
            println!("remove sig value:{:?}", sig_value.to_vec());
            let sig = SigValue::Sr25519(Bytes64 { value: sig_value });
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
    }*/

    // TODO: Add test for events DidAdded, KeyUpdated, DIDRemoval
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use crate::benchmark_utils::{
        get_data_for_did_removal, get_data_for_key_update, get_data_for_sig_ver, DID_DATA_SIZE,
    };
    use frame_benchmarking::{account, benchmarks};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const SEED: u32 = 0;
    const MAX_USER_INDEX: u32 = 1000;

    benchmarks! {
        _ {
            // Origin
            let u in 1 .. MAX_USER_INDEX => ();
            // DID
            let d in 0 .. 255 => ();
            // Key
            let k in 0 .. 255 => ();
            // Key type
            let t in 0 .. 2 => ();
            // index into hardcoded public key and signature data
            // Does not compile without the cast to u32
            let i in 0 .. (DID_DATA_SIZE - 1) as u32 => ();
        }

        new {
            let u in ...;
            let d in ...;
            let k in ...;
            let t in ...;

            let caller = account("caller", u, SEED);
            let did = [d as u8; DID_BYTE_SIZE];
            let pk = match t {
                n if n == 0 => PublicKey::Sr25519(Bytes32 { value: [k as u8; 32] }),
                n if n == 1 => PublicKey::Ed25519(Bytes32 { value: [k as u8; 32] }),
                _ => PublicKey::Secp256k1(Bytes33 { value: [k as u8; 33] }),
            };

        }: _(RawOrigin::Signed(caller), did, KeyDetail {controller: did, public_key: pk})
        verify {
            let value = Dids::<T>::get(did);
            assert!(value.is_some());
        }

        // Using hardcoded data for keys and signatures and key generation and signing is not
        // available with benchmarks

        key_update_sr25519 {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(0, i as usize);
            let detail = KeyDetail::new(did.clone(), pk_1);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            let key_update = KeyUpdate::new(
                did.clone(),
                pk_2,
                None,
                n,
            );
        }: update_key(RawOrigin::Signed(caller), key_update, sig)
        verify {
            let value = Dids::<T>::get(did);
            assert!(value.is_some());
        }

        key_update_ed25519 {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(1, i as usize);
            let detail = KeyDetail::new(did.clone(), pk_1);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            let key_update = KeyUpdate::new(
                did.clone(),
                pk_2,
                None,
                n,
            );
        }: update_key(RawOrigin::Signed(caller), key_update, sig)
        verify {
            let value = Dids::<T>::get(did);
            assert!(value.is_some());
        }

        key_update_secp256k1 {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(2, i as usize);
            let detail = KeyDetail::new(did.clone(), pk_1);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            let key_update = KeyUpdate::new(
                did.clone(),
                pk_2,
                None,
                n,
            );
        }: update_key(RawOrigin::Signed(caller), key_update, sig)
        verify {
            let value = Dids::<T>::get(did);
            assert!(value.is_some());
        }

        remove_sr25519 {
            let u in ...;
            let i in ...;

            let caller = account("caller", u, SEED);

            let (n, did, pk, sig) = get_data_for_did_removal(0, i as usize);
            let detail = KeyDetail::new(did.clone(), pk);
            let block_number = <T as system::Config>::BlockNumber::from(n);
            Dids::<T>::insert(did.clone(), (detail, block_number));

            let remove = DidRemoval::new(
                did.clone(),
                n,
            );
        }: remove(RawOrigin::Signed(caller), remove, sig)
        verify {
            let value = Dids::<T>::get(did);
            assert!(value.is_none());
        }

        sig_ver_sr25519 {
            let i in ...;
            let (msg, pk, sig) = get_data_for_sig_ver(0, i as usize);

        }: {
            assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
        }

        sig_ver_ed25519 {
            let i in ...;
            let (msg, pk, sig) = get_data_for_sig_ver(1, i as usize);

        }: {
            assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
        }

        sig_ver_secp256k1 {
            let i in ...;
            let (msg, pk, sig) = get_data_for_sig_ver(2, i as usize);

        }: {
            assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
        }
    }
}
