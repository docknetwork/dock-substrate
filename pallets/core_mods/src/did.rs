use super::{BlockNumber, StateChange};
use crate as dock;
use crate::keys_and_sigs::{PublicKey, SigValue};
use bitmask::*;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError,
    dispatch::DispatchResult, ensure, fail, traits::Get, weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{Hash, One};
use sp_std::{collections::btree_set::BTreeSet, vec::Vec};

// TODO: This module is getting too big and might be useful to others without all the other stuff in this pallet. Consider making it a separate pallet

/// Size of the Dock DID in bytes
pub const DID_BYTE_SIZE: usize = 32;
/// The type of the Dock DID
pub type Did = [u8; DID_BYTE_SIZE];

/// The module's configuration trait.
pub trait Trait: system::Config {
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
    /// Maximum byte size of reference to off-chain DID Doc.
    type MaxDidDocRefSize: Get<u32>;
    /// Weight per byte of the off-chain DID Doc reference
    type DidDocRefPerByteWeight: Get<Weight>;
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
        InsufficientVerificationRelationship,
    }
}

/// To describe the off chain DID Doc's reference. This is just to inform the client, this module
/// does not check if the bytes are indeed valid as per the enum variant
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OffChainDidDocRef {
    /// Content IDentifier as per https://github.com/multiformats/cid.
    CID(Vec<u8>),
    /// A URL
    URL(Vec<u8>),
    /// A custom encoding of the reference
    Custom(Vec<u8>),
}

bitmask::bitmask! {
    /// Verification relation types set.
    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub mask VerRelSet: u16 where
    /// Different verification relation types specified in the DID spec
    flags VerRelType {
        /// No verification relation set.
        None = 0,
        /// https://www.w3.org/TR/did-core/#authentication
        Authentication = 0b0001,
        /// https://www.w3.org/TR/did-core/#assertion
        Assertion = 0b0010,
        /// A key must have this to control a DID
        /// https://www.w3.org/TR/did-core/#capability-invocation
        CapabilityInvocation = 0b0100,
        /// https://www.w3.org/TR/did-core/#key-agreement
        KeyAgreement = 0b1000,

        /// Includes `Authentication`, `Assertion`, `CapabilityInvocation`.
        /// We might add more relationships in future but these 3 are all we care about now.
        AllForSigning = 0b0111
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidKey {
    /// The public key
    key: PublicKey,
    /// The different verification relationships the above key has with the DID.
    ver_rels: VerRelSet,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidSignature {
    /// The DID that created this signature
    did: Did,
    /// The key-id of above DID used to verify the signature
    key_id: IncId,
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
    /// Number of keys added for this DID so far.
    last_key_id: IncId,
    /// Number of controllers added for this DID so far.
    last_controller_id: IncId,
    /// Number of currently active keys.
    active_control_keys: u32,
    /// Number of currently active controllers.
    active_controllers: u32,
}

/// Enum describing the storage of the DID
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DidDetailStorage<T: Trait> {
    /// Off-chain DID has no need of nonce as the signature is made on the whole transaction by
    /// the caller account and Substrate takes care of replay protection. Thus it stores the data
    /// about off-chain DID Doc (hash, URI or any other reference) and the account that owns it.
    OffChain(T::AccountId, OffChainDidDocRef),
    /// For on-chain DID, all data is stored on the chain.
    OnChain(DidDetail<T>),
}

/// An incremental identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Copy, Default, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncId(u32);

impl IncId {
    /// Creates new `IncId` equal to zero.
    fn new() -> Self {
        Self::default()
    }

    /// Increases `IncId` value returning next sequential identifier.
    fn next(&mut self) -> &mut Self {
        self.0 += 1;
        self
    }
}

impl From<u32> for IncId {
    fn from(val: u32) -> IncId {
        IncId(val)
    }
}

impl From<u16> for IncId {
    fn from(val: u16) -> IncId {
        IncId(val.into())
    }
}

impl From<u8> for IncId {
    fn from(val: u8) -> IncId {
        IncId(val.into())
    }
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
    keys: Vec<IncId>,
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
    controllers: Vec<IncId>,
    nonce: BlockNumber,
}

impl OffChainDidDocRef {
    pub fn len(&self) -> usize {
        match self {
            OffChainDidDocRef::CID(v) => v.len(),
            OffChainDidDocRef::URL(v) => v.len(),
            OffChainDidDocRef::Custom(v) => v.len(),
        }
    }
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
        last_key_id: IncId,
        last_controller_id: IncId,
        active_control_keys: u32,
        active_controllers: u32,
        nonce: T::BlockNumber,
    ) -> Self {
        DidDetailStorage::OnChain(DidDetail {
            last_key_id,
            last_controller_id,
            active_control_keys,
            active_controllers,
            nonce,
        })
    }

    pub fn to_off_chain_did_owner_and_uri(self) -> (T::AccountId, OffChainDidDocRef) {
        match self {
            DidDetailStorage::OffChain(owner, doc_ref) => (owner, doc_ref),
            _ => panic!("This should never happen"),
        }
    }
}

impl DidKey {
    pub fn new(key: PublicKey, ver_rels: impl Into<VerRelSet>) -> Self {
        DidKey {
            key: key.into(),
            ver_rels: ver_rels.into(),
        }
    }

    /// Add all possible verification relationships for a given key
    pub fn new_with_all_relationships(public_key: PublicKey) -> Self {
        let ver_rels = if public_key.can_sign() {
            // We might add more relationships in future but these 3 are all we care about now.
            VerRelType::AllForSigning
        } else {
            // This is true for the current key type, X25519, used for key agreement but might
            // change in future.
            VerRelType::KeyAgreement
        };

        DidKey::new(public_key, ver_rels)
    }

    /// Checks if the public key has valid verification relationships. Currently, the keys used for
    /// key-agreement cannot (without converting) be used for signing and vice versa
    pub fn is_valid(&self) -> bool {
        !self.can_sign() ^ (self.ver_rels & VerRelType::AllForSigning == self.ver_rels)
    }

    pub fn can_control(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::CapabilityInvocation)
    }

    pub fn can_authenticate(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::Authentication)
    }

    pub fn can_sign(&self) -> bool {
        self.key.can_sign()
    }

    pub fn for_key_agreement(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::KeyAgreement)
    }

    pub fn can_authenticate_or_control(&self) -> bool {
        self.is_valid()
            && self
                .ver_rels
                .intersects(VerRelType::Authentication | VerRelType::CapabilityInvocation)
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
        OffChainDidAdded(dock::did::Did, OffChainDidDocRef),
        OffChainDidUpdated(dock::did::Did, OffChainDidDocRef),
        OffChainDidRemoved(dock::did::Did),
        OnChainDidAdded(dock::did::Did),
        DidKeysAdded(dock::did::Did),
        DidKeysRemoved(dock::did::Did),
        DidControllersAdded(dock::did::Did),
        DidControllersRemoved(dock::did::Did),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule {
        /// Stores details of off-chain and on-chain DIDs
        pub Dids get(fn did): map hasher(blake2_128_concat) dock::did::Did
            => Option<DidDetailStorage<T>>;
        /// Stores keys of a DID as (DID, IncId) -> DidKey. Does not check if the same key is being added multiple times to the same DID.
        pub DidKeys get(fn did_key): double_map hasher(blake2_128_concat) dock::did::Did, hasher(identity) IncId => Option<DidKey>;
        /// Stores controllers of a DID as (DID, IncId) -> DID.
        pub DidControllers get(fn did_controller): double_map hasher(blake2_128_concat) dock::did::Did, hasher(identity) IncId => Option<Did>;
        /// Stores information about DID controller relation count.
        pub DidControllersCount get(fn did_controller_count): double_map hasher(blake2_128_concat) dock::did::Did, hasher(blake2_128_concat) Did => u32;
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

        const MaxDidDocRefSize: u32 = T::MaxDidDocRefSize::get();
        const DidDocRefPerByteWeight: Weight = T::DidDocRefPerByteWeight::get();

        #[weight = T::DbWeight::get().reads_writes(1, 1) + did_doc_ref.len() as u64 * T::DidDocRefPerByteWeight::get()]
        pub fn new_offchain(origin, did: dock::did::Did, did_doc_ref: OffChainDidDocRef) -> DispatchResult {
            // Only `did_owner` can update or remove this DID
            let did_owner = ensure_signed(origin)?;
            ensure!(
                T::MaxDidDocRefSize::get() as usize >= did_doc_ref.len(),
                Error::<T>::DidDocUriTooBig
            );
            Self::new_offchain_(did_owner, did, did_doc_ref)
        }

        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1) + did_doc_ref.len() as u64 * T::DidDocRefPerByteWeight::get()]
        pub fn set_offchain_did_uri(origin, did: dock::did::Did, did_doc_ref: OffChainDidDocRef) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            ensure!(
                T::MaxDidDocRefSize::get() as usize >= did_doc_ref.len(),
                Error::<T>::DidDocUriTooBig
            );
            Self::set_offchain_did_uri_(caller, did, did_doc_ref)
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

        /// Add more keys from DID doc. Does not check if the key is already added or it has duplicate
        /// verification relationships
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        fn add_keys(origin, keys: AddKeys, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(keys.len() > 0, Error::<T>::NoKeyProvided);
            Module::<T>::add_keys_(keys, sig)
        }

        /// Remove keys from DID doc. This's atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        fn remove_keys(origin, keys: RemoveKeys, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(keys.len() > 0, Error::<T>::NoKeyProvided);
            Module::<T>::remove_keys_(keys, sig)
        }

        /// Add new controllers. Does not check if the controller being added has any key or is even
        /// a DID that exists on or off chain. Does not check if the controller is already added.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn add_controllers(origin, controllers: AddControllers, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(controllers.len() > 0, Error::<T>::NoControllerProvided);
            Module::<T>::add_controllers_(controllers, sig)
        }

        /// Remove controllers. This's atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn remove_controllers(origin, controllers: RemoveControllers, sig: DidSignature) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(controllers.len() > 0, Error::<T>::NoControllerProvided);
            Module::<T>::remove_controllers_(controllers, sig)
        }
    }
}

impl<T: Trait> Module<T> {
    fn new_offchain_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef,
    ) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        Dids::<T>::insert(did, DidDetailStorage::OffChain(caller, did_doc_ref.clone()));
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OffChainDidAdded(did, did_doc_ref)).into(),
        );
        Ok(())
    }

    fn set_offchain_did_uri_(
        caller: T::AccountId,
        did: Did,
        did_doc_ref: OffChainDidDocRef,
    ) -> DispatchResult {
        Self::ensure_offchain_did_be_updated(&caller, &did)?;
        Dids::<T>::insert(did, DidDetailStorage::OffChain(caller, did_doc_ref.clone()));
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OffChainDidUpdated(did, did_doc_ref)).into(),
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

    fn new_onchain_(did: Did, keys: Vec<DidKey>, controllers: Vec<Did>) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        if keys.is_empty() && controllers.is_empty() {
            fail!(Error::<T>::NoControllerProvided)
        }

        let (keys_to_insert, controller_keys_count) = Self::prepare_keys_to_insert(keys)?;

        let mut last_key_id = IncId::new();
        let mut last_controller_id = IncId::new();
        for key in keys_to_insert {
            DidKeys::insert(&did, last_key_id.next(), key);
        }

        if controller_keys_count > 0 {
            DidControllers::insert(&did, last_controller_id.next(), &did);
            DidControllersCount::mutate(&did, &did, |val| *val += 1);
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, last_controller_id.next(), &ctrl);
            DidControllersCount::mutate(&did, &ctrl, |val| *val += 1);
        }

        // Nonce will start from current block number
        let nonce = <system::Module<T>>::block_number();
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                last_key_id,
                last_controller_id,
                controller_keys_count,
                controllers.len() as u32 + (controller_keys_count > 0) as u32,
                nonce,
            ),
        );

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
        let (keys_to_insert, controller_keys_count) = Self::prepare_keys_to_insert(keys.keys)?;

        // Make self controlled if need to be
        let mut last_controller_id = did_detail.last_controller_id;
        let was_self_controlled = Self::is_self_controlled(&did);

        if controller_keys_count > 0 && !was_self_controlled {
            DidControllers::insert(&did, last_controller_id.next(), did);
            DidControllersCount::mutate(&did, &did, |val| *val += 1);
        }

        let mut last_key_id = did_detail.last_key_id;
        for key in keys_to_insert.into_iter() {
            DidKeys::insert(did, last_key_id.next(), key)
        }
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidKeysAdded(*did)).into(),
        );

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                last_key_id,
                last_controller_id,
                did_detail.active_control_keys + controller_keys_count,
                did_detail.active_controllers
                    + (controller_keys_count > 0 && !was_self_controlled) as u32,
                T::BlockNumber::from(keys.nonce),
            ),
        );

        Ok(())
    }

    fn remove_keys_(remove_keys: RemoveKeys, sig: DidSignature) -> DispatchResult {
        let did = &remove_keys.did;
        let signer = &sig.did;

        let did_detail = Self::get_on_chain_did_detail_for_update(did, remove_keys.nonce)?;

        let serz_remove_keys = StateChange::RemoveKeys(remove_keys.clone()).encode();

        ensure!(
            Self::verify_sig_from_controller(did, &serz_remove_keys, signer, &sig)?,
            Error::<T>::InvalidSig
        );

        let mut controller_keys = BTreeSet::new();
        for key_id in &remove_keys.keys {
            let key = DidKeys::get(did, key_id).ok_or(Error::<T>::NoKeyForDid)?;

            if key.can_control() {
                controller_keys.insert(key_id);
            }
        }

        for key in &remove_keys.keys {
            DidKeys::remove(did, key);
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.last_controller_id,
                did_detail.active_control_keys - controller_keys.len() as u32,
                did_detail.active_controllers,
                T::BlockNumber::from(remove_keys.nonce),
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidKeysRemoved(*did)).into(),
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

        let mut last_controller_id = did_detail.last_controller_id;

        for cnt in &controllers.controllers {
            DidControllers::insert(&did, last_controller_id.next(), cnt);
            DidControllersCount::mutate(&did, cnt, |val| *val += 1);
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                last_controller_id,
                did_detail.active_control_keys,
                did_detail.active_controllers + controllers.controllers.len() as u32,
                T::BlockNumber::from(controllers.nonce),
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidControllersAdded(*did)).into(),
        );

        Ok(())
    }

    fn remove_controllers_(controllers: RemoveControllers, sig: DidSignature) -> DispatchResult {
        let did = &controllers.did;
        let signer = &sig.did;

        let did_detail = Self::get_on_chain_did_detail_for_update(did, controllers.nonce)?;

        let serz_add_controllers = StateChange::RemoveControllers(controllers.clone()).encode();

        ensure!(
            Self::verify_sig_from_controller(did, &serz_add_controllers, signer, &sig)?,
            Error::<T>::InvalidSig
        );

        let uniq_controller_ids: BTreeSet<_> = controllers.controllers.into_iter().collect();
        let controller_list: Vec<_> = uniq_controller_ids
            .into_iter()
            .map(|controller_id| {
                DidControllers::get(&did, controller_id)
                    .ok_or(Error::<T>::NoKeyForDid)
                    .map(|controller_did| (controller_id, controller_did))
            })
            .collect::<Result<_, _>>()?;

        for (controller_id, controller_did) in &controller_list {
            DidControllers::remove(&did, controller_id);
            DidControllersCount::mutate(&did, controller_did, |val| *val = val.saturating_sub(1));
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.last_controller_id,
                did_detail.active_control_keys,
                did_detail.active_controllers - controller_list.len() as u32,
                T::BlockNumber::from(controllers.nonce),
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(did)],
            <T as Trait>::Event::from(Event::DidControllersRemoved(*did)).into(),
        );

        Ok(())
    }

    /// Prepare `DidKey`s to insert. The DID is assumed to be self controlled as well if there is any key
    /// that is capable of either authenticating or invoking a capability. Returns the keys and whether any
    /// key can make the DID a controller. The following logic is contentious
    fn prepare_keys_to_insert(keys: Vec<DidKey>) -> Result<(Vec<DidKey>, u32), DispatchError> {
        let mut controller_keys_count = 0;
        let mut keys_to_insert = Vec::with_capacity(keys.len());
        for key in keys {
            let key = if key.ver_rels.is_none() {
                DidKey::new_with_all_relationships(key.key)
            } else {
                if !key.is_valid() {
                    fail!(Error::<T>::IncompatableVerificationRelation)
                }
                key
            };
            if key.can_control() {
                controller_keys_count += 1;
            }

            keys_to_insert.push(key);
        }

        Ok((keys_to_insert, controller_keys_count))
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
        Self::did_controller_count(controlled, controller) > 0
    }

    /// Returns true if `did` controls itself, else false.
    pub fn is_self_controlled(did: &Did) -> bool {
        Self::is_controller(did, did)
    }

    /// Return `did`'s key with id `key_id` only if it can control otherwise throw error
    pub fn get_key_for_control(did: &Did, key_id: IncId) -> Result<PublicKey, DispatchError> {
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
            // println!("{}", (did_detail_storage.nonce + T::BlockNumber::one()));
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
    use frame_support::{assert_err, assert_noop, assert_ok};
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

    fn check_did_detail(
        did: &Did,
        last_key_id: u32,
        last_controller_id: u32,
        active_control_keys: u32,
        active_controllers: u32,
        nonce: BlockNumber,
    ) {
        let did_detail = DIDModule::get_on_chain_did_detail(did).unwrap();
        assert_eq!(did_detail.last_key_id, last_key_id.into());
        assert_eq!(did_detail.last_controller_id, last_controller_id.into());
        assert_eq!(did_detail.active_control_keys, active_control_keys);
        assert_eq!(did_detail.active_controllers, active_controllers);
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
            let doc_ref = OffChainDidDocRef::Custom(vec![129; 60]);
            let too_big_doc_ref = OffChainDidDocRef::Custom(vec![129; 300]);

            assert_noop!(
                DIDModule::new_offchain(
                    Origin::signed(alice),
                    did.clone(),
                    too_big_doc_ref.clone()
                ),
                Error::<Test>::DidDocUriTooBig
            );

            // Add a DID
            assert_ok!(DIDModule::new_offchain(
                Origin::signed(alice),
                did.clone(),
                doc_ref.clone()
            ));

            // Try to add the same DID and same uri again and fail
            assert_noop!(
                DIDModule::new_offchain(Origin::signed(alice), did.clone(), doc_ref.clone()),
                Error::<Test>::DidAlreadyExists
            );

            // Try to add the same DID and different uri and fail
            let doc_ref_1 = OffChainDidDocRef::URL(vec![205; 99]);
            assert_noop!(
                DIDModule::new_offchain(Origin::signed(alice), did, doc_ref_1),
                Error::<Test>::DidAlreadyExists
            );

            assert!(DIDModule::is_offchain_did(&did).unwrap());
            assert!(!DIDModule::is_onchain_did(&did).unwrap());

            assert_noop!(
                DIDModule::get_on_chain_did_detail(&did),
                Error::<Test>::CannotGetDetailForOffChainDid
            );

            let did_detail_storage = Dids::<Test>::get(&did).unwrap();
            let (owner, fetched_ref) = did_detail_storage.to_off_chain_did_owner_and_uri();
            assert_eq!(owner, alice);
            assert_eq!(fetched_ref, doc_ref);

            let bob = 2u64;
            let new_ref = OffChainDidDocRef::CID(vec![235; 99]);
            assert_noop!(
                DIDModule::set_offchain_did_uri(Origin::signed(bob), did, new_ref.clone()),
                Error::<Test>::DidNotOwnedByAccount
            );

            assert_noop!(
                DIDModule::set_offchain_did_uri(
                    Origin::signed(alice),
                    did.clone(),
                    too_big_doc_ref
                ),
                Error::<Test>::DidDocUriTooBig
            );

            assert_ok!(DIDModule::set_offchain_did_uri(
                Origin::signed(alice),
                did.clone(),
                new_ref.clone()
            ));
            let did_detail_storage = Dids::<Test>::get(&did).unwrap();
            let (_, fetched_ref) = did_detail_storage.to_off_chain_did_owner_and_uri();
            assert_eq!(fetched_ref, new_ref);

            assert_noop!(
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

            assert_noop!(
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

            check_did_detail(&did_1, 0, 1, 0, 1, 20);

            assert_noop!(
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

            check_did_detail(&did_2, 0, 3, 0, 3, 55);
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
                    ver_rels: VerRelType::None.into()
                }],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 1, 1, 5);

            let key_1 = DidKeys::get(&did_1, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_1);

            run_to_block(6);

            // DID controls itself and specifies another controller as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::None.into()
                }],
                vec![did_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 2, 1, 2, 6);

            let key_2 = DidKeys::get(&did_2, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_2);

            run_to_block(7);

            // DID controls itself and specifies multiple another controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::None.into()
                }],
                vec![did_1, did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 3, 1, 3, 7);

            let key_3 = DidKeys::get(&did_3, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_3);

            run_to_block(8);

            // Adding x25519 key does not make the DID self controlled
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::None.into()
                }],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 0, 0, 0, 8);

            let key_4 = DidKeys::get(&did_4, IncId::from(1u32)).unwrap();
            only_key_agreement(&key_4);

            // x25519 key cannot be added for incompatible relationship types
            for vr in vec![
                VerRelType::Authentication,
                VerRelType::Assertion,
                VerRelType::CapabilityInvocation,
            ] {
                assert_noop!(
                    DIDModule::new_onchain(
                        Origin::signed(alice),
                        did_5.clone(),
                        vec![DidKey {
                            key: PublicKey::x25519(pk_ed),
                            ver_rels: vr.into()
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
                assert_noop!(
                    DIDModule::new_onchain(
                        Origin::signed(alice),
                        did_5.clone(),
                        vec![DidKey {
                            key: pk,
                            ver_rels: VerRelType::KeyAgreement.into()
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
                        ver_rels: VerRelType::CapabilityInvocation.into()
                    }],
                    vec![]
                ));
                assert!(DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, IncId::from(1u32)).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_authenticate());
                assert!(key.can_control());
                assert!(key.can_authenticate_or_control());
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 1, 1, 1, 10);
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
                        ver_rels: vr.into()
                    }],
                    vec![]
                ));
                assert!(!DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, IncId::from(1u32)).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_control());
                if vr == VerRelType::Authentication {
                    assert!(key.can_authenticate());
                    assert!(key.can_authenticate_or_control());
                }
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 0, 0, 0, 13);
            }

            run_to_block(19);

            // Add single key, specify multiple relationships and but do not specify relationship as `capabilityInvocation`
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_8.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: (VerRelType::Authentication | VerRelType::Assertion).into()
                }],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_8));
            let key_8 = DidKeys::get(&did_8, IncId::from(1u32)).unwrap();
            assert!(key_8.can_sign());
            assert!(key_8.can_authenticate());
            assert!(!key_8.can_control());
            check_did_detail(&did_8, 1, 0, 0, 0, 19);

            run_to_block(20);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_9.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::Authentication.into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::Assertion.into()
                    },
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: (VerRelType::Assertion | VerRelType::Authentication).into()
                    },
                ],
                vec![]
            ));
            assert!(!DIDModule::is_self_controlled(&did_9));
            let key_9_1 = DidKeys::get(&did_9, IncId::from(1u32)).unwrap();
            assert!(key_9_1.can_sign());
            assert!(key_9_1.can_authenticate());
            assert!(!key_9_1.can_control());
            let key_9_2 = DidKeys::get(&did_9, IncId::from(2u32)).unwrap();
            assert!(key_9_2.can_sign());
            assert!(!key_9_2.can_authenticate());
            assert!(!key_9_2.can_control());
            let key_9_3 = DidKeys::get(&did_9, IncId::from(3u32)).unwrap();
            assert!(key_9_3.can_sign());
            assert!(key_9_3.can_authenticate());
            assert!(!key_9_3.can_control());
            check_did_detail(&did_9, 3, 0, 0, 0, 20);

            run_to_block(22);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_10.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::Authentication | VerRelType::Assertion).into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::Assertion.into()
                    },
                    DidKey {
                        key: pk_secp,
                        ver_rels: VerRelType::CapabilityInvocation.into()
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_10));
            let key_10_1 = DidKeys::get(&did_10, IncId::from(1u32)).unwrap();
            assert!(key_10_1.can_sign());
            assert!(key_10_1.can_authenticate());
            assert!(!key_10_1.can_control());
            let key_10_2 = DidKeys::get(&did_10, IncId::from(2u32)).unwrap();
            assert!(key_10_2.can_sign());
            assert!(!key_10_2.can_authenticate());
            assert!(!key_10_2.can_control());
            let key_10_3 = DidKeys::get(&did_10, IncId::from(3u32)).unwrap();
            assert!(key_10_3.can_sign());
            assert!(!key_10_3.can_authenticate());
            assert!(key_10_3.can_control());
            check_did_detail(&did_10, 3, 1, 1, 1, 22);

            run_to_block(23);

            // Add multiple keys, specify multiple relationships and other controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_11.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::Authentication | VerRelType::Assertion).into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::CapabilityInvocation.into()
                    },
                ],
                vec![did_1, did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_11));
            let key_11_1 = DidKeys::get(&did_11, IncId::from(1u32)).unwrap();
            assert!(key_11_1.can_sign());
            assert!(key_11_1.can_authenticate());
            assert!(!key_11_1.can_control());
            let key_11_2 = DidKeys::get(&did_11, IncId::from(2u32)).unwrap();
            assert!(key_11_2.can_sign());
            assert!(!key_11_2.can_authenticate());
            assert!(key_11_2.can_control());
            check_did_detail(&did_11, 2, 3, 1, 3, 23);
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
                    ver_rels: VerRelType::Authentication.into()
                }],
                vec![controller_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_1));
            assert!(DIDModule::is_controller(&did_1, &controller_1));
            check_did_detail(&did_1, 1, 1, 0, 1, 10);

            run_to_block(11);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::Assertion.into()
                }],
                vec![controller_2]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            assert!(DIDModule::is_controller(&did_2, &controller_2));
            check_did_detail(&did_2, 1, 1, 0, 1, 11);

            run_to_block(12);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::KeyAgreement.into()
                }],
                vec![controller_3]
            ));
            assert!(!DIDModule::is_self_controlled(&did_3));
            assert!(DIDModule::is_controller(&did_3, &controller_3));
            check_did_detail(&did_3, 1, 1, 0, 1, 12);

            run_to_block(13);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::Authentication.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::Assertion.into()
                    }
                ],
                vec![controller_4]
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            assert!(DIDModule::is_controller(&did_4, &controller_4));
            check_did_detail(&did_4, 2, 1, 0, 1, 13);

            run_to_block(14);

            // DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_5.clone(),
                vec![
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: (VerRelType::Authentication | VerRelType::CapabilityInvocation)
                            .into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::Assertion.into()
                    }
                ],
                vec![controller_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_5));
            assert!(DIDModule::is_controller(&did_5, &controller_1));
            check_did_detail(&did_5, 2, 2, 1, 2, 14);

            run_to_block(15);

            // DID has 2 keys to control itself and another DID
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_6.clone(),
                vec![
                    DidKey {
                        key: pk_secp,
                        ver_rels: (VerRelType::Authentication | VerRelType::CapabilityInvocation)
                            .into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::Assertion | VerRelType::CapabilityInvocation).into()
                    }
                ],
                vec![controller_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_6));
            assert!(DIDModule::is_controller(&did_6, &controller_1));
            check_did_detail(&did_6, 2, 2, 2, 2, 15);
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
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                    ver_rels: VerRelType::None.into(),
                }],
                nonce: 5,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                        ver_rels: VerRelType::None.into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr_2),
                        ver_rels: VerRelType::None.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_2),
                        ver_rels: VerRelType::Authentication.into()
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 3, 1, 2, 1, 5);

            run_to_block(7);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed_1),
                    ver_rels: VerRelType::Authentication.into()
                }],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 0, 1, 7);

            run_to_block(10);

            // Since did_2 does not control itself, it cannot add keys to itself
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: VerRelType::None.into(),
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed_1);
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 1u32.into(),
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
                        ver_rels: VerRelType::None.into(),
                    }],
                    nonce,
                };
                let sig =
                    SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
                assert_noop!(
                    DIDModule::add_keys(
                        Origin::signed(alice),
                        add_keys,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1u32.into(),
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
                    ver_rels: VerRelType::None.into(),
                }],
                nonce: 7 + 1,
            };
            // Using some arbitrary bytes as signature
            let sig = SigValue::Sr25519(Bytes64 { value: [109; 64] });
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                    ver_rels: VerRelType::None.into(),
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 2u32.into(),
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
                    ver_rels: VerRelType::KeyAgreement.into(),
                }],
                nonce: 7 + 1,
            };
            let sig =
                SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr_1);
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                    ver_rels: VerRelType::KeyAgreement.into(),
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
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 2, 1, 0, 1, 8);

            // Add many keys
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![
                    DidKey {
                        key: PublicKey::x25519(pk_sr_2),
                        ver_rels: VerRelType::KeyAgreement.into(),
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::Assertion.into(),
                    },
                    DidKey {
                        key: pk_secp_2,
                        ver_rels: (VerRelType::Authentication | VerRelType::Assertion).into(),
                    },
                ],
                nonce: 8 + 1,
            };

            // Controller uses a key without the capability to update DID
            let sig =
                SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed_2);
            assert_noop!(
                DIDModule::add_keys(
                    Origin::signed(alice),
                    add_keys.clone(),
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 3u32.into(),
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
                    key_id: 2u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 5, 1, 0, 1, 9);
        });
    }

    #[test]
    fn remove_keys_from_did() {
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

            run_to_block(2);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1)),
                    DidKey::new_with_all_relationships(PublicKey::ed25519(pk_ed_1)),
                    DidKey::new(PublicKey::ed25519(pk_ed_2), VerRelType::Assertion),
                    DidKey::new(PublicKey::sr25519(pk_sr_2), VerRelType::Authentication),
                ],
                vec![did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 4, 2, 2, 2, 2);

            run_to_block(5);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::Authentication.into()
                    },
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1))
                ],
                vec![did_1]
            ));
            check_did_detail(&did_2, 2, 2, 1, 2, 5);

            run_to_block(10);

            // Nonce should be 1 greater than existing 7, i.e. 8
            for nonce in vec![1, 2, 4, 5, 10, 10000] {
                let remove_keys = RemoveKeys {
                    did: did_2.clone(),
                    keys: vec![2u32.into()],
                    nonce,
                };
                let sig = SigValue::sr25519(
                    &StateChange::RemoveKeys(remove_keys.clone()).encode(),
                    &pair_sr_1,
                );
                assert_noop!(
                    DIDModule::remove_keys(
                        Origin::signed(alice),
                        remove_keys,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1u32.into(),
                            sig
                        }
                    ),
                    Error::<Test>::IncorrectNonce
                );
            }

            // Since did_2 does not control itself, it cannot add keys to itself
            let remove_keys = RemoveKeys {
                did: did_1.clone(),
                keys: vec![1u32.into(), 3u32.into(), 5u32.into()],
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveKeys(remove_keys.clone()).encode(),
                &pair_ed_1,
            );
            assert_noop!(
                DIDModule::remove_keys(
                    Origin::signed(alice),
                    remove_keys,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::NoKeyForDid
            );
            let remove_keys = RemoveKeys {
                did: did_1.clone(),
                keys: vec![1u32.into()],
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveKeys(remove_keys.clone()).encode(),
                &pair_ed_1,
            );
            assert_ok!(DIDModule::remove_keys(
                Origin::signed(alice),
                remove_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
            check_did_detail(&did_1, 4, 2, 1, 2, 3);

            let remove_keys = RemoveKeys {
                did: did_1.clone(),
                keys: vec![3u32.into()],
                nonce: 4,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveKeys(remove_keys.clone()).encode(),
                &pair_sr_1,
            );
            assert_ok!(DIDModule::remove_keys(
                Origin::signed(alice),
                remove_keys,
                DidSignature {
                    did: did_2.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
        });
    }

    #[test]
    fn remove_controllers_from_did() {
        ext().execute_with(|| {
            let alice = 1u64;
            let did_1 = [51; DID_BYTE_SIZE];
            let did_2 = [52; DID_BYTE_SIZE];
            let did_3 = [53; DID_BYTE_SIZE];

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

            run_to_block(2);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1)),
                    DidKey::new_with_all_relationships(PublicKey::ed25519(pk_ed_1)),
                    DidKey::new(PublicKey::ed25519(pk_ed_2), VerRelType::Assertion),
                    DidKey::new(PublicKey::sr25519(pk_sr_2), VerRelType::Authentication),
                ],
                vec![did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 4, 2, 2, 2, 2);

            run_to_block(5);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::Authentication.into()
                    },
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1))
                ],
                vec![did_1]
            ));
            check_did_detail(&did_2, 2, 2, 1, 2, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![],
                vec![did_1, did_2, did_3]
            ));
            check_did_detail(&did_3, 0, 3, 0, 3, 5);

            run_to_block(10);

            // Nonce should be 1 greater than existing 7, i.e. 8
            for nonce in vec![1, 2, 4, 5, 10, 10000] {
                let remove_controllers = RemoveControllers {
                    did: did_2.clone(),
                    controllers: vec![0u32.into()],
                    nonce,
                };
                let sig = SigValue::sr25519(
                    &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                    &pair_sr_1,
                );
                assert_noop!(
                    DIDModule::remove_controllers(
                        Origin::signed(alice),
                        remove_controllers,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1u32.into(),
                            sig
                        }
                    ),
                    Error::<Test>::IncorrectNonce
                );
            }

            // Since did_2 does not control itself, it cannot add keys to itself
            let remove_controllers = RemoveControllers {
                did: did_1.clone(),
                controllers: vec![1u32.into(), 3u32.into(), 5u32.into()],
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                &pair_ed_1,
            );
            assert_noop!(
                DIDModule::remove_controllers(
                    Origin::signed(alice),
                    remove_controllers,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::NoKeyForDid
            );
            let remove_controllers = RemoveControllers {
                did: did_1.clone(),
                controllers: vec![1u32.into()],
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                &pair_ed_1,
            );
            assert_ok!(DIDModule::remove_controllers(
                Origin::signed(alice),
                remove_controllers,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 4, 2, 2, 1, 3);

            let remove_controllers = RemoveControllers {
                did: did_1.clone(),
                controllers: vec![2u32.into()],
                nonce: 4,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                &pair_sr_1,
            );
            assert_ok!(DIDModule::remove_controllers(
                Origin::signed(alice),
                remove_controllers,
                DidSignature {
                    did: did_2.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
            check_did_detail(&did_1, 4, 2, 2, 0, 4);

            let remove_controllers = RemoveControllers {
                did: did_3.clone(),
                controllers: vec![2u32.into()],
                nonce: 6,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                &pair_sr_1,
            );
            assert_ok!(DIDModule::remove_controllers(
                Origin::signed(alice),
                remove_controllers,
                DidSignature {
                    did: did_2.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
            run_to_block(22);
            let remove_controllers = RemoveControllers {
                did: did_3.clone(),
                controllers: vec![1u32.into()],
                nonce: 7,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(remove_controllers.clone()).encode(),
                &pair_sr_1,
            );
            assert_err!(
                DIDModule::remove_controllers(
                    Origin::signed(alice),
                    remove_controllers,
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::OnlyControllerCanUpdate
            );
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
            assert_noop!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
            assert_noop!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                        ver_rels: VerRelType::None.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::Authentication.into()
                    },
                ],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 2, 1, 1, 1, 5);

            run_to_block(6);

            // This DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp_2.clone(),
                    ver_rels: VerRelType::None.into()
                },],
                vec![did_1]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_3, 1, 2, 1, 2, 6);

            run_to_block(10);
            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::Authentication.into()
                }],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 0, 1, 10);

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
            assert_noop!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers,
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 1u32.into(),
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
                assert_noop!(
                    DIDModule::add_controllers(
                        Origin::signed(alice),
                        add_controllers,
                        DidSignature {
                            did: did_1.clone(),
                            key_id: 1u32.into(),
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
            assert_noop!(
                DIDModule::add_controllers(
                    Origin::signed(alice),
                    add_controllers.clone(),
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
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
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 2, 0, 2, 11);

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
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 4, 0, 4, 12);
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
                    ver_rels: VerRelType::None.into()
                },],
                vec![]
            ));

            run_to_block(10);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::KeyAgreement.into()
                },],
                vec![did_1]
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 0, 1, 10);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::Assertion.into(),
                }],
                nonce: 10 + 1,
            };
            let sig = SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 2, 1, 0, 1, 11);

            run_to_block(20);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::CapabilityInvocation.into(),
                }],
                nonce: 11 + 1,
            };
            let sig = SigValue::sr25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_sr);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 3, 2, 1, 2, 12);
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
                    ver_rels: VerRelType::None.into()
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::None.into()
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::None.into()
                },],
                vec![]
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 1, 1, 1, 5);

            run_to_block(7);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::None.into()
                },],
                vec![did_2]
            ));
            assert!(DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 2, 1, 2, 7);

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
                    key_id: 1u32.into(),
                    sig
                }
            ));
            check_did_detail(&did_4, 1, 3, 1, 3, 8);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_4.clone(),
                keys: vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::None.into(),
                }],
                nonce: 8 + 1,
            };
            let sig = SigValue::ed25519(&StateChange::AddKeys(add_keys.clone()).encode(), &pair_ed);
            assert_ok!(DIDModule::add_keys(
                Origin::signed(alice),
                add_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
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
            assert_noop!(
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
            assert_noop!(
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
