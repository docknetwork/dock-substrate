use super::StateChange;
use crate as dock;
use crate::keys_and_sigs::{PublicKey, SigValue};
use crate::Action;
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchError,
    dispatch::DispatchResult, ensure, fail, traits::Get, weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{Hash, One};
use sp_std::borrow::Cow;
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
    type MaxDidDocRefSize: Get<u16>;
    /// Weight per byte of the off-chain DID Doc reference
    type DidDocRefPerByteWeight: Get<Weight>;
    /// Maximum byte size of service endpoint's `id` field
    type MaxServiceEndpointIdSize: Get<u16>;
    /// Weight per byte of service endpoint's `id` field
    type ServiceEndpointIdPerByteWeight: Get<Weight>;
    /// Maximum number of service endpoint's `origin`
    type MaxServiceEndpointOrigins: Get<u16>;
    /// Maximum byte size of service endpoint's `origin`
    type MaxServiceEndpointOriginSize: Get<u16>;
    /// Weight per byte of service endpoint's `origin`
    type ServiceEndpointOriginPerByteWeight: Get<Weight>;
}

decl_error! {
    /// Error for the DID module.
    pub enum Error for Module<T: Trait> where T: Debug {
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
        NoControllerForDid,
        InsufficientVerificationRelationship,
        ControllerIsAlreadyAdded,
        InvalidServiceEndpoint,
        ServiceEndpointAlreadyExists,
        ServiceEndpointDoesNotExist
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

bitflags::bitflags! {
    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    /// Different verification relation types specified in the DID spec here https://www.w3.org/TR/did-core/#verification-relationships
    pub struct VerRelType: u16 {
        /// No verification relation set.
        const NONE = 0;
        /// https://www.w3.org/TR/did-core/#authentication
        const AUTHENTICATION = 0b0001;
        /// https://www.w3.org/TR/did-core/#assertion
        const ASSERTION = 0b0010;
        /// A key must have this to control a DID
        /// https://www.w3.org/TR/did-core/#capability-invocation
        const CAPABILITY_INVOCATION = 0b0100;
        /// https://www.w3.org/TR/did-core/#key-agreement
        const KEY_AGREEMENT = 0b1000;

        /// Includes `AUTHENTICATION`, `ASSERTION`, `CAPABILITY_INVOCATION`.
        /// We might add more relationships in future but these 3 are all we care about now.
        const ALL_FOR_SIGNING = 0b0111;
    }
}

bitflags::bitflags! {
    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    /// Different service endpoint types specified in the DID spec here https://www.w3.org/TR/did-core/#services
    pub struct ServiceEndpointType: u16 {
        /// No service endpoint set.
        const NONE = 0;
        const LINKED_DOMAINS = 0b0001;
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidKey {
    /// The public key
    pub key: PublicKey,
    /// The different verification relationships the above key has with the DID.
    pub ver_rels: VerRelType,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidSignature {
    /// The DID that created this signature
    pub did: Did,
    /// The key-id of above DID used to verify the signature
    pub key_id: IncId,
    /// The actual signature
    pub sig: SigValue,
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
    pub nonce: T::BlockNumber,
    /// Number of keys added for this DID so far.
    pub last_key_id: IncId,
    /// Number of currently active controller keys.
    active_controller_keys: u32,
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

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceEndpoint {
    types: ServiceEndpointType,
    origins: Vec<Vec<u8>>,
}

/// An incremental identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Copy, Default, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IncId(u32);

impl Iterator for &'_ mut IncId {
    type Item = IncId;

    fn next(&mut self) -> Option<Self::Item> {
        Some(*self.inc())
    }
}

impl IncId {
    /// Creates new `IncId` equal to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increases `IncId` value returning next sequential identifier.
    pub fn inc(&mut self) -> &mut Self {
        self.0 += 1;
        self
    }

    pub fn as_number(&self) -> u32 {
        self.0
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

impl<T: Trait> DidDetail<T> {
    pub fn next_nonce(&self) -> T::BlockNumber {
        self.nonce + T::BlockNumber::one()
    }

    pub fn increment_last_key_id(&mut self) {
        self.last_key_id.inc();
    }
}

impl ServiceEndpoint {
    pub fn is_valid(&self, max_origins: usize, max_origin_length: usize) -> bool {
        !self.types.is_empty()
            && !self.origins.is_empty()
            && self.origins.len() <= max_origins
            && !self
                .origins
                .iter()
                .any(|o| o.is_empty() || o.len() > max_origin_length)
    }
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddKeys<T: frame_system::Config> {
    did: Did,
    keys: Vec<DidKey>,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveKeys<T: frame_system::Config> {
    did: Did,
    /// Key ids to remove
    keys: BTreeSet<IncId>,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddControllers<T: frame_system::Config> {
    did: Did,
    controllers: BTreeSet<Did>,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveControllers<T: frame_system::Config> {
    did: Did,
    /// Controllers ids to remove
    controllers: BTreeSet<Did>,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddServiceEndpoint<T: frame_system::Config> {
    did: Did,
    /// Endpoint id
    id: Vec<u8>,
    /// Endpoint data
    endpoint: ServiceEndpoint,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveServiceEndpoint<T: frame_system::Config> {
    did: Did,
    /// Endpoint id to remove
    id: Vec<u8>,
    nonce: T::BlockNumber,
}

/// This struct is passed as an argument while removing the DID
/// `did` is the DID which is being removed.
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidRemoval<T: frame_system::Config> {
    pub did: Did,
    pub nonce: T::BlockNumber,
}

impl_action!(
    Did,
    did,
    AddKeys,
    RemoveKeys,
    AddControllers,
    RemoveControllers,
    AddServiceEndpoint,
    RemoveServiceEndpoint,
    DidRemoval
);

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
        active_controller_keys: u32,
        active_controllers: u32,
        nonce: impl Into<T::BlockNumber>,
    ) -> Self {
        DidDetailStorage::OnChain(DidDetail {
            last_key_id,
            active_controller_keys,
            active_controllers,
            nonce: nonce.into(),
        })
    }

    pub fn to_off_chain_did_owner_and_doc_ref(self) -> (T::AccountId, OffChainDidDocRef) {
        match self {
            DidDetailStorage::OffChain(owner, doc_ref) => (owner, doc_ref),
            _ => panic!("This should never happen"),
        }
    }
}

impl DidKey {
    pub fn new(key: PublicKey, ver_rels: VerRelType) -> Self {
        DidKey { key, ver_rels }
    }

    /// Add all possible verification relationships for a given key
    pub fn new_with_all_relationships(public_key: PublicKey) -> Self {
        let ver_rels = if public_key.can_sign() {
            // We might add more relationships in future but these 3 are all we care about now.
            VerRelType::ALL_FOR_SIGNING
        } else {
            // This is true for the current key type, X25519, used for key agreement but might
            // change in future.
            VerRelType::KEY_AGREEMENT
        };

        DidKey::new(public_key, ver_rels)
    }

    pub fn can_sign(&self) -> bool {
        self.key.can_sign()
    }

    /// Checks if the public key has valid verification relationships. Currently, the keys used for
    /// key-agreement cannot (without converting) be used for signing and vice versa
    pub fn is_valid(&self) -> bool {
        !self.can_sign() ^ (self.ver_rels & VerRelType::ALL_FOR_SIGNING == self.ver_rels)
    }

    pub fn can_control(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::CAPABILITY_INVOCATION)
    }

    pub fn can_authenticate(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::AUTHENTICATION)
    }

    pub fn for_key_agreement(&self) -> bool {
        self.is_valid() && self.ver_rels.intersects(VerRelType::KEY_AGREEMENT)
    }

    pub fn can_authenticate_or_control(&self) -> bool {
        self.is_valid()
            && self
                .ver_rels
                .intersects(VerRelType::AUTHENTICATION | VerRelType::CAPABILITY_INVOCATION)
    }
}

impl DidSignature {
    fn verify<T: Trait + Debug>(
        &self,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, DispatchError> {
        self.sig
            .verify(message, public_key)
            .map_err(|_| Error::<T>::IncompatSigPubkey.into())
    }

    /// This is just the weight to verify the signature. It does not include weight to read the DID or the key.
    pub fn weight(&self) -> Weight {
        self.sig.weight()
    }
}

impl<T: frame_system::Config> AddKeys<T> {
    pub fn len(&self) -> u32 {
        self.keys.len() as u32
    }
}

impl<T: frame_system::Config> RemoveKeys<T> {
    pub fn len(&self) -> u32 {
        self.keys.len() as u32
    }
}

impl<T: frame_system::Config> AddControllers<T> {
    pub fn len(&self) -> u32 {
        self.controllers.len() as u32
    }
}

impl<T: frame_system::Config> RemoveControllers<T> {
    pub fn len(&self) -> u32 {
        self.controllers.len() as u32
    }
}

macro_rules! ensure_signed_origin_and_control_signed_payload {
    ($origin: ident, $payload: expr, $sig: expr, $extra_checks: block) => {
        ensure_signed($origin)?;
        $extra_checks
        ensure!(
            Self::verify_sig_from_controller($payload, $sig)?,
            Error::<T>::InvalidSig
        );
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
        DidServiceEndpointAdded(dock::did::Did),
        DidServiceEndpointRemoved(dock::did::Did),
        OnChainDidRemoved(dock::did::Did),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as DIDModule where T: Debug {
        /// Stores details of off-chain and on-chain DIDs
        pub Dids get(fn did): map hasher(blake2_128_concat) dock::did::Did
            => Option<DidDetailStorage<T>>;
        /// Stores keys of a DID as (DID, IncId) -> DidKey. Does not check if the same key is being added multiple times to the same DID.
        pub DidKeys get(fn did_key): double_map hasher(blake2_128_concat) dock::did::Did, hasher(identity) IncId => Option<DidKey>;
        /// Stores controlled - controller) pairs of a DID as (DID, DID) -> bool.
        pub DidControllers get(fn is_controller): double_map hasher(blake2_128_concat) dock::did::Did, hasher(blake2_128_concat) Did => bool;
        /// Stores service endpoints of a DID as (DID, endpoint id) -> bool.
        pub DidServiceEndpoints get(fn did_service_endpoints): double_map hasher(blake2_128_concat) dock::did::Did, hasher(blake2_128_concat) Vec<u8> => Option<ServiceEndpoint>;
    }
    add_extra_genesis {
        config(dids): Vec<(Did, DidKey)>;
        build(|slef: &Self| {
            debug_assert!({
                let mut dedup: Vec<&Did> = slef.dids.iter().map(|(d, _kd)| d).collect();
                dedup.sort();
                dedup.dedup();
                slef.dids.len() == dedup.len()
            });
            let block_no: T::BlockNumber = 0u32.into();
            for (did, key) in slef.dids.iter() {
                let mut key_id = IncId::new();
                key_id.inc();
                Dids::<T>::insert(did, DidDetailStorage::from_on_chain_detail(
                        key_id,
                        1,
                        1,
                        block_no,
                    ));
                DidKeys::insert(&did, key_id, key);
            }
        })
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin, T: Debug {
        fn deposit_event() = default;

        type Error = Error<T>;

        const MaxDidDocRefSize: u16 = T::MaxDidDocRefSize::get();
        const DidDocRefPerByteWeight: Weight = T::DidDocRefPerByteWeight::get();
        const MaxServiceEndpointIdSize: u16 = T::MaxServiceEndpointIdSize::get();
        const ServiceEndpointIdPerByteWeight: Weight = T::ServiceEndpointIdPerByteWeight::get();
        const MaxServiceEndpointOrigins: u16 = T::MaxServiceEndpointOrigins::get();
        const MaxServiceEndpointOriginSize: u16 = T::MaxServiceEndpointOriginSize::get();
        const ServiceEndpointOriginPerByteWeight: Weight = T::ServiceEndpointOriginPerByteWeight::get();

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
        /// `AUTHENTICATION`, `ASSERTION` and `CAPABILITY_INVOCATION`. This is because keys without any verification
        /// relation won't be usable and these 3 keep the logic most similar to before. Avoiding more
        /// explicit argument to keep the caller's experience simple.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight + controllers.len() as Weight + 1)]
        pub fn new_onchain(origin, did: dock::did::Did, keys: Vec<DidKey>, controllers: BTreeSet<Did>) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::new_onchain_(did, keys, controllers)
        }

        /// Add more keys from DID doc. Does not check if the key is already added or it has duplicate
        /// verification relationships
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        fn add_keys(origin, keys: AddKeys<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &keys, &sig, {
                ensure!(keys.len() > 0, Error::<T>::NoKeyProvided);
            });
            Module::<T>::add_keys_(keys)
        }

        /// Remove keys from DID doc. This is an atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        fn remove_keys(origin, keys: RemoveKeys<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &keys, &sig, {
                ensure!(keys.len() > 0, Error::<T>::NoKeyProvided);
            });
            Module::<T>::remove_keys_(keys)
        }

        /// Add new controllers. Does not check if the controller being added has any key or is even
        /// a DID that exists on or off chain. Does not check if the controller is already added.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn add_controllers(origin, controllers: AddControllers<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &controllers, &sig, {
                ensure!(controllers.len() > 0, Error::<T>::NoControllerProvided);
            });
            Module::<T>::add_controllers_(controllers)
        }

        /// Remove controllers. This's atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn remove_controllers(origin, controllers: RemoveControllers<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &controllers, &sig, {
                ensure!(controllers.len() > 0, Error::<T>::NoControllerProvided);
            });
            Module::<T>::remove_controllers_(controllers)
        }

        /// Add a single service endpoint.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn add_service_endpoint(origin, service_endpoint: AddServiceEndpoint<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &service_endpoint, &sig, {
                ensure!(!service_endpoint.id.is_empty(), Error::<T>::InvalidServiceEndpoint);
                ensure!(
                    T::MaxServiceEndpointIdSize::get() as usize >= service_endpoint.id.len(),
                    Error::<T>::InvalidServiceEndpoint
                );
                ensure!(service_endpoint.endpoint.is_valid(T::MaxServiceEndpointOrigins::get() as usize, T::MaxServiceEndpointOriginSize::get() as usize), Error::<T>::InvalidServiceEndpoint);
            });
            Module::<T>::add_service_endpoint_(service_endpoint)
        }

        /// Remove a single service endpoint.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        fn remove_service_endpoint(origin, service_endpoint: RemoveServiceEndpoint<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &service_endpoint, &sig, {
                ensure!(!service_endpoint.id.is_empty(), Error::<T>::InvalidServiceEndpoint);
            });
            Module::<T>::remove_service_endpoint_(service_endpoint)
        }

        /// Remove the on-chain DID. This will remove this DID's keys, controllers and service endpoints. But it won't remove storage
        /// entries for DIDs that it controls. However, the authorization logic ensures that once a DID is removed, it
        /// loses its ability to control any DID.
        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_onchain_did(origin, removal: dock::did::DidRemoval<T>, sig: DidSignature) -> DispatchResult {
            ensure_signed_origin_and_control_signed_payload!(origin, &removal, &sig, {});
            Self::remove_onchain_did_(removal)
        }
    }
}

impl<T: Trait> Module<T>
where
    T: Debug,
{
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

    fn new_onchain_(did: Did, keys: Vec<DidKey>, mut controllers: BTreeSet<Did>) -> DispatchResult {
        // DID is not registered already
        ensure!(!Dids::<T>::contains_key(did), Error::<T>::DidAlreadyExists);

        if keys.is_empty() && controllers.is_empty() {
            fail!(Error::<T>::NoControllerProvided)
        }

        let (keys_to_insert, controller_keys_count) = Self::prepare_keys_to_insert(keys)?;

        let mut last_key_id = IncId::new();
        for (key, key_id) in keys_to_insert.into_iter().zip(&mut last_key_id) {
            DidKeys::insert(&did, key_id, key);
        }
        // Make self controlled if needed
        if controller_keys_count > 0 {
            controllers.insert(did);
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, &ctrl, true);
        }

        // Nonce will start from current block number
        let nonce = <system::Module<T>>::block_number();
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                last_key_id,
                controller_keys_count,
                controllers.len() as u32,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OnChainDidAdded(did)).into(),
        );
        Ok(())
    }

    fn add_keys_(AddKeys { did, nonce, keys }: AddKeys<T>) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;

        // If DID was not self controlled first, check if it can become by looking
        let (keys_to_insert, controller_keys_count) = Self::prepare_keys_to_insert(keys)?;

        // Make self controlled if needed
        let add_self_controlled = controller_keys_count > 0 && !Self::is_self_controlled(&did);
        if add_self_controlled {
            DidControllers::insert(&did, &did, true);
        }

        let mut last_key_id = did_detail.last_key_id;
        for (key, key_id) in keys_to_insert.iter().zip(&mut last_key_id) {
            DidKeys::insert(did, key_id, key)
        }

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidKeysAdded(did)).into(),
        );

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                last_key_id,
                did_detail.active_controller_keys + controller_keys_count,
                did_detail.active_controllers + add_self_controlled as u32,
                nonce,
            ),
        );

        Ok(())
    }

    fn remove_keys_(RemoveKeys { did, nonce, keys }: RemoveKeys<T>) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;

        let mut controller_keys_count = 0;
        for key_id in &keys {
            let key = DidKeys::get(&did, key_id).ok_or(Error::<T>::NoKeyForDid)?;

            if key.can_control() {
                controller_keys_count += 1;
            }
        }

        for key in &keys {
            DidKeys::remove(did, key);
        }

        let active_controller_keys = did_detail.active_controller_keys - controller_keys_count;

        // If no self-control keys exist for the given DID, remove self-control
        let remove_self_controlled = active_controller_keys == 0 && Self::is_self_controlled(&did);
        if remove_self_controlled {
            DidControllers::remove(&did, &did);
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                active_controller_keys,
                did_detail.active_controllers - remove_self_controlled as u32,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidKeysRemoved(did)).into(),
        );

        Ok(())
    }

    fn add_controllers_(
        AddControllers {
            did,
            nonce,
            controllers,
        }: AddControllers<T>,
    ) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;

        for ctrl in &controllers {
            if Self::is_controller(&did, ctrl) {
                fail!(Error::<T>::ControllerIsAlreadyAdded)
            }
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, &ctrl, true);
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.active_controller_keys,
                did_detail.active_controllers + controllers.len() as u32,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidControllersAdded(did)).into(),
        );

        Ok(())
    }

    fn remove_controllers_(
        RemoveControllers {
            did,
            nonce,
            controllers,
        }: RemoveControllers<T>,
    ) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;

        for controller_did in &controllers {
            if !Self::is_controller(&did, controller_did) {
                fail!(Error::<T>::NoControllerForDid)
            }
        }

        for controller_did in &controllers {
            DidControllers::remove(&did, controller_did);
        }

        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.active_controller_keys,
                did_detail.active_controllers - controllers.len() as u32,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidControllersRemoved(did)).into(),
        );

        Ok(())
    }

    fn add_service_endpoint_(
        AddServiceEndpoint {
            did,
            id,
            endpoint,
            nonce,
        }: AddServiceEndpoint<T>,
    ) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;
        if Self::did_service_endpoints(&did, &id).is_some() {
            fail!(Error::<T>::ServiceEndpointAlreadyExists)
        }
        DidServiceEndpoints::insert(did, id, endpoint);
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.active_controller_keys,
                did_detail.active_controllers,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidServiceEndpointAdded(did)).into(),
        );
        Ok(())
    }

    fn remove_service_endpoint_(
        RemoveServiceEndpoint { did, id, nonce }: RemoveServiceEndpoint<T>,
    ) -> DispatchResult {
        let did_detail = Self::get_on_chain_did_detail_for_update(&did, nonce)?;
        if Self::did_service_endpoints(&did, &id).is_none() {
            fail!(Error::<T>::ServiceEndpointDoesNotExist)
        }
        DidServiceEndpoints::remove(did, id);
        Dids::<T>::insert(
            did,
            DidDetailStorage::from_on_chain_detail(
                did_detail.last_key_id,
                did_detail.active_controller_keys,
                did_detail.active_controllers,
                nonce,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::DidServiceEndpointRemoved(did)).into(),
        );
        Ok(())
    }

    fn remove_onchain_did_(DidRemoval { did, nonce }: DidRemoval<T>) -> DispatchResult {
        let _ = Self::get_on_chain_did_detail_for_update(&did, nonce)?;
        DidKeys::remove_prefix(did);
        DidControllers::remove_prefix(did);
        DidServiceEndpoints::remove_prefix(did);
        Dids::<T>::remove(did);
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&did)],
            <T as Trait>::Event::from(Event::OnChainDidRemoved(did)).into(),
        );
        Ok(())
    }

    pub fn insert_did_detail(did: Did, detail: DidDetail<T>) {
        Dids::<T>::insert(did, DidDetailStorage::OnChain(detail));
    }

    /// Prepare `DidKey`s to insert. The DID is assumed to be self controlled as well if there is any key
    /// that is capable of invoking a capability. Returns the keys along with the
    /// amount of controller keys being met. The following logic is contentious.
    fn prepare_keys_to_insert(keys: Vec<DidKey>) -> Result<(Vec<DidKey>, u32), DispatchError> {
        let mut controller_keys_count = 0;
        let mut keys_to_insert = Vec::with_capacity(keys.len());
        for key in keys {
            let key = if key.ver_rels.is_empty() {
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

    /// Return `did`'s key with id `key_id` only if it can authenticate or control otherwise throw error
    pub fn get_key_for_auth_or_control(
        did: &Did,
        key_id: IncId,
    ) -> Result<PublicKey, DispatchError> {
        if let Some(did_key) = DidKeys::get(did, key_id) {
            if did_key.can_authenticate_or_control() {
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
    /// controller of the DID and must have a key with `CAPABILITY_INVOCATION` verification relationship
    pub fn verify_sig_from_controller<A>(
        action: &A,
        sig: &DidSignature,
    ) -> Result<bool, DispatchError>
    where
        A: Action<T, Target = Did>,
    {
        Self::ensure_controller(&action.target(), &sig.did)?;
        let signer_pubkey = Self::get_key_for_control(&sig.did, sig.key_id)?;

        sig.verify::<T>(&action.to_state_change().encode(), &signer_pubkey)
    }

    pub fn verify_sig_from_auth_or_control_key(
        msg: &[u8],
        sig: &DidSignature,
    ) -> Result<bool, DispatchError> {
        let signer_pubkey = Self::get_key_for_auth_or_control(&sig.did, sig.key_id)?;
        sig.verify::<T>(msg, &signer_pubkey)
    }

    /// Get DID detail for on-chain DID if given nonce is correct, i.e. 1 more than the current nonce.
    /// This is used for update
    pub fn get_on_chain_did_detail_for_update(
        did: &Did,
        new_nonce: impl Into<T::BlockNumber>,
    ) -> Result<DidDetail<T>, DispatchError> {
        let did_detail_storage = Self::get_on_chain_did_detail(did)?;
        if new_nonce.into() != did_detail_storage.next_nonce() {
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
        active_controller_keys: u32,
        active_controllers: u32,
        nonce: <Test as frame_system::Config>::BlockNumber,
    ) {
        let did_detail = DIDModule::get_on_chain_did_detail(did).unwrap();
        assert_eq!(did_detail.last_key_id, last_key_id.into());
        assert_eq!(did_detail.active_controller_keys, active_controller_keys);
        assert_eq!(did_detail.active_controllers, active_controllers);
        assert_eq!(
            did_detail.nonce,
            <Test as system::Config>::BlockNumber::from(nonce)
        );
    }

    /// Ensure that all keys in storage corresponding to the DID are deleted. This check should be
    /// performed when a DID is removed.
    fn ensure_onchain_did_gone(did: &Did) {
        assert!(DIDModule::did(did).is_none());
        let mut i = 0;
        for (_, _) in DidKeys::iter_prefix(did) {
            i += 1;
        }
        assert_eq!(i, 0);
        for (_, _) in DidControllers::iter_prefix(did) {
            i += 1;
        }
        assert_eq!(i, 0);
        for (_, _) in DidServiceEndpoints::iter_prefix(did) {
            i += 1;
        }
        assert_eq!(i, 0);
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
            let (owner, fetched_ref) = did_detail_storage.to_off_chain_did_owner_and_doc_ref();
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
            let (_, fetched_ref) = did_detail_storage.to_off_chain_did_owner_and_doc_ref();
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
                DIDModule::new_onchain(
                    Origin::signed(alice),
                    did_1.clone(),
                    vec![],
                    vec![].into_iter().collect()
                ),
                Error::<Test>::NoControllerProvided
            );

            run_to_block(20);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![].into_iter().collect(),
                vec![controller_1].into_iter().collect()
            ));

            assert!(!DIDModule::is_offchain_did(&did_1).unwrap());
            assert!(DIDModule::is_onchain_did(&did_1).unwrap());

            assert!(!DIDModule::is_self_controlled(&did_1));
            assert!(!DIDModule::is_controller(&did_1, &controller_2));
            assert!(DIDModule::is_controller(&did_1, &controller_1));

            check_did_detail(&did_1, 0, 0, 1, 20);

            assert_noop!(
                DIDModule::new_onchain(
                    Origin::signed(alice),
                    did_1.clone(),
                    vec![].into_iter().collect(),
                    vec![controller_1].into_iter().collect()
                ),
                Error::<Test>::DidAlreadyExists
            );

            run_to_block(55);
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![].into_iter().collect(),
                vec![did_1, controller_1, controller_2]
                    .into_iter()
                    .collect()
            ));

            assert!(!DIDModule::is_offchain_did(&did_2).unwrap());
            assert!(DIDModule::is_onchain_did(&did_2).unwrap());

            assert!(!DIDModule::is_self_controlled(&did_2));
            assert!(DIDModule::is_controller(&did_2, &did_1));
            assert!(DIDModule::is_controller(&did_2, &controller_1));
            assert!(DIDModule::is_controller(&did_2, &controller_2));

            check_did_detail(&did_2, 0, 0, 3, 55);
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
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 1, 5);

            let key_1 = DidKeys::get(&did_1, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_1);

            run_to_block(6);

            // DID controls itself and specifies another controller as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![did_1].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 2, 6);

            let key_2 = DidKeys::get(&did_2, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_2);

            run_to_block(7);

            // DID controls itself and specifies multiple another controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![did_1, did_2].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 1, 3, 7);

            let key_3 = DidKeys::get(&did_3, IncId::from(1u32)).unwrap();
            not_key_agreement(&key_3);

            run_to_block(8);

            // Adding x25519 key does not make the DID self controlled
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 0, 0, 8);

            let key_4 = DidKeys::get(&did_4, IncId::from(1u32)).unwrap();
            only_key_agreement(&key_4);

            // x25519 key cannot be added for incompatible relationship types
            for vr in vec![
                VerRelType::AUTHENTICATION,
                VerRelType::ASSERTION,
                VerRelType::CAPABILITY_INVOCATION,
            ] {
                assert_noop!(
                    DIDModule::new_onchain(
                        Origin::signed(alice),
                        did_5.clone(),
                        vec![DidKey {
                            key: PublicKey::x25519(pk_ed),
                            ver_rels: vr.into()
                        }],
                        vec![].into_iter().collect()
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
                            ver_rels: VerRelType::KEY_AGREEMENT.into()
                        }],
                        vec![].into_iter().collect()
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
                        ver_rels: VerRelType::CAPABILITY_INVOCATION.into()
                    }],
                    vec![].into_iter().collect()
                ));
                assert!(DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, IncId::from(1u32)).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_authenticate());
                assert!(key.can_control());
                assert!(key.can_authenticate_or_control());
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 1, 1, 10);
            }

            run_to_block(13);

            // Add single key with single relationship and but do not specify relationship as `capabilityInvocation`
            for (did, pk, vr) in vec![
                (
                    [72; DID_BYTE_SIZE],
                    PublicKey::sr25519(pk_sr),
                    VerRelType::ASSERTION,
                ),
                (
                    [73; DID_BYTE_SIZE],
                    PublicKey::ed25519(pk_ed),
                    VerRelType::ASSERTION,
                ),
                ([74; DID_BYTE_SIZE], pk_secp.clone(), VerRelType::ASSERTION),
                (
                    [75; DID_BYTE_SIZE],
                    PublicKey::sr25519(pk_sr),
                    VerRelType::AUTHENTICATION,
                ),
                (
                    [76; DID_BYTE_SIZE],
                    PublicKey::ed25519(pk_ed),
                    VerRelType::AUTHENTICATION,
                ),
                (
                    [77; DID_BYTE_SIZE],
                    pk_secp.clone(),
                    VerRelType::AUTHENTICATION,
                ),
            ] {
                assert_ok!(DIDModule::new_onchain(
                    Origin::signed(alice),
                    did.clone(),
                    vec![DidKey {
                        key: pk,
                        ver_rels: vr.into()
                    }],
                    vec![].into_iter().collect()
                ));
                assert!(!DIDModule::is_self_controlled(&did));
                let key = DidKeys::get(&did, IncId::from(1u32)).unwrap();
                assert!(key.can_sign());
                assert!(!key.can_control());
                if vr == VerRelType::AUTHENTICATION {
                    assert!(key.can_authenticate());
                    assert!(key.can_authenticate_or_control());
                }
                assert!(!key.for_key_agreement());
                check_did_detail(&did, 1, 0, 0, 13);
            }

            run_to_block(19);

            // Add single key, specify multiple relationships and but do not specify relationship as `capabilityInvocation`
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_8.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: (VerRelType::AUTHENTICATION | VerRelType::ASSERTION).into()
                }],
                vec![].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_8));
            let key_8 = DidKeys::get(&did_8, IncId::from(1u32)).unwrap();
            assert!(key_8.can_sign());
            assert!(key_8.can_authenticate());
            assert!(!key_8.can_control());
            check_did_detail(&did_8, 1, 0, 0, 19);

            run_to_block(20);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_9.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::ASSERTION.into()
                    },
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: (VerRelType::ASSERTION | VerRelType::AUTHENTICATION).into()
                    },
                ],
                vec![].into_iter().collect()
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
            check_did_detail(&did_9, 3, 0, 0, 20);

            run_to_block(22);

            // Add multiple keys and specify multiple relationships
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_10.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::ASSERTION).into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::ASSERTION.into()
                    },
                    DidKey {
                        key: pk_secp,
                        ver_rels: VerRelType::CAPABILITY_INVOCATION.into()
                    },
                ],
                vec![].into_iter().collect()
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
            check_did_detail(&did_10, 3, 1, 1, 22);

            run_to_block(23);

            // Add multiple keys, specify multiple relationships and other controllers as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_11.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::ASSERTION).into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::CAPABILITY_INVOCATION.into()
                    },
                ],
                vec![did_1, did_2].into_iter().collect()
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
            check_did_detail(&did_11, 2, 1, 3, 23);
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
                    ver_rels: VerRelType::AUTHENTICATION.into()
                }],
                vec![controller_1].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_1));
            assert!(DIDModule::is_controller(&did_1, &controller_1));
            check_did_detail(&did_1, 1, 0, 1, 10);

            run_to_block(11);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::ASSERTION.into()
                }],
                vec![controller_2].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            assert!(DIDModule::is_controller(&did_2, &controller_2));
            check_did_detail(&did_2, 1, 0, 1, 11);

            run_to_block(12);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::KEY_AGREEMENT.into()
                }],
                vec![controller_3].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_3));
            assert!(DIDModule::is_controller(&did_3, &controller_3));
            check_did_detail(&did_3, 1, 0, 1, 12);

            run_to_block(13);

            // DID does not control itself, some other DID does
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::ASSERTION.into()
                    }
                ],
                vec![controller_4].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_4));
            assert!(DIDModule::is_controller(&did_4, &controller_4));
            check_did_detail(&did_4, 2, 0, 1, 13);

            run_to_block(14);

            // DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_5.clone(),
                vec![
                    DidKey {
                        key: pk_secp.clone(),
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::CAPABILITY_INVOCATION)
                            .into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::ASSERTION.into()
                    }
                ],
                vec![controller_1].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_5));
            assert!(DIDModule::is_controller(&did_5, &controller_1));
            check_did_detail(&did_5, 2, 1, 2, 14);

            run_to_block(15);

            // DID has 2 keys to control itself and another DID
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_6.clone(),
                vec![
                    DidKey {
                        key: pk_secp,
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::CAPABILITY_INVOCATION)
                            .into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::ASSERTION | VerRelType::CAPABILITY_INVOCATION)
                            .into()
                    }
                ],
                vec![controller_1].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_6));
            assert!(DIDModule::is_controller(&did_6, &controller_1));
            check_did_detail(&did_6, 2, 2, 2, 15);
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
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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

            let add_keys = AddKeys {
                did: did_1.clone(),
                keys: vec![DidKey {
                    key: PublicKey::sr25519(pk_sr_1),
                    ver_rels: VerRelType::NONE.into(),
                }],
                nonce: 5,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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
                Error::<Test>::OnlyControllerCanUpdate
            );

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr_1),
                        ver_rels: VerRelType::NONE.into()
                    },
                    DidKey {
                        key: PublicKey::sr25519(pk_sr_2),
                        ver_rels: VerRelType::NONE.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_2),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                ],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 3, 2, 1, 5);

            run_to_block(7);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed_1),
                    ver_rels: VerRelType::AUTHENTICATION.into()
                }],
                vec![did_1].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 0, 1, 7);

            run_to_block(10);

            // Since did_2 does not control itself, it cannot add keys to itself
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp_1.clone(),
                    ver_rels: VerRelType::NONE.into(),
                }],
                nonce: 7 + 1,
            };
            let sig = SigValue::ed25519(&add_keys.to_state_change().encode(), &pair_ed_1);
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
                        ver_rels: VerRelType::NONE.into(),
                    }],
                    nonce,
                };
                let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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
                    ver_rels: VerRelType::NONE.into(),
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
                    ver_rels: VerRelType::NONE.into(),
                }],
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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
                    ver_rels: VerRelType::KEY_AGREEMENT.into(),
                }],
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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
                    ver_rels: VerRelType::KEY_AGREEMENT.into(),
                }],
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_1);
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
            check_did_detail(&did_2, 2, 0, 1, 8);

            // Add many keys
            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![
                    DidKey {
                        key: PublicKey::x25519(pk_sr_2),
                        ver_rels: VerRelType::KEY_AGREEMENT.into(),
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::ASSERTION.into(),
                    },
                    DidKey {
                        key: pk_secp_2,
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::ASSERTION).into(),
                    },
                ],
                nonce: 8 + 1,
            };

            // Controller uses a key without the capability to update DID
            let sig = SigValue::ed25519(&add_keys.to_state_change().encode(), &pair_ed_2);
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
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr_2);
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
            check_did_detail(&did_2, 5, 0, 1, 9);
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
                    DidKey::new(PublicKey::ed25519(pk_ed_2), VerRelType::ASSERTION),
                    DidKey::new(PublicKey::sr25519(pk_sr_2), VerRelType::AUTHENTICATION),
                ],
                vec![did_2].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 4, 2, 2, 2);

            run_to_block(5);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1))
                ],
                vec![did_1].into_iter().collect()
            ));
            check_did_detail(&did_2, 2, 1, 2, 5);

            run_to_block(10);

            // Nonce should be 1 greater than existing 7, i.e. 8
            for nonce in vec![1, 2, 4, 5, 10, 10000] {
                let remove_keys = RemoveKeys {
                    did: did_2.clone(),
                    keys: vec![2u32.into()].into_iter().collect(),
                    nonce,
                };
                let sig = SigValue::sr25519(&remove_keys.to_state_change().encode(), &pair_sr_1);
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
                keys: vec![1u32.into(), 3u32.into(), 5u32.into()]
                    .into_iter()
                    .collect(),
                nonce: 3,
            };
            let sig = SigValue::ed25519(&remove_keys.to_state_change().encode(), &pair_ed_1);
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
                keys: vec![1u32.into()].into_iter().collect(),
                nonce: 3,
            };
            let sig = SigValue::ed25519(&remove_keys.to_state_change().encode(), &pair_ed_1);
            assert_ok!(DIDModule::remove_keys(
                Origin::signed(alice),
                remove_keys,
                DidSignature {
                    did: did_1.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));
            check_did_detail(&did_1, 4, 1, 2, 3);

            let remove_keys = RemoveKeys {
                did: did_1.clone(),
                keys: vec![3u32.into()].into_iter().collect(),
                nonce: 4,
            };
            let sig = SigValue::sr25519(&remove_keys.to_state_change().encode(), &pair_sr_1);
            assert_ok!(DIDModule::remove_keys(
                Origin::signed(alice),
                remove_keys,
                DidSignature {
                    did: did_2.clone(),
                    key_id: 2u32.into(),
                    sig
                }
            ));

            let did_5 = [54; DID_BYTE_SIZE];
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_5.clone(),
                vec![DidKey::new_with_all_relationships(PublicKey::sr25519(
                    pk_sr_1
                ))]
                .into_iter()
                .collect(),
                vec![did_2].into_iter().collect()
            ));
            check_did_detail(&did_5, 1, 1, 2, 10);

            let remove_keys = RemoveKeys {
                did: did_5.clone(),
                keys: vec![1u32.into()].into_iter().collect(),
                nonce: 11,
            };
            let sig = SigValue::sr25519(&remove_keys.to_state_change().encode(), &pair_sr_1);
            assert_ok!(DIDModule::remove_keys(
                Origin::signed(alice),
                remove_keys,
                DidSignature {
                    did: did_5.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            check_did_detail(&did_5, 1, 0, 1, 11);

            let remove_controllers = RemoveControllers {
                did: did_5.clone(),
                controllers: vec![did_2].into_iter().collect(),
                nonce: 12,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
            check_did_detail(&did_5, 1, 0, 0, 12);
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
                    DidKey::new(PublicKey::ed25519(pk_ed_2), VerRelType::ASSERTION),
                    DidKey::new(PublicKey::sr25519(pk_sr_2), VerRelType::AUTHENTICATION),
                ],
                vec![did_2].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 4, 2, 2, 2);

            run_to_block(5);

            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![
                    DidKey {
                        key: PublicKey::ed25519(pk_ed_1),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                    DidKey::new_with_all_relationships(PublicKey::sr25519(pk_sr_1))
                ],
                vec![did_1].into_iter().collect()
            ));
            check_did_detail(&did_2, 2, 1, 2, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![].into_iter().collect(),
                vec![did_1, did_2, did_3].into_iter().collect()
            ));
            check_did_detail(&did_3, 0, 0, 3, 5);

            run_to_block(10);

            // Nonce should be 1 greater than existing 7, i.e. 8
            for nonce in vec![1, 2, 4, 5, 10, 10000] {
                let remove_controllers = RemoveControllers {
                    did: did_2.clone(),
                    controllers: vec![did_1].into_iter().into_iter().collect(),
                    nonce,
                };
                let sig = SigValue::sr25519(
                    &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
                controllers: vec![did_1, did_2, did_3, [53; DID_BYTE_SIZE]]
                    .into_iter()
                    .collect(),
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
                Error::<Test>::NoControllerForDid
            );
            let remove_controllers = RemoveControllers {
                did: did_1.clone(),
                controllers: vec![did_1].into_iter().collect(),
                nonce: 3,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
            check_did_detail(&did_1, 4, 2, 1, 3);

            let remove_controllers = RemoveControllers {
                did: did_1.clone(),
                controllers: vec![did_2.into()].into_iter().collect(),
                nonce: 4,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
            check_did_detail(&did_1, 4, 2, 0, 4);

            let remove_controllers = RemoveControllers {
                did: did_3.clone(),
                controllers: vec![did_2.into()].into_iter().collect(),
                nonce: 6,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
                controllers: vec![did_1.into()].into_iter().collect(),
                nonce: 7,
            };
            check_did_detail(&did_3, 0, 0, 2, 6);
            let sig = SigValue::sr25519(
                &StateChange::RemoveControllers(Cow::Borrowed(&remove_controllers)).encode(),
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
                controllers: vec![].into_iter().collect(),
                nonce: 5,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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

            let add_controllers = AddControllers {
                did: did_1.clone(),
                controllers: vec![did_2].into_iter().collect(),
                nonce: 5,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
                Error::<Test>::OnlyControllerCanUpdate
            );

            // This DID controls itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![
                    DidKey {
                        key: pk_secp_1.clone(),
                        ver_rels: VerRelType::NONE.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: VerRelType::AUTHENTICATION.into()
                    },
                ],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 2, 1, 1, 5);

            run_to_block(6);

            // This DID is controlled by itself and another DID as well
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp_2.clone(),
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![did_1].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_3, 1, 1, 2, 6);

            run_to_block(10);
            // This DID does not control itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::AUTHENTICATION.into()
                }],
                vec![did_1].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 0, 1, 10);

            run_to_block(15);

            // Since did_2 does not control itself, it cannot controller to itself
            let add_controllers = AddControllers {
                did: did_2.clone(),
                controllers: vec![did_3].into_iter().collect(),
                nonce: 10 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
                    controllers: vec![did_3].into_iter().collect(),
                    nonce,
                };
                let sig = SigValue::secp256k1(
                    &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
                controllers: vec![did_3].into_iter().collect(),
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
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
            check_did_detail(&did_2, 1, 0, 2, 11);

            run_to_block(15);

            // Add many controllers
            let add_controllers = AddControllers {
                did: did_2.clone(),
                controllers: vec![did_4, did_5].into_iter().collect(),
                nonce: 11 + 1,
            };
            let sig = SigValue::secp256k1(
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
            check_did_detail(&did_2, 1, 0, 4, 12);
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
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![].into_iter().collect()
            ));

            run_to_block(10);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::x25519(pk_ed),
                    ver_rels: VerRelType::KEY_AGREEMENT.into()
                },],
                vec![did_1].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 0, 1, 10);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::ASSERTION.into(),
                }],
                nonce: 10 + 1,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr);
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
            check_did_detail(&did_2, 2, 0, 1, 11);

            run_to_block(20);

            let add_keys = AddKeys {
                did: did_2.clone(),
                keys: vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::CAPABILITY_INVOCATION.into(),
                }],
                nonce: 11 + 1,
            };
            let sig = SigValue::sr25519(&add_keys.to_state_change().encode(), &pair_sr);
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
            check_did_detail(&did_2, 3, 1, 2, 12);
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
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 1, 1, 5);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 1, 1, 5);

            run_to_block(7);

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: pk_secp.clone(),
                    ver_rels: VerRelType::NONE.into()
                },],
                vec![did_2].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 1, 2, 7);

            run_to_block(14);

            let add_controllers = AddControllers {
                did: did_4.clone(),
                controllers: vec![did_1].into_iter().collect(),
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddControllers(Cow::Borrowed(&add_controllers)).encode(),
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
            check_did_detail(&did_4, 1, 1, 3, 8);

            run_to_block(15);

            let add_keys = AddKeys {
                did: did_4.clone(),
                keys: vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::NONE.into(),
                }],
                nonce: 8 + 1,
            };
            let sig = SigValue::ed25519(&add_keys.to_state_change().encode(), &pair_ed);
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

    #[test]
    fn service_endpoints() {
        // Adding and removing service endpoints to a DID
        ext().execute_with(|| {
            let alice = 1u64;
            let did = [51; DID_BYTE_SIZE];

            let endpoint_1_id = vec![102; 50];
            let origins_1 = vec![vec![112; 100]];
            let endpoint_2_id = vec![202; 90];
            let origins_2 = vec![vec![212; 150], vec![225; 30]];

            let (pair_sr, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_sr = pair_sr.public().0;
            let (pair_ed, _, _) = ed25519::Pair::generate_with_phrase(None);
            let pk_ed = pair_ed.public().0;

            run_to_block(5);

            let add_service_endpoint = AddServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                endpoint: ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_1.clone(),
                },
                nonce: 5 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                &pair_sr,
            );

            // DID does not exist yet, thus no controller
            assert_noop!(
                DIDModule::add_service_endpoint(
                    Origin::signed(alice),
                    add_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::OnlyControllerCanUpdate
            );

            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did.clone(),
                vec![
                    DidKey {
                        key: PublicKey::sr25519(pk_sr),
                        ver_rels: VerRelType::NONE.into()
                    },
                    DidKey {
                        key: PublicKey::ed25519(pk_ed),
                        ver_rels: (VerRelType::AUTHENTICATION | VerRelType::ASSERTION).into()
                    },
                ],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did));
            check_did_detail(&did, 2, 1, 1, 5);

            run_to_block(10);

            // Non-control key cannot add endpoint
            let add_service_endpoint = AddServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                endpoint: ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_1.clone(),
                },
                nonce: 5 + 1,
            };
            let sig = SigValue::ed25519(
                &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                &pair_ed,
            );

            assert_noop!(
                DIDModule::add_service_endpoint(
                    Origin::signed(alice),
                    add_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::InsufficientVerificationRelationship
            );

            // Trying to add invalid endpoint fails
            for (id, ep) in vec![
                (
                    vec![], // Empty id not allowed
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: origins_1.clone(),
                    },
                ),
                (
                    vec![20; 512], // too big id not allowed
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: origins_1.clone(),
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::NONE, // Empty type not allowed
                        origins: origins_1.clone(),
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: vec![], // Empty origin not allowed
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: vec![vec![]], // Empty origin not allowed
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: vec![vec![45; 55], vec![]], // All provided origins mut be non-empty
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: vec![vec![30; 561]], // too big origin not allowed
                    },
                ),
                (
                    endpoint_1_id.clone(),
                    ServiceEndpoint {
                        types: ServiceEndpointType::LINKED_DOMAINS,
                        origins: vec![vec![30; 20]; 300], // too many origins not allowed
                    },
                ),
            ] {
                let add_service_endpoint = AddServiceEndpoint {
                    did: did.clone(),
                    id,
                    endpoint: ep,
                    nonce: 5 + 1,
                };
                let sig = SigValue::sr25519(
                    &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                    &pair_sr,
                );

                assert_noop!(
                    DIDModule::add_service_endpoint(
                        Origin::signed(alice),
                        add_service_endpoint.clone(),
                        DidSignature {
                            did: did.clone(),
                            key_id: 1u32.into(),
                            sig
                        }
                    ),
                    Error::<Test>::InvalidServiceEndpoint
                );
            }

            assert!(DIDModule::did_service_endpoints(&did, &endpoint_1_id).is_none());

            let add_service_endpoint = AddServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                endpoint: ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_1.clone(),
                },
                nonce: 5 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_ok!(DIDModule::add_service_endpoint(
                Origin::signed(alice),
                add_service_endpoint.clone(),
                DidSignature {
                    did: did.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));

            assert_eq!(
                DIDModule::did_service_endpoints(&did, &endpoint_1_id).unwrap(),
                ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_1.clone(),
                }
            );
            check_did_detail(&did, 2, 1, 1, 6);

            run_to_block(15);

            // Adding new endpoint with existing id fails
            let add_service_endpoint = AddServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                endpoint: ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_2.clone(),
                },
                nonce: 6 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_noop!(
                DIDModule::add_service_endpoint(
                    Origin::signed(alice),
                    add_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::ServiceEndpointAlreadyExists
            );

            let add_service_endpoint = AddServiceEndpoint {
                did: did.clone(),
                id: endpoint_2_id.clone(),
                endpoint: ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_2.clone(),
                },
                nonce: 6 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::AddServiceEndpoint(Cow::Borrowed(&add_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_ok!(DIDModule::add_service_endpoint(
                Origin::signed(alice),
                add_service_endpoint.clone(),
                DidSignature {
                    did: did.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));

            assert_eq!(
                DIDModule::did_service_endpoints(&did, &endpoint_2_id).unwrap(),
                ServiceEndpoint {
                    types: ServiceEndpointType::LINKED_DOMAINS,
                    origins: origins_2.clone(),
                }
            );
            check_did_detail(&did, 2, 1, 1, 7);

            run_to_block(16);

            // Non-control key cannot remove endpoint
            let rem_service_endpoint = RemoveServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                nonce: 7 + 1,
            };
            let sig = SigValue::ed25519(
                &StateChange::RemoveServiceEndpoint(Cow::Borrowed(&rem_service_endpoint)).encode(),
                &pair_ed,
            );

            assert_noop!(
                DIDModule::remove_service_endpoint(
                    Origin::signed(alice),
                    rem_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::InsufficientVerificationRelationship
            );

            // Invalid endpoint id fails
            let rem_service_endpoint = RemoveServiceEndpoint {
                did: did.clone(),
                id: vec![],
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveServiceEndpoint(Cow::Borrowed(&rem_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_noop!(
                DIDModule::remove_service_endpoint(
                    Origin::signed(alice),
                    rem_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::InvalidServiceEndpoint
            );

            let rem_service_endpoint = RemoveServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                nonce: 7 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveServiceEndpoint(Cow::Borrowed(&rem_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_ok!(DIDModule::remove_service_endpoint(
                Origin::signed(alice),
                rem_service_endpoint.clone(),
                DidSignature {
                    did: did.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(DIDModule::did_service_endpoints(&did, &endpoint_1_id).is_none());
            check_did_detail(&did, 2, 1, 1, 8);

            // id already removed, removing again fails
            let rem_service_endpoint = RemoveServiceEndpoint {
                did: did.clone(),
                id: endpoint_1_id.clone(),
                nonce: 8 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveServiceEndpoint(Cow::Borrowed(&rem_service_endpoint)).encode(),
                &pair_sr,
            );
            assert_noop!(
                DIDModule::remove_service_endpoint(
                    Origin::signed(alice),
                    rem_service_endpoint.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::ServiceEndpointDoesNotExist
            );

            let rem_service_endpoint = RemoveServiceEndpoint {
                did: did.clone(),
                id: endpoint_2_id.clone(),
                nonce: 8 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::RemoveServiceEndpoint(Cow::Borrowed(&rem_service_endpoint)).encode(),
                &pair_sr,
            );

            assert_ok!(DIDModule::remove_service_endpoint(
                Origin::signed(alice),
                rem_service_endpoint.clone(),
                DidSignature {
                    did: did.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            assert!(DIDModule::did_service_endpoints(&did, &endpoint_2_id).is_none());
            check_did_detail(&did, 2, 1, 1, 9);

            let rem_did = DidRemoval {
                did: did.clone(),
                nonce: 9 + 1,
            };
            let sig = SigValue::ed25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_ed,
            );

            assert_noop!(
                DIDModule::remove_onchain_did(
                    Origin::signed(alice),
                    rem_did.clone(),
                    DidSignature {
                        did: did.clone(),
                        key_id: 2u32.into(),
                        sig
                    }
                ),
                Error::<Test>::InsufficientVerificationRelationship
            );

            check_did_detail(&did, 2, 1, 1, 9);

            let rem_did = DidRemoval {
                did: did.clone(),
                nonce: 9 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );

            assert_ok!(DIDModule::remove_onchain_did(
                Origin::signed(alice),
                rem_did.clone(),
                DidSignature {
                    did: did.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            ensure_onchain_did_gone(&did);
        });
    }

    #[test]
    fn did_removal() {
        // Removing a DID
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

            run_to_block(5);

            // did_1 controls itself
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_1.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_1));
            check_did_detail(&did_1, 1, 1, 1, 5);

            run_to_block(10);

            // did_2 does not control itself but controlled by did_1
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_2.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::AUTHENTICATION.into()
                }],
                vec![did_1.clone()].into_iter().collect()
            ));
            assert!(!DIDModule::is_self_controlled(&did_2));
            check_did_detail(&did_2, 1, 0, 1, 10);

            run_to_block(15);

            // did_3 controls itself and also controlled by did_1
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_3.clone(),
                vec![DidKey {
                    key: PublicKey::ed25519(pk_ed),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![did_1.clone()].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_3));
            check_did_detail(&did_3, 1, 1, 2, 15);

            run_to_block(20);

            // did_4 controls itself and also controlled by did_3
            assert_ok!(DIDModule::new_onchain(
                Origin::signed(alice),
                did_4.clone(),
                vec![DidKey {
                    key: PublicKey::sr25519(pk_sr),
                    ver_rels: VerRelType::NONE.into()
                }],
                vec![did_3.clone()].into_iter().collect()
            ));
            assert!(DIDModule::is_self_controlled(&did_4));
            check_did_detail(&did_4, 1, 1, 2, 20);

            // did_2 does not control itself so it cannot remove itself
            let rem_did = DidRemoval {
                did: did_2.clone(),
                nonce: 10 + 1,
            };
            let sig = SigValue::ed25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_ed,
            );
            assert_noop!(
                DIDModule::remove_onchain_did(
                    Origin::signed(alice),
                    rem_did.clone(),
                    DidSignature {
                        did: did_2.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::OnlyControllerCanUpdate
            );
            check_did_detail(&did_2, 1, 0, 1, 10);

            // did_2 is controlled by did_1 so it can be removed by did_1
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );
            assert_ok!(DIDModule::remove_onchain_did(
                Origin::signed(alice),
                rem_did.clone(),
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            ensure_onchain_did_gone(&did_2);

            // Nonce should be correct when its deleted
            let rem_did = DidRemoval {
                did: did_3.clone(),
                nonce: 15,
            };
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );
            assert_noop!(
                DIDModule::remove_onchain_did(
                    Origin::signed(alice),
                    rem_did.clone(),
                    DidSignature {
                        did: did_1.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::IncorrectNonce
            );
            check_did_detail(&did_3, 1, 1, 2, 15);

            // did_3 is controlled by itself and did_1 and thus did_1 can remove it
            let rem_did = DidRemoval {
                did: did_3.clone(),
                nonce: 15 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );
            assert_ok!(DIDModule::remove_onchain_did(
                Origin::signed(alice),
                rem_did.clone(),
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            ensure_onchain_did_gone(&did_3);

            // did_4 is controlled by itself and did_3 but did_3 has been removed so it can no
            // longer remove did_4
            let rem_did = DidRemoval {
                did: did_4.clone(),
                nonce: 20 + 1,
            };
            let sig = SigValue::ed25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_ed,
            );
            assert_noop!(
                DIDModule::remove_onchain_did(
                    Origin::signed(alice),
                    rem_did.clone(),
                    DidSignature {
                        did: did_3.clone(),
                        key_id: 1u32.into(),
                        sig
                    }
                ),
                Error::<Test>::NoKeyForDid
            );
            check_did_detail(&did_4, 1, 1, 2, 20);

            // did_4 removes itself
            let rem_did = DidRemoval {
                did: did_4.clone(),
                nonce: 20 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );
            assert_ok!(DIDModule::remove_onchain_did(
                Origin::signed(alice),
                rem_did.clone(),
                DidSignature {
                    did: did_4.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            ensure_onchain_did_gone(&did_4);

            // did_1 removes itself
            let rem_did = DidRemoval {
                did: did_1.clone(),
                nonce: 5 + 1,
            };
            let sig = SigValue::sr25519(
                &StateChange::DidRemoval(Cow::Borrowed(&rem_did)).encode(),
                &pair_sr,
            );
            assert_ok!(DIDModule::remove_onchain_did(
                Origin::signed(alice),
                rem_did.clone(),
                DidSignature {
                    did: did_1.clone(),
                    key_id: 1u32.into(),
                    sig
                }
            ));
            ensure_onchain_did_gone(&did_1);
        });
    }
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
