use crate as dock;
use crate::keys_and_sigs::PublicKey;
use crate::util::with_nonce::NonceError;
use crate::util::*;
use crate::StorageVersion;
use crate::{deposit_indexed_event, impl_action_with_nonce, impl_bits_conversion, impl_wrapper};
use crate::{Action, ActionWithNonce};
pub use actions::*;
pub use base::{offchain, onchain, signature};
use codec::{Decode, Encode};
use core::fmt::Debug;
pub use details_aggregator::*;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure, fail,
    traits::Get, weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;
use sp_std::convert::{TryFrom, TryInto};
use sp_std::{collections::btree_set::BTreeSet, vec::Vec};

pub use base::*;
pub use controllers::Controller;
pub use keys::{DidKey, VerRelType};
pub use service_endpoints::ServiceEndpoint;

mod actions;
mod base;
mod controllers;
mod details_aggregator;
mod keys;
mod service_endpoints;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
pub mod tests;

/// The module's configuration trait.
pub trait Config: system::Config {
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
    #[derive(Eq, PartialEq, Clone)]
    pub enum Error for Module<T: Config> where T: Debug {
        /// Given public key is not of the correct size
        PublicKeySizeIncorrect,
        /// There is already a DID with same value
        DidAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        /// Signature type does not match public key type
        IncompatSigPubkey,
        /// Signature by DID failed verification
        InvalidSignature,
        DidDocRefTooBig,
        NotAnOffChainDid,
        DidNotOwnedByAccount,
        NoControllerProvided,
        /// The provided key type is not comptaible with the provided verification relationship
        IncompatibleVerificationRelation,
        CannotGetDetailForOffChainDid,
        CannotGetDetailForOnChainDid,
        NoKeyProvided,
        EmptyPayload,
        IncorrectNonce,
        /// Only controller of a DID can update the DID Doc
        OnlyControllerCanUpdate,
        NoKeyForDid,
        NoControllerForDid,
        /// The key does not have the required verification relationship
        InsufficientVerificationRelationship,
        ControllerIsAlreadyAdded,
        InvalidServiceEndpoint,
        ServiceEndpointAlreadyExists,
        ServiceEndpointDoesNotExist
    }
}

impl<T: Config + Debug> Error<T> {
    fn empty_payload_to(self, to_err: Self) -> Self {
        match self {
            Self::EmptyPayload => to_err,
            other => other,
        }
    }
}

impl<T: Config + Debug> From<NonceError> for Error<T> {
    fn from(NonceError::IncorrectNonce: NonceError) -> Self {
        Self::IncorrectNonce
    }
}

decl_event!(
    pub enum Event {
        OffChainDidAdded(Did, OffChainDidDocRef),
        OffChainDidUpdated(Did, OffChainDidDocRef),
        OffChainDidRemoved(Did),
        OnChainDidAdded(Did),
        DidKeysAdded(Did),
        DidKeysRemoved(Did),
        DidControllersAdded(Did),
        DidControllersRemoved(Did),
        DidServiceEndpointAdded(Did),
        DidServiceEndpointRemoved(Did),
        OnChainDidRemoved(Did),
    }
);

decl_storage! {
    trait Store for Module<T: Config> as DIDModule where T: Debug {
        /// Stores details of off-chain and on-chain DIDs
        pub Dids get(fn did): map hasher(blake2_128_concat) Did => Option<StoredDidDetails<T>>;
        /// Stores keys of a DID as (DID, IncId) -> DidKey. Does not check if the same key is being added multiple times to the same DID.
        pub DidKeys get(fn did_key): double_map hasher(blake2_128_concat) Did, hasher(identity) IncId => Option<DidKey>;
        /// Stores controlled - controller pairs of a DID as (DID, DID) -> zero-sized record. If a record exists, then the controller is bound.
        pub DidControllers get(fn bound_controller): double_map hasher(blake2_128_concat) Did, hasher(blake2_128_concat) Controller => Option<()>;
        /// Stores service endpoints of a DID as (DID, endpoint id) -> ServiceEndpoint.
        pub DidServiceEndpoints get(fn did_service_endpoints): double_map hasher(blake2_128_concat) Did, hasher(blake2_128_concat) WrappedBytes => Option<ServiceEndpoint>;

        pub Version get(fn storage_version): StorageVersion;
    }
    add_extra_genesis {
        config(dids): Vec<(Did, DidKey)>;
        build(|this: &Self| {
            debug_assert!({
                let dedup: BTreeSet<&Did> = this.dids.iter().map(|(d, _kd)| d).collect();
                this.dids.len() == dedup.len()
            });
            debug_assert!({
                this.dids.iter().all(|(_, key)| key.can_control())
            });

            for (did, key) in &this.dids {
                let mut key_id = IncId::new();
                key_id.inc();
                let did_details = StoredOnChainDidDetails::new(
                    OnChainDidDetails::new(key_id, 1u32, 1u32),
                );

                <Module<T>>::insert_did_details(*did, did_details);
                DidKeys::insert(did, key_id, key);
                DidControllers::insert(did, Controller(*did), ());
            }
        })
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        pub fn deposit_event() = default;

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
            let did_owner = ensure_signed(origin)?.into();

            Self::new_offchain_(did_owner, did, did_doc_ref)?;
            Ok(())
        }

        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1) + did_doc_ref.len() as u64 * T::DidDocRefPerByteWeight::get()]
        pub fn set_offchain_did_doc_ref(origin, did: dock::did::Did, did_doc_ref: OffChainDidDocRef) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            Self::set_offchain_did_doc_ref_(caller, did, did_doc_ref)?;
            Ok(())
        }

        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_offchain_did(origin, did: dock::did::Did) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            Self::remove_offchain_did_(caller, did)?;
            Ok(())
        }

        /// Create new DID.
        /// If no `keys` are provided, then its a keyless DID and at least 1 `controllers` must be provided.
        /// If any `keys` are provided, but they have an empty `ver_rel`, then its set to a vector with variants
        /// `AUTHENTICATION`, `ASSERTION` and `CAPABILITY_INVOCATION`. This is because keys without any verification
        /// relation won't be usable and these 3 keep the logic most similar to before. Avoiding more
        /// explicit argument to keep the caller's experience simple.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + Module::<T>::key_counts(keys).sr25519 as Weight + controllers.len() as Weight + 1)]
        pub fn new_onchain(origin, did: dock::did::Did, keys: Vec<DidKey>, controllers: BTreeSet<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::new_onchain_(did, keys, controllers)?;
            Ok(())
        }

        /// Add more keys from DID doc. Does not check if the key is already added or it has duplicate
        /// verification relationships
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        pub fn add_keys(origin, keys: AddKeys<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::add_keys_, keys, sig)
                .map_err(|err| err.empty_payload_to(Error::<T>::NoKeyProvided))?;
            Ok(())
        }

        /// Remove keys from DID doc. This is an atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Weights are not accurate as each DidKey can have different cost depending on type and no of relationships
        #[weight = T::DbWeight::get().reads_writes(1, 1 + keys.len() as Weight)]
        pub fn remove_keys(origin, keys: RemoveKeys<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::remove_keys_, keys, sig)
                .map_err(|err| err.empty_payload_to(Error::<T>::NoKeyProvided))?;
            Ok(())
        }

        /// Add new controllers. Does not check if the controller being added has any key or is even
        /// a DID that exists on or off chain. Does not check if the controller is already added.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn add_controllers(origin, controllers: AddControllers<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::add_controllers_, controllers, sig)
                .map_err(|err| err.empty_payload_to(Error::<T>::NoControllerProvided))?;
            Ok(())
        }

        /// Remove controllers. This is an atomic operation meaning that it will either remove all keys or do nothing.
        /// # **Note that removing all might make DID unusable**.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_controllers(origin, controllers: RemoveControllers<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::remove_controllers_, controllers, sig)
                .map_err(|err| err.empty_payload_to(Error::<T>::NoControllerProvided))?;
            Ok(())
        }

        /// Add a single service endpoint.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn add_service_endpoint(origin, service_endpoint: AddServiceEndpoint<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::add_service_endpoint_, service_endpoint, sig)?;
            Ok(())
        }

        /// Remove a single service endpoint.
        // TODO: Fix weights
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_service_endpoint(origin, service_endpoint: RemoveServiceEndpoint<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::remove_service_endpoint_, service_endpoint, sig)?;
            Ok(())
        }

        /// Remove the on-chain DID. This will remove this DID's keys, controllers and service endpoints. But it won't remove storage
        /// entries for DIDs that it controls. However, the authorization logic ensures that once a DID is removed, it
        /// loses its ability to control any DID.
        // TODO: Fix weight
        #[weight = T::DbWeight::get().reads_writes(1, 1)]
        pub fn remove_onchain_did(origin, removal: dock::did::DidRemoval<T>, sig: DidSignature<Controller>) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_removable_action_from_controller(Self::remove_onchain_did_, removal, sig)?;
            Ok(())
        }

        fn on_runtime_upgrade() -> Weight {
            if Version::get() == StorageVersion::SingleKey {
                let weight = crate::migrations::did::single_key::migrate_to_multi_key::<T>();
                Version::put(StorageVersion::MultiKey);

                T::DbWeight::get().writes(1) + weight
            } else {
                0
            }
        }
    }
}
