use crate::{
    common::{self, PublicKey, SigValue, VerificationError},
    util::*,
};

use crate::common::Limits;
use arith_utils::CheckedDivCeil;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::DispatchResult, ensure, weights::Weight, CloneNoBound, DebugNoBound, EqNoBound,
    PartialEqNoBound,
};
use frame_system::ensure_signed;
use sp_std::{
    collections::btree_set::BTreeSet,
    convert::{TryFrom, TryInto},
    fmt::Debug,
    prelude::*,
    vec::Vec,
};

pub use actions::*;
pub use base::{offchain, onchain, signature};
pub use details_aggregator::*;
pub use pallet::*;
use weights::*;

pub use base::*;
pub use controllers::Controller;
pub use keys::{DidKey, UncheckedDidKey, VerRelType};
pub use service_endpoints::{ServiceEndpoint, ServiceEndpointId, ServiceEndpointOrigin};

pub(crate) mod actions;
pub(crate) mod base;
pub(crate) mod controllers;
pub(crate) mod details_aggregator;
pub(crate) mod keys;
pub(crate) mod service_endpoints;
pub(crate) mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
pub mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::collections::BTreeMap;
    use frame_support::{pallet_prelude::*, Blake2_128Concat, Identity};
    use frame_system::pallet_prelude::*;

    /// The module's configuration trait.
    #[pallet::config]
    pub trait Config: frame_system::Config + Limits {
        /// The handler of a `DID` removal.
        type OnDidRemoval: OnDidRemoval;

        /// The overarching event type.
        type Event: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    #[pallet::event]
    pub enum Event<T: Config> {
        OffChainDidAdded(Did, OffChainDidDocRef<T>),
        OffChainDidUpdated(Did, OffChainDidDocRef<T>),
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

    /// Error for the DID module.
    #[pallet::error]
    #[derive(PartialEq, Eq, Clone)]
    pub enum Error<T> {
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
        NotAnOffChainDid,
        DidNotOwnedByAccount,
        NoControllerProvided,
        /// The provided key type is not comptaible with the provided verification relationship
        IncompatibleVerificationRelation,
        CannotGetDetailForOffChainDid,
        CannotGetDetailForOnChainDid,
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
        ServiceEndpointDoesNotExist,
        KeyAgreementCantBeUsedForSigning,
        SigningKeyCantBeUsedForKeyAgreement,
    }

    impl<T: Config> From<NonceError> for Error<T> {
        fn from(NonceError::IncorrectNonce: NonceError) -> Self {
            Self::IncorrectNonce
        }
    }

    impl<T: Config> From<VerificationError> for Error<T> {
        fn from(VerificationError::IncompatibleKey(_, _): VerificationError) -> Self {
            Self::IncompatSigPubkey
        }
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// Stores details of off-chain and on-chain DIDs
    #[pallet::storage]
    #[pallet::getter(fn did)]
    pub type Dids<T> = StorageMap<_, Blake2_128Concat, Did, StoredDidDetails<T>>;

    /// Stores keys of a DID as (DID, IncId) -> DidKey. Does not check if the same key is being added multiple times to the same DID.
    #[pallet::storage]
    #[pallet::getter(fn did_key)]
    pub type DidKeys<T> = StorageDoubleMap<_, Blake2_128Concat, Did, Identity, IncId, DidKey>;

    /// Stores controlled - controller pairs of a DID as (DID, DID) -> zero-sized record. If a record exists, then the controller is bound.
    #[pallet::storage]
    #[pallet::getter(fn bound_controller)]
    pub type DidControllers<T> =
        StorageDoubleMap<_, Blake2_128Concat, Did, Blake2_128Concat, Controller, ()>;

    /// Stores service endpoints of a DID as (DID, endpoint id) -> ServiceEndpoint.
    #[pallet::storage]
    #[pallet::getter(fn did_service_endpoints)]
    pub type DidServiceEndpoints<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        Did,
        Blake2_128Concat,
        ServiceEndpointId<T>,
        ServiceEndpoint<T>,
    >;

    #[pallet::storage]
    #[pallet::getter(fn storage_version)]
    pub type Version<T> = StorageValue<_, common::StorageVersion, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub dids: BTreeMap<Did, DidKey>,
        pub _marker: PhantomData<T>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                dids: Default::default(),
                _marker: PhantomData,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            debug_assert!({
                let dedup: BTreeSet<&Did> = self.dids.keys().collect();
                self.dids.len() == dedup.len()
            });
            debug_assert!({ self.dids.iter().all(|(_, key)| key.can_control()) });

            for (did, key) in &self.dids {
                let mut key_id = IncId::new();
                key_id.inc();
                let did_details =
                    StoredOnChainDidDetails::new(OnChainDidDetails::new(key_id, 1u32, 1u32));

                <Pallet<T>>::insert_did_details(*did, did_details);
                DidKeys::<T>::insert(did, key_id, key);
                DidControllers::<T>::insert(did, Controller(*did), ());
            }

            Version::<T>::put(common::StorageVersion::MultiKey);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(SubstrateWeight::<T>::new_offchain(did_doc_ref.len()))]
        pub fn new_offchain(
            origin: OriginFor<T>,
            did: Did,
            did_doc_ref: OffChainDidDocRef<T>,
        ) -> DispatchResult {
            // Only `did_owner` can update or remove this DID
            let did_owner = ensure_signed(origin)?;

            Self::new_offchain_(did_owner, did, did_doc_ref)
        }

        #[pallet::weight(SubstrateWeight::<T>::set_offchain_did_doc_ref(did_doc_ref.len()))]
        pub fn set_offchain_did_doc_ref(
            origin: OriginFor<T>,
            did: Did,
            did_doc_ref: OffChainDidDocRef<T>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            Self::set_offchain_did_doc_ref_(caller, did, did_doc_ref)
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_offchain_did())]
        pub fn remove_offchain_did(origin: OriginFor<T>, did: Did) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            Self::remove_offchain_did_(caller, did)
        }

        /// Create new DID.
        /// At least 1 control key or 1 controller must be provided.
        /// If any supplied key has an empty `ver_rel`, then it will use all verification relationships available for its key type.
        #[pallet::weight(SubstrateWeight::<T>::new_onchain(keys.len() as u32, controllers.len() as u32))]
        pub fn new_onchain(
            origin: OriginFor<T>,
            did: Did,
            keys: Vec<UncheckedDidKey>,
            controllers: BTreeSet<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::new_onchain_(did, keys, controllers)
        }

        /// Add more keys from DID doc.
        /// **Does not** check if the key was already added.
        #[pallet::weight(SubstrateWeight::<T>::add_keys(keys, sig))]
        pub fn add_keys(
            origin: OriginFor<T>,
            keys: AddKeys<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::add_keys_, keys, sig)
        }

        /// Remove keys from DID doc. This is an atomic operation meaning that it will either remove all keys or do nothing.
        /// **Note that removing all keys might make DID unusable**.
        #[pallet::weight(SubstrateWeight::<T>::remove_keys(keys, sig))]
        pub fn remove_keys(
            origin: OriginFor<T>,
            keys: RemoveKeys<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::remove_keys_, keys, sig)
        }

        /// Add new controllers to the signer DID.
        /// **Does not** require provided controllers to
        /// - have any key
        /// - exist on- or off-chain
        #[pallet::weight(SubstrateWeight::<T>::add_controllers(controllers, sig))]
        pub fn add_controllers(
            origin: OriginFor<T>,
            controllers: AddControllers<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(Self::add_controllers_, controllers, sig)
        }

        /// Remove controllers from the signer DID.
        /// This is an atomic operation meaning that it will either remove all keys or do nothing.
        /// **Note that removing all controllers might make DID unusable**.
        #[pallet::weight(SubstrateWeight::<T>::remove_controllers(controllers, sig))]
        pub fn remove_controllers(
            origin: OriginFor<T>,
            controllers: RemoveControllers<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(
                Self::remove_controllers_,
                controllers,
                sig,
            )
        }

        /// Add a single service endpoint to the signer DID.
        #[pallet::weight(SubstrateWeight::<T>::add_service_endpoint(service_endpoint, sig))]
        pub fn add_service_endpoint(
            origin: OriginFor<T>,
            service_endpoint: AddServiceEndpoint<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(
                Self::add_service_endpoint_,
                service_endpoint,
                sig,
            )
        }

        /// Remove a single service endpoint.
        #[pallet::weight(SubstrateWeight::<T>::remove_service_endpoint(service_endpoint, sig))]
        pub fn remove_service_endpoint(
            origin: OriginFor<T>,
            service_endpoint: RemoveServiceEndpoint<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_action_from_controller(
                Self::remove_service_endpoint_,
                service_endpoint,
                sig,
            )
        }

        /// Remove the on-chain DID along with its keys, controllers, service endpoints and BBS+ keys.
        /// Other DID-controlled entities won't be removed.
        /// However, the authorization logic ensures that once a DID is removed, it loses its ability to control any DID.
        #[pallet::weight(SubstrateWeight::<T>::remove_onchain_did(removal, sig))]
        pub fn remove_onchain_did(
            origin: OriginFor<T>,
            removal: DidRemoval<T>,
            sig: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_signed_removable_action_from_controller(
                Self::remove_onchain_did_,
                removal,
                sig,
            )
        }

        /// Adds `StateChange` and `AggregatedDidDetailsResponse` to the metadata.
        #[doc(hidden)]
        #[pallet::weight(<T as frame_system::Config>::DbWeight::get().writes(10))]
        pub fn noop(
            _o: OriginFor<T>,
            _s: common::StateChange<'static, T>,
            _d: AggregatedDidDetailsResponse<T>,
        ) -> DispatchResult {
            Err(DispatchError::BadOrigin)
        }
    }
}

pub trait OnDidRemoval {
    fn on_remove_did(did: Did) -> Weight;
}

impl OnDidRemoval for () {
    fn on_remove_did(_: Did) -> Weight {
        Default::default()
    }
}

crate::impl_tuple!(OnDidRemoval::on_remove_did(did: Did) -> Weight => using saturating_add for A B);
crate::impl_tuple!(OnDidRemoval::on_remove_did(did: Did) -> Weight => using saturating_add for A B C);
crate::impl_tuple!(OnDidRemoval::on_remove_did(did: Did) -> Weight => using saturating_add for A B C D);
crate::impl_tuple!(OnDidRemoval::on_remove_did(did: Did) -> Weight => using saturating_add for A B C D E);

impl<T: Config> SubstrateWeight<T> {
    fn add_keys(keys: &AddKeys<T>, DidSignature { sig, .. }: &DidSignature<Controller>) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_keys_sr25519,
            SigValue::Ed25519(_) => Self::add_keys_ed25519,
            SigValue::Secp256k1(_) => Self::add_keys_secp256k1,
        }(keys.len()))
    }

    fn remove_keys(
        keys: &RemoveKeys<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_keys_sr25519,
            SigValue::Ed25519(_) => Self::remove_keys_ed25519,
            SigValue::Secp256k1(_) => Self::remove_keys_secp256k1,
        }(keys.len()))
    }

    fn add_controllers(
        controllers: &AddControllers<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_controllers_sr25519,
            SigValue::Ed25519(_) => Self::add_controllers_ed25519,
            SigValue::Secp256k1(_) => Self::add_controllers_secp256k1,
        }(controllers.len()))
    }

    fn remove_controllers(
        controllers: &RemoveControllers<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_controllers_sr25519,
            SigValue::Ed25519(_) => Self::remove_controllers_ed25519,
            SigValue::Secp256k1(_) => Self::remove_controllers_secp256k1,
        }(controllers.len()))
    }

    fn add_service_endpoint(
        AddServiceEndpoint { id, endpoint, .. }: &AddServiceEndpoint<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_service_endpoint_sr25519,
            SigValue::Ed25519(_) => Self::add_service_endpoint_ed25519,
            SigValue::Secp256k1(_) => Self::add_service_endpoint_secp256k1,
        })(
            endpoint.origins.len() as u32,
            endpoint
                .origins
                .iter()
                .map(|v| v.len() as u32)
                .sum::<u32>()
                .checked_div_ceil(endpoint.origins.len() as u32)
                .unwrap_or(0),
            id.len() as u32,
        )
    }

    fn remove_service_endpoint(
        RemoveServiceEndpoint { id, .. }: &RemoveServiceEndpoint<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_service_endpoint_sr25519,
            SigValue::Ed25519(_) => Self::remove_service_endpoint_ed25519,
            SigValue::Secp256k1(_) => Self::remove_service_endpoint_secp256k1,
        }(id.len() as u32))
    }

    fn remove_onchain_did(
        _: &DidRemoval<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_onchain_did_sr25519,
            SigValue::Ed25519(_) => Self::remove_onchain_did_ed25519,
            SigValue::Secp256k1(_) => Self::remove_onchain_did_secp256k1,
        }())
    }
}
