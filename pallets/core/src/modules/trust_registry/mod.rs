//! Dock Trust Registry.

use crate::{
    common::ForSigType,
    deposit_indexed_event,
    did::{self, DidOrDidMethodKeySignature},
    util::{
        ActionWithNonce, ActionWrapper, BoundedKeyValue, OnlyExistent, SetOrAddOrRemoveOrModify,
        SetOrModify,
    },
};
use frame_support::{pallet_prelude::*, weights::PostDispatchInfo};

use frame_system::ensure_signed;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod weights;

pub mod actions;
pub mod types;
mod update_rules;

pub use actions::*;
pub use pallet::*;
pub use types::*;

use weights::*;

#[frame_support::pallet]

pub mod pallet {
    use super::*;
    use frame_system::pallet_prelude::*;

    /// Error for the TrustRegistry module.
    #[pallet::error]
    pub enum Error<T> {
        TooManyRegistries,
        /// Not the `TrustRegistry`'s `Convener`.
        NotTheConvener,
        NoSuchIssuer,
        SchemaMetadataDoesntExist,
        AlreadySuspended,
        NotSuspended,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        /// `TrustRegistry` with the given id was created.
        TrustRegistryInitialized(TrustRegistryId),
        /// Schema metadata was added in the `TrustRegistry` with the given id.
        SchemaMetadataAdded(TrustRegistryId, TrustRegistrySchemaId),
        /// Schema metadata was updated in the `TrustRegistry` with the given id.
        SchemaMetadataUpdated(TrustRegistryId, TrustRegistrySchemaId),
        /// Schema metadata was removed from the `TrustRegistry` with the given id.
        SchemaMetadataRemoved(TrustRegistryId, TrustRegistrySchemaId),
        /// `TrustRegistry`'s `Issuer` was suspended.
        IssuerSuspended(TrustRegistryId, Issuer),
        /// `TrustRegistry`'s `Issuer` was unsuspended.
        IssuerUnsuspended(TrustRegistryId, Issuer),
        /// Delegated `Issuer`s were updated in the  `TrustRegistry` with the given id..
        DelegatedIssuersUpdated(TrustRegistryId, Issuer),
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {
        type Event: From<Event>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    /// Stores `TrustRegistry`s information: `Convener`, name, etc.
    #[pallet::storage]
    #[pallet::getter(fn trust_registry_info)]
    pub type TrustRegistriesInfo<T: Config> =
        StorageMap<_, Blake2_128Concat, TrustRegistryId, TrustRegistryInfo<T>>;

    /// Schema metadata stored in all trust registries. Mapping of the form (schema_id, registry_id) -> schema_metadata
    #[pallet::storage]
    #[pallet::getter(fn schema_metadata)]
    pub type TrustRegistrySchemasMetadata<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistrySchemaId,
        Blake2_128Concat,
        TrustRegistryId,
        TrustRegistrySchemaMetadata<T>,
    >;

    /// Schema ids corresponding to trust registries. Mapping of registry_id -> schema_id
    #[pallet::storage]
    #[pallet::getter(fn registry_schema)]
    pub type TrustRegistryStoredSchemas<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        TrustRegistrySchemaId,
        (),
    >;

    /// Stores `TrustRegistry`s owned by conveners as a mapping of the form convener_id -> Set<registry_id>
    #[pallet::storage]
    #[pallet::getter(fn convener_trust_registries)]
    pub type ConvenerTrustRegistries<T> =
        StorageMap<_, Blake2_128Concat, Convener, TrustRegistryIdSet<T>, ValueQuery>;

    /// Stores `Trust Registry`'s `Verifier`s schemas.
    #[pallet::storage]
    #[pallet::getter(fn trust_registry_verifier_schemas)]
    pub type TrustRegistryVerifierSchemas<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        Verifier,
        VerifierSchemas<T>,
        ValueQuery,
    >;

    /// Stores `Trust Registry`'s `Issuer`s schemas.
    #[pallet::storage]
    #[pallet::getter(fn trust_registry_issuer_schemas)]
    pub type TrustRegistryIssuerSchemas<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        Issuer,
        IssuerSchemas<T>,
        ValueQuery,
    >;

    /// Stores `Trust Registry`'s `Issuer`s configurations.
    #[pallet::storage]
    #[pallet::getter(fn trust_registry_issuer_config)]
    pub type TrustRegistryIssuerConfigurations<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        Issuer,
        TrustRegistryIssuerConfiguration<T>,
        ValueQuery,
    >;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Creates a new `Trust Registry` with the provided identifier.
        /// The DID signature signer will be set as a `Trust Registry` owner.
        #[pallet::weight(SubstrateWeight::<T>::init_or_update_trust_registry(init_or_update_trust_registry, signature))]
        pub fn init_or_update_trust_registry(
            origin: OriginFor<T>,
            init_or_update_trust_registry: InitOrUpdateTrustRegistry<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            init_or_update_trust_registry
                .signed_with_signer_target(signature)?
                .execute(ActionWrapper::wrap_fn(Self::init_or_update_trust_registry_))
        }

        /// Sets the schema metadata entry (entries) with the supplied identifier(s).
        ///
        /// - `Convener` DID owning registry with the provided identifier can make any modifications.
        ///
        /// - `Issuer` DID can only modify his verification prices and remove himself from the `issuers` map.
        ///
        /// - `Verifier` DID can only remove himself from the `verifiers` set.
        #[pallet::weight(SubstrateWeight::<T>::set_schemas_metadata(set_schemas_metadata, signature))]
        pub fn set_schemas_metadata(
            origin: OriginFor<T>,
            set_schemas_metadata: SetSchemasMetadata<T>,
            signature: DidOrDidMethodKeySignature<ConvenerOrIssuerOrVerifier>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            let (ver, iss, schem) = set_schemas_metadata
                .signed(signature.clone())
                .execute_readonly(Self::set_schemas_metadata_)?;

            let actual_weight = signature.weight_for_sig_type::<T>(
                || SubstrateWeight::<T>::set_schemas_metadata_sr25519(iss, ver, schem),
                || SubstrateWeight::<T>::set_schemas_metadata_ed25519(iss, ver, schem),
                || SubstrateWeight::<T>::set_schemas_metadata_secp256k1(iss, ver, schem),
            );

            Ok(PostDispatchInfo {
                actual_weight: Some(actual_weight),
                pays_fee: Pays::Yes,
            })
        }

        /// Update delegated `Issuer`s of the given `Issuer`.
        #[pallet::weight(SubstrateWeight::<T>::update_delegated_issuers(update_delegated_issuers, signature))]
        pub fn update_delegated_issuers(
            origin: OriginFor<T>,
            update_delegated_issuers: UpdateDelegatedIssuers<T>,
            signature: DidOrDidMethodKeySignature<Issuer>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            update_delegated_issuers
                .signed(signature)
                .execute_readonly(Self::update_delegated_issuers_)
        }

        /// Suspends given `Issuer`s.
        #[pallet::weight(SubstrateWeight::<T>::suspend_issuers(suspend_issuers, signature))]
        pub fn suspend_issuers(
            origin: OriginFor<T>,
            suspend_issuers: SuspendIssuers<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            suspend_issuers
                .signed(signature)
                .execute_readonly(Self::suspend_issuers_)
        }

        /// Unsuspends given `Issuer`s.
        #[pallet::weight(SubstrateWeight::<T>::unsuspend_issuers(unsuspend_issuers, signature))]
        pub fn unsuspend_issuers(
            origin: OriginFor<T>,
            unsuspend_issuers: UnsuspendIssuers<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            unsuspend_issuers
                .signed(signature)
                .execute_readonly(Self::unsuspend_issuers_)
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn init_or_update_trust_registry(
        InitOrUpdateTrustRegistry {
            name,
            gov_framework,
            ..
        }: &InitOrUpdateTrustRegistry<T>,
        signed: &DidOrDidMethodKeySignature<Convener>,
    ) -> Weight {
        signed.weight_for_sig_type::<T>(
            || {
                Self::init_or_update_trust_registry_sr25519(
                    name.len() as u32,
                    gov_framework.len() as u32,
                )
            },
            || {
                Self::init_or_update_trust_registry_ed25519(
                    name.len() as u32,
                    gov_framework.len() as u32,
                )
            },
            || {
                Self::init_or_update_trust_registry_secp256k1(
                    name.len() as u32,
                    gov_framework.len() as u32,
                )
            },
        )
    }

    fn set_schemas_metadata(
        SetSchemasMetadata { schemas, .. }: &SetSchemasMetadata<T>,
        signed: &DidOrDidMethodKeySignature<ConvenerOrIssuerOrVerifier>,
    ) -> Weight {
        let issuers_len = schemas
            .values()
            .map(|schema_update| match schema_update {
                SetOrAddOrRemoveOrModify::Add(schema) | SetOrAddOrRemoveOrModify::Set(schema) => {
                    schema.issuers.len() as u32
                }
                SetOrAddOrRemoveOrModify::Modify(OnlyExistent(update)) => {
                    update.issuers.as_ref().map_or(0, |v| match v {
                        SetOrModify::Set(issuers) => issuers.capacity(),
                        SetOrModify::Modify(map) => map.len() as u32,
                    })
                }
                SetOrAddOrRemoveOrModify::Remove => Default::default(),
            })
            .sum();
        let verifiers_len = schemas
            .values()
            .map(|schema_update| match schema_update {
                SetOrAddOrRemoveOrModify::Add(schema) | SetOrAddOrRemoveOrModify::Set(schema) => {
                    schema.verifiers.len() as u32
                }
                SetOrAddOrRemoveOrModify::Modify(OnlyExistent(update)) => {
                    update.verifiers.as_ref().map_or(0, |v| match v {
                        SetOrModify::Set(verifiers) => verifiers.capacity(),
                        SetOrModify::Modify(map) => map.len() as u32,
                    })
                }
                SetOrAddOrRemoveOrModify::Remove => Default::default(),
            })
            .sum();
        let schemas_len = schemas.len() as u32;

        signed.weight_for_sig_type::<T>(
            || Self::set_schemas_metadata_sr25519(issuers_len, verifiers_len, schemas_len),
            || Self::set_schemas_metadata_ed25519(issuers_len, verifiers_len, schemas_len),
            || Self::set_schemas_metadata_secp256k1(issuers_len, verifiers_len, schemas_len),
        )
    }

    fn update_delegated_issuers(
        UpdateDelegatedIssuers { delegated, .. }: &UpdateDelegatedIssuers<T>,
        signed: &DidOrDidMethodKeySignature<Issuer>,
    ) -> Weight {
        let issuers_len = delegated.len();

        signed.weight_for_sig_type::<T>(
            || Self::update_delegated_issuers_sr25519(issuers_len),
            || Self::update_delegated_issuers_ed25519(issuers_len),
            || Self::update_delegated_issuers_secp256k1(issuers_len),
        )
    }

    fn suspend_issuers(
        SuspendIssuers { issuers, .. }: &SuspendIssuers<T>,
        signed: &DidOrDidMethodKeySignature<Convener>,
    ) -> Weight {
        let issuers_len = issuers.len() as u32;

        signed.weight_for_sig_type::<T>(
            || Self::suspend_issuers_sr25519(issuers_len),
            || Self::suspend_issuers_ed25519(issuers_len),
            || Self::suspend_issuers_secp256k1(issuers_len),
        )
    }

    fn unsuspend_issuers(
        UnsuspendIssuers { issuers, .. }: &UnsuspendIssuers<T>,
        signed: &DidOrDidMethodKeySignature<Convener>,
    ) -> Weight {
        let issuers_len = issuers.len() as u32;

        signed.weight_for_sig_type::<T>(
            || Self::unsuspend_issuers_sr25519(issuers_len),
            || Self::unsuspend_issuers_ed25519(issuers_len),
            || Self::unsuspend_issuers_secp256k1(issuers_len),
        )
    }
}
