//! Dock Trust Registry.

use crate::{
    common::{DidSignatureWithNonce, ForSigType},
    deposit_indexed_event,
    did::{self, DidOrDidMethodKeySignature},
    util::{
        constants::ZeroDbWeight, Action, ActionWithNonce, ActionWithNonceWrapper, ActionWrapper,
        KeyValue, KeyedUpdate, OnlyExistent, SetOrAddOrRemoveOrModify, SetOrModify,
        UpdateTranslationError,
    },
};
use core::convert::Infallible;
use frame_support::{
    dispatch::DispatchErrorWithPostInfo,
    pallet_prelude::*,
    weights::{PostDispatchInfo, RuntimeDbWeight},
};
use r#impl::{StepError, StepStorageAccesses};
use sp_std::vec::Vec;

use frame_system::ensure_signed;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod weights;

pub mod actions;
pub mod query;
pub mod types;
mod update;
mod update_rules;

pub use actions::*;
pub use pallet::*;
pub use query::*;
pub use types::*;

pub(super) use update::*;
use weights::*;

#[frame_support::pallet]
pub mod pallet {
    use crate::{
        common::{DidSignatureWithNonce, MultiSignedAction},
        util::{AddOrRemoveOrModify, AnyOfOrAll, DuplicateKey, UpdateError},
    };

    use super::*;
    use frame_system::pallet_prelude::*;
    use utils::BoundedStringConversionError;

    pub trait IntoModuleError<T> {
        fn into_module_error(self) -> Error<T>;
    }

    impl<T> IntoModuleError<T> for Error<T> {
        fn into_module_error(self) -> Error<T> {
            self
        }
    }

    impl<T> IntoModuleError<T> for Infallible {
        fn into_module_error(self) -> Error<T> {
            unreachable!()
        }
    }

    impl<T, V, U> IntoModuleError<T> for UpdateTranslationError<V, U>
    where
        V: IntoModuleError<T>,
        U: IntoModuleError<T>,
    {
        fn into_module_error(self) -> Error<T> {
            match self {
                UpdateTranslationError::Value(value_err) => value_err.into_module_error(),
                UpdateTranslationError::Update(update_err) => update_err.into_module_error(),
            }
        }
    }

    impl<T> IntoModuleError<T> for BoundedStringConversionError {
        fn into_module_error(self) -> Error<T> {
            Error::<T>::PriceCurrencySymbolSizeExceeded
        }
    }

    impl<T> From<UpdateError> for Error<T> {
        fn from(update_error: UpdateError) -> Self {
            match update_error {
                UpdateError::DoesntExist => Error::<T>::EntityDoesntExist,
                UpdateError::AlreadyExists => Error::<T>::EntityAlreadyExists,
                UpdateError::InvalidActor => Error::<T>::SenderCantApplyThisUpdate,
                UpdateError::Overflow => Error::<T>::TooManySchemasPerDelegatedIssuer,
                UpdateError::Underflow => Error::<T>::Underflow,
                UpdateError::CapacityOverflow => Error::<T>::TooManyEntities,
                UpdateError::ValidationFailed => Error::<T>::UpdateValidationFailed,
            }
        }
    }

    impl<T> From<DuplicateKey> for Error<T> {
        fn from(DuplicateKey: DuplicateKey) -> Self {
            Error::<T>::DuplicateKey
        }
    }

    /// Error for the TrustRegistry module.
    #[pallet::error]
    pub enum Error<T> {
        /// Too many registries per a `Convener`.
        TooManyRegistries,
        /// Not the `TrustRegistry`'s `Convener`.
        NotTheConvener,
        /// `TrustRegistry` with supplied identitier doesn't exist
        NoRegistry,
        /// Supplied `Issuer` doesn't exist.
        NoSuchIssuer,
        /// At least one of the supplied `Issuers` was suspended already.
        AlreadySuspended,
        /// At least one of the supplied `Issuers` wasn't suspended.
        NotSuspended,
        /// Trust registry name length exceeds its bound.
        TrustRegistryNameSizeExceeded,
        /// Trust registry gov framework size exceeds its bound.
        GovFrameworkSizeExceeded,
        /// Supplied delegated `Issuer`s amount exceeds max allowed bound.
        DelegatedIssuersSizeExceeded,
        /// Supplied `Issuer`s amount exceeds max allowed bound.
        IssuersSizeExceeded,
        /// Supplied `Verifier`s amount exceeds max allowed bound.
        VerifiersSizeExceeded,
        /// Supplied `VerificatinPrice`s amount exceeds max allowed bound.
        VerificationPricesSizeExceeded,
        /// One of the verification prices symbols exceeds its max length bound.
        PriceCurrencySymbolSizeExceeded,
        /// Too many schemas per a single Trust Registry.
        SchemasPerRegistrySizeExceeded,
        /// `Issuer` attempts to set himself as a delegated `Issuer`.
        IssuerCantDelegateToHimself,
        /// Issuer cant' modify other `Issuer`.
        InvalidIssuerTarget,
        /// Attempt to decrease counter below zero.
        Underflow,
        /// Attempt to remove/update non-existing entity failed.
        EntityDoesntExist,
        /// Attempt to add an existing entity failed.
        EntityAlreadyExists,
        /// This update can't be executed by the provided sender.
        SenderCantApplyThisUpdate,
        /// Delegated `Issuer`'s schemas amount exceeded.
        TooManySchemasPerDelegatedIssuer,
        /// Can't add more entities.
        TooManyEntities,
        /// Failed to validate provided update.
        UpdateValidationFailed,
        /// Some of the keys were found twice in the update.
        DuplicateKey,
        /// One of the `Issuer`s or `Verifier`s is not a registry participant.
        NotAParticipant,
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
        /// Delegated `Issuer`s were updated in the `TrustRegistry` with the given id.
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
    #[pallet::getter(fn registry_info)]
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
    #[pallet::getter(fn registry_stored_schemas)]
    pub type TrustRegistriesStoredSchemas<T: Config> =
        StorageMap<_, Blake2_128Concat, TrustRegistryId, TrustRegistryStoredSchemas<T>, ValueQuery>;

    /// Trust Registry participants. Mapping of registry_id -> schema_id
    #[pallet::storage]
    #[pallet::getter(fn registry_participants)]
    pub type TrustRegistriesParticipants<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        TrustRegistryIdForParticipants,
        TrustRegistryStoredParticipants<T>,
        ValueQuery,
    >;

    /// Stores `TrustRegistry`s owned by conveners as a mapping of the form convener_id -> Set<registry_id>
    #[pallet::storage]
    #[pallet::getter(fn convener_registries)]
    pub type ConvenerTrustRegistries<T> =
        StorageMap<_, Blake2_128Concat, Convener, TrustRegistryIdSet<T>, ValueQuery>;

    /// Stores `Trust Registry`'s `Verifier`s schemas.
    #[pallet::storage]
    #[pallet::getter(fn registry_verifier_schemas)]
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
    #[pallet::getter(fn registry_issuer_schemas)]
    pub type TrustRegistryIssuerSchemas<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        Issuer,
        IssuerSchemas<T>,
        ValueQuery,
    >;

    /// Stores `Trust Registry`'s delegated `Issuer`s schemas.
    #[pallet::storage]
    #[pallet::getter(fn registry_delegated_issuer_schemas)]
    pub type TrustRegistryDelegatedIssuerSchemas<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        TrustRegistryId,
        Blake2_128Concat,
        Issuer,
        DelegatedIssuerSchemas<T>,
        ValueQuery,
    >;

    /// Stores a set of `Verifier`s Trust Registries.
    #[pallet::storage]
    #[pallet::getter(fn verifier_registries)]
    pub type VerifiersTrustRegistries<T: Config> =
        StorageMap<_, Blake2_128Concat, Verifier, VerifierTrustRegistries<T>, ValueQuery>;

    /// Stores a set of `Issuer`s Trust Registries.
    #[pallet::storage]
    #[pallet::getter(fn issuer_registries)]
    pub type IssuersTrustRegistries<T: Config> =
        StorageMap<_, Blake2_128Concat, Issuer, IssuerTrustRegistries<T>, ValueQuery>;

    /// Stores `Trust Registry`'s `Issuer`s configurations.
    #[pallet::storage]
    #[pallet::getter(fn registry_issuer_config)]
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
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::init_or_update_trust_registry::<T>(init_or_update_trust_registry, signature))]
        pub fn init_or_update_trust_registry(
            origin: OriginFor<T>,
            init_or_update_trust_registry: InitOrUpdateTrustRegistry<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let f = ActionWithNonceWrapper::wrap_fn_with_modify_removable_action(
                Self::init_or_update_trust_registry_,
            );

            init_or_update_trust_registry
                .signed_with_signer_target(signature)?
                .execute(f)
        }

        /// Sets the schema metadata entry (entries) with the supplied identifier(s).
        ///
        /// - `Convener` DID owning registry with the provided identifier can make any modifications.
        ///
        /// - `Issuer` DID can only modify his verification prices and remove himself from the `issuers` map.
        ///
        /// - `Verifier` DID can only remove himself from the `verifiers` set.
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::set_schemas_metadata::<T>(set_schemas_metadata, signature))]
        pub fn set_schemas_metadata(
            origin: OriginFor<T>,
            set_schemas_metadata: SetSchemasMetadata<T>,
            signature: DidOrDidMethodKeySignature<ConvenerOrIssuerOrVerifier>,
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;

            let base_weight = T::DbWeight::get().reads_writes(4, 2).saturating_add(
                SubstrateWeight::<ZeroDbWeight>::set_schemas_metadata(
                    &set_schemas_metadata,
                    &signature,
                ),
            );

            match set_schemas_metadata
                .signed(signature)
                .execute_view(Self::set_schemas_metadata_)
            {
                Ok(StepStorageAccesses {
                    validation,
                    execution,
                }) => Ok(PostDispatchInfo {
                    actual_weight: Some(
                        base_weight
                            .saturating_add(validation.reads::<T>())
                            .saturating_add(execution.reads_writes::<T>()),
                    ),
                    pays_fee: Pays::Yes,
                }),
                Err(StepError::Conversion(error)) => Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(base_weight),
                        pays_fee: Pays::Yes,
                    },
                    error,
                }),
                Err(StepError::Validation(error, validation)) => Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(base_weight.saturating_add(validation.reads::<T>())),
                        pays_fee: Pays::Yes,
                    },
                    error,
                }),
            }
        }

        /// Update delegated `Issuer`s of the given `Issuer`.
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::update_delegated_issuers::<T>(update_delegated_issuers, signature))]
        pub fn update_delegated_issuers(
            origin: OriginFor<T>,
            update_delegated_issuers: UpdateDelegatedIssuers<T>,
            signature: DidOrDidMethodKeySignature<Issuer>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            update_delegated_issuers
                .signed_with_combined_target(signature, |target, signer| (target, signer))?
                .execute(Self::update_delegated_issuers_)
        }

        /// Suspends given `Issuer`s.
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::suspend_issuers::<T>(suspend_issuers, signature))]
        pub fn suspend_issuers(
            origin: OriginFor<T>,
            suspend_issuers: SuspendIssuers<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            suspend_issuers
                .signed(signature)
                .execute_view(Self::suspend_issuers_)
        }

        /// Unsuspends given `Issuer`s.
        #[pallet::weight(SubstrateWeight::<T::DbWeight>::unsuspend_issuers::<T>(unsuspend_issuers, signature))]
        pub fn unsuspend_issuers(
            origin: OriginFor<T>,
            unsuspend_issuers: UnsuspendIssuers<T>,
            signature: DidOrDidMethodKeySignature<Convener>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            unsuspend_issuers
                .signed(signature)
                .execute_view(Self::unsuspend_issuers_)
        }

        #[pallet::weight(SubstrateWeight::<T::DbWeight>::change_participants_::<T>(change_participants, signatures))]
        pub fn change_participants(
            origin: OriginFor<T>,
            change_participants: ChangeParticipantsRaw<T>,
            signatures: Vec<DidSignatureWithNonce<T::BlockNumber, ConvenerOrIssuerOrVerifier>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let f = |action: ChangeParticipantsRaw<T>, registry_info: TrustRegistryInfo<T>| {
                let participants = action
                    .participants
                    .keys()
                    .map(|did| ConvenerOrIssuerOrVerifier(**did));
                // Only require convener signature to add new participants, existing participants
                // can remove themselves without involving the convener.
                let maybe_convener = action
                    .participants
                    .values()
                    .any(|update| matches!(update, AddOrRemoveOrModify::Add(())))
                    .then(|| ConvenerOrIssuerOrVerifier(*registry_info.convener));

                let signers = AnyOfOrAll::all(participants.chain(maybe_convener));

                MultiSignedAction::new(action, signatures)
                    .execute(Self::change_participants_, |_| signers)
            };

            ActionWrapper::new(*change_participants.registry_id, change_participants)
                .view(ActionWrapper::wrap_fn(f))
        }
    }
}

impl<W: Get<RuntimeDbWeight>> SubstrateWeight<W> {
    fn init_or_update_trust_registry<T: Config>(
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

    fn set_schemas_metadata<T: Config>(
        SetSchemasMetadata { schemas, .. }: &SetSchemasMetadata<T>,
        signed: &DidOrDidMethodKeySignature<ConvenerOrIssuerOrVerifier>,
    ) -> Weight {
        let unknown_issuers_per_schema = T::MaxIssuersPerSchema::get() / 5;
        let unknown_verifiers_per_schema = T::MaxVerifiersPerSchema::get() / 5;

        let issuers_len = match schemas {
            SetOrModify::Modify(update) => update
                .values()
                .map(|schema_update| match schema_update {
                    SetOrAddOrRemoveOrModify::Add(schema)
                    | SetOrAddOrRemoveOrModify::Set(schema) => schema.issuers.len() as u32,
                    SetOrAddOrRemoveOrModify::Modify(OnlyExistent(update)) => {
                        update.issuers.as_ref().map_or(0, |v| match v {
                            SetOrModify::Set(_) => unknown_issuers_per_schema,
                            SetOrModify::Modify(map) => map.len() as u32,
                        })
                    }
                    SetOrAddOrRemoveOrModify::Remove => unknown_issuers_per_schema,
                })
                .sum(),
            SetOrModify::Set(_) => unknown_issuers_per_schema,
        };
        let verifiers_len = match schemas {
            SetOrModify::Modify(update) => update
                .values()
                .map(|schema_update| match schema_update {
                    SetOrAddOrRemoveOrModify::Add(schema)
                    | SetOrAddOrRemoveOrModify::Set(schema) => schema.verifiers.len() as u32,
                    SetOrAddOrRemoveOrModify::Modify(OnlyExistent(update)) => {
                        update.verifiers.as_ref().map_or(0, |v| match v {
                            SetOrModify::Set(_) => unknown_verifiers_per_schema,
                            SetOrModify::Modify(map) => map.len() as u32,
                        })
                    }
                    SetOrAddOrRemoveOrModify::Remove => unknown_verifiers_per_schema,
                })
                .sum(),
            SetOrModify::Set(_) => unknown_verifiers_per_schema,
        };
        let schemas_len = match schemas {
            SetOrModify::Modify(update) => update.len(),
            SetOrModify::Set(schemas) => schemas.len(),
        } as u32;

        signed.weight_for_sig_type::<T>(
            || Self::set_schemas_metadata_sr25519(issuers_len, verifiers_len, schemas_len),
            || Self::set_schemas_metadata_ed25519(issuers_len, verifiers_len, schemas_len),
            || Self::set_schemas_metadata_secp256k1(issuers_len, verifiers_len, schemas_len),
        )
    }

    fn update_delegated_issuers<T: Config>(
        UpdateDelegatedIssuers { delegated, .. }: &UpdateDelegatedIssuers<T>,
        signed: &DidOrDidMethodKeySignature<Issuer>,
    ) -> Weight {
        let issuers_len = delegated.size();

        signed.weight_for_sig_type::<T>(
            || Self::update_delegated_issuers_sr25519(issuers_len),
            || Self::update_delegated_issuers_ed25519(issuers_len),
            || Self::update_delegated_issuers_secp256k1(issuers_len),
        )
    }

    fn suspend_issuers<T: Config>(
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

    fn change_participants_<T: Config>(
        ChangeParticipantsRaw { participants, .. }: &ChangeParticipantsRaw<T>,
        _signatures: &[DidSignatureWithNonce<T::BlockNumber, ConvenerOrIssuerOrVerifier>],
    ) -> Weight {
        let len = participants.len() as u32;

        Self::change_participants(len)
    }

    fn unsuspend_issuers<T: Config>(
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
