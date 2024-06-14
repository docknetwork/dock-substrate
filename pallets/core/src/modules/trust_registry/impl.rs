use core::iter::repeat;
use itertools::Itertools;

use super::{types::*, *};
use crate::{
    common::IntermediateError,
    util::{
        ActionWithNonceWrapper, AddOrRemoveOrModify, ApplyUpdate, IncOrDec, MultiTargetUpdate,
        TranslateUpdate, ValidateUpdate,
    },
};
use alloc::collections::BTreeSet;

impl<T: Config> Pallet<T> {
    pub(super) fn init_or_update_trust_registry_(
        InitOrUpdateTrustRegistry {
            registry_id,
            name,
            gov_framework,
            ..
        }: InitOrUpdateTrustRegistry<T>,
        registries: &mut TrustRegistryIdSet<T>,
        info: &mut Option<TrustRegistryInfo<T>>,
        convener: Convener,
    ) -> DispatchResult {
        let name = name
            .try_into()
            .map_err(|_| Error::<T>::TrustRegistryNameSizeExceeded)?;
        let gov_framework = gov_framework
            .try_into()
            .map_err(|_| Error::<T>::GovFrameworkSizeExceeded)?;

        info.replace(TrustRegistryInfo {
            convener,
            name,
            gov_framework,
        });

        registries
            .try_insert(registry_id)
            .map(drop)
            .map_err(|_| Error::<T>::TooManyRegistries)?;

        deposit_indexed_event!(TrustRegistryInitialized(registry_id));
        Ok(())
    }

    pub(super) fn set_schemas_metadata_(
        SetSchemasMetadata {
            registry_id,
            schemas,
            ..
        }: SetSchemasMetadata<T>,
        registry_info: TrustRegistryInfo<T>,
        actor: ConvenerOrIssuerOrVerifier,
    ) -> Result<PostDispatchInfo, IntermediateError<T>> {
        let schemas: SchemasUpdate<T> = schemas
            .translate_update()
            .map_err(IntoModuleError::into_module_error)
            .map_err(Into::into)
            .map_err(|error| DispatchErrorWithPostInfo {
                post_info: PostDispatchInfo {
                    actual_weight: Some(Default::default()),
                    pays_fee: Pays::Yes,
                },
                error,
            })?;

        let mut validation = StorageAccesses::default();
        let update = schemas
            .validate_and_record_diff(actor, registry_id, &registry_info, &mut validation)
            .map_err(Into::into)
            .map_err(|error| DispatchErrorWithPostInfo {
                post_info: PostDispatchInfo {
                    actual_weight: Some(validation.reads::<T>()),
                    pays_fee: Pays::Yes,
                },
                error,
            })?;

        let execution = update.execute(registry_id);
        let weight = validation
            .reads::<T>()
            .saturating_add(execution.reads_writes::<T>());

        Ok(PostDispatchInfo {
            actual_weight: Some(weight),
            pays_fee: Pays::Yes,
        })
    }

    /// Updates the delegated issuers for a trust registry.
    ///
    /// This function performs the following actions:
    /// 1. Checks if the issuer exists in the trust registry's schemas.
    /// 2. Translates the delegated updates to the appropriate format.
    /// 3. Ensures that the delegated updates are valid.
    /// 4. Updates the issuer schema IDs and ensures their validity.
    /// 5. Applies the updates to the delegated issuer schemas.
    /// 6. Applies the updates to the overall configuration.
    /// 7. Emits an event to signal the successful update.
    pub(super) fn update_delegated_issuers_(
        ActionWithNonceWrapper {
            action:
                UpdateDelegatedIssuers {
                    registry_id,
                    delegated,
                    ..
                },
            ..
        }: ActionWithNonceWrapper<T, UpdateDelegatedIssuers<T>, (TrustRegistryId, Issuer)>,
        config: &mut TrustRegistryIssuerConfiguration<T>,
        issuer: Issuer,
    ) -> DispatchResult {
        ensure!(
            TrustRegistryIssuerSchemas::<T>::contains_key(registry_id, issuer),
            Error::<T>::NoSuchIssuer
        );
        // Translate the ubounded update to the bounded updates (with size limitations).
        let delegated: DelegatedUpdate<T> = delegated
            .translate_update()
            .map_err(IntoModuleError::into_module_error)?;

        // Ensure that the delegated updates are valid.
        delegated.ensure_valid(&issuer, &config.delegated)?;

        // Get the schema IDs associated with the issuer.
        let issuer_schema_ids = TrustRegistryIssuerSchemas::<T>::get(registry_id, issuer);

        let participants =
            TrustRegistriesParticipants::<T>::get(TrustRegistryIdForParticipants(registry_id));

        // Compute the difference in issuer updates and translate update from `AddOrRemoveOrModify` to `IncOrDec`.
        let issuers_diff: MultiTargetUpdate<Issuer, IncOrDec> = delegated
            .keys_diff(&config.delegated)
            .translate_update()
            .map_err(IntoModuleError::<T>::into_module_error)?;

        // Validate and apply the schema ID updates for each delegated issuer.
        for (delegated_issuer, update) in issuers_diff.iter() {
            let schema_ids_update: MultiTargetUpdate<_, IncOrDec> = issuer_schema_ids
                .iter()
                .copied()
                .zip(repeat(update.clone()))
                .collect();
            let schema_ids =
                TrustRegistryDelegatedIssuerSchemas::<T>::get(registry_id, delegated_issuer);
            if schema_ids.is_empty() {
                ensure!(
                    participants.contains(&IssuerOrVerifier(**delegated_issuer)),
                    Error::<T>::NotAParticipant
                );
            }

            schema_ids_update.ensure_valid(&issuer, &schema_ids)?;
        }

        // Apply the schema ID updates for each delegated issuer.
        for (issuer, update) in issuers_diff {
            let schema_ids_update: MultiTargetUpdate<_, IncOrDec> = issuer_schema_ids
                .iter()
                .copied()
                .zip(repeat(update))
                .collect();

            TrustRegistryDelegatedIssuerSchemas::<T>::mutate(registry_id, issuer, |schema_ids| {
                schema_ids_update.apply_update(schema_ids);
            });
        }

        // Apply the delegated updates to the issuer configuration.
        delegated.apply_update(&mut config.delegated);

        Self::deposit_event(Event::DelegatedIssuersUpdated(registry_id, issuer));

        Ok(())
    }

    pub(super) fn suspend_issuers_(
        SuspendIssuers {
            registry_id,
            issuers,
            ..
        }: SuspendIssuers<T>,
        _: TrustRegistryInfo<T>,
        _: Convener,
    ) -> DispatchResult {
        for issuer in &issuers {
            ensure!(
                TrustRegistryIssuerSchemas::<T>::contains_key(registry_id, issuer),
                Error::<T>::NoSuchIssuer
            );
            ensure!(
                !TrustRegistryIssuerConfigurations::<T>::get(registry_id, issuer).suspended,
                Error::<T>::AlreadySuspended
            );
        }

        for issuer in issuers {
            Self::deposit_event(Event::IssuerSuspended(registry_id, issuer));

            TrustRegistryIssuerConfigurations::<T>::mutate(registry_id, issuer, |issuer| {
                issuer.suspended = true
            });
        }

        Ok(())
    }

    pub(super) fn unsuspend_issuers_(
        UnsuspendIssuers {
            registry_id,
            issuers,
            ..
        }: UnsuspendIssuers<T>,
        _: TrustRegistryInfo<T>,
        _: Convener,
    ) -> DispatchResult {
        for issuer in &issuers {
            ensure!(
                TrustRegistryIssuerSchemas::<T>::contains_key(registry_id, issuer),
                Error::<T>::NoSuchIssuer
            );
            ensure!(
                TrustRegistryIssuerConfigurations::<T>::get(registry_id, issuer).suspended,
                Error::<T>::NotSuspended
            );
        }

        for issuer in issuers {
            Self::deposit_event(Event::IssuerUnsuspended(registry_id, issuer));

            TrustRegistryIssuerConfigurations::<T>::mutate(registry_id, issuer, |issuer| {
                issuer.suspended = false
            });
        }

        Ok(())
    }

    pub(super) fn change_participants_(
        ChangeParticipantsRaw {
            registry_id,
            participants,
            ..
        }: ChangeParticipantsRaw<T>,
        trust_registry_participants: &mut TrustRegistryStoredParticipants<T>,
        convener_or_issuers_or_verifiers: BTreeSet<ConvenerOrIssuerOrVerifier>,
    ) -> DispatchResult {
        participants.ensure_valid(
            &IssuersOrVerifiers(
                convener_or_issuers_or_verifiers
                    .into_iter()
                    .map(|did| IssuerOrVerifier(*did))
                    .collect(),
            ),
            &trust_registry_participants,
        )?;
        for (participant, action) in participants.iter() {
            let event = match action {
                AddOrRemoveOrModify::Add(()) => {
                    Event::TrustRegistryParticipantConfirmed(*registry_id, *participant)
                }
                AddOrRemoveOrModify::Remove => {
                    Event::TrustRegistryParticipantRemoved(*registry_id, *participant)
                }
                _ => continue,
            };

            Self::deposit_event(event);
        }
        participants.apply_update(trust_registry_participants);

        Ok(())
    }

    pub fn issuer_or_verifier_registries(
        issuer_or_verifier: IssuerOrVerifier,
    ) -> BTreeSet<TrustRegistryId> {
        let issuer_registries = Self::issuer_registries(Issuer(*issuer_or_verifier));
        let verifier_registries = Self::verifier_registries(Verifier(*issuer_or_verifier));

        issuer_registries
            .union(&verifier_registries)
            .copied()
            .collect()
    }

    pub fn registry_issuer_or_verifier_schemas(
        reg_id: TrustRegistryId,
        issuer_or_verifier: IssuerOrVerifier,
    ) -> BTreeSet<TrustRegistrySchemaId> {
        let issuer_schemas =
            Self::registry_issuer_or_delegated_issuer_schemas(reg_id, Issuer(*issuer_or_verifier));
        let verifier_schemas =
            Self::registry_verifier_schemas(reg_id, Verifier(*issuer_or_verifier));

        issuer_schemas.union(&verifier_schemas).copied().collect()
    }

    pub fn registry_issuer_or_delegated_issuer_schemas(
        reg_id: TrustRegistryId,
        issuer_or_delegated_issuer: Issuer,
    ) -> BTreeSet<TrustRegistrySchemaId> {
        let IssuerSchemas(issuer_schemas) =
            Self::registry_issuer_schemas(reg_id, issuer_or_delegated_issuer);
        let DelegatedIssuerSchemas(delegated_issuer_schemas) =
            Self::registry_delegated_issuer_schemas(reg_id, issuer_or_delegated_issuer);

        delegated_issuer_schemas
            .into_iter()
            .map(|(key, _)| key)
            .into_iter()
            .merge(issuer_schemas)
            .dedup()
            .collect()
    }

    pub fn aggregate_schema_metadata(
        (reg_id, schema_id): (TrustRegistryId, TrustRegistrySchemaId),
    ) -> Option<AggregatedTrustRegistrySchemaMetadata<T>> {
        TrustRegistrySchemasMetadata::<T>::get(schema_id, reg_id).map(|meta| meta.aggregate(reg_id))
    }

    pub fn schema_metadata_by_schema_id(
        schema_id: TrustRegistrySchemaId,
    ) -> impl Iterator<Item = (TrustRegistryId, TrustRegistrySchemaMetadata<T>)> {
        TrustRegistrySchemasMetadata::<T>::iter_prefix(schema_id)
    }

    pub fn schema_metadata_by_registry_id(
        registry_id: TrustRegistryId,
    ) -> impl Iterator<Item = (TrustRegistrySchemaId, TrustRegistrySchemaMetadata<T>)> {
        let TrustRegistryStoredSchemas(schemas) =
            TrustRegistriesStoredSchemas::<T>::get(registry_id);

        schemas.into_iter().filter_map(move |schema_id| {
            TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id)
                .map(|schema_metadata| (schema_id, schema_metadata))
        })
    }
}
