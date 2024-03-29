use core::iter::repeat;
use itertools::Itertools;

use super::{types::*, *};
use crate::util::{
    ActionExecutionError, ApplyUpdate, IncOrDec, MultiTargetUpdate, NonceError, TranslateUpdate,
    ValidateUpdate,
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
        convener: Convener,
    ) -> DispatchResult {
        TrustRegistriesInfo::<T>::try_mutate(registry_id, |info| {
            let name = name
                .try_into()
                .map_err(|_| Error::<T>::TrustRegistryNameSizeExceeded)?;
            let gov_framework = gov_framework
                .try_into()
                .map_err(|_| Error::<T>::GovFrameworkSizeExceeded)?;
            let new_info = TrustRegistryInfo {
                convener,
                name,
                gov_framework,
            };

            if let Some(existing) = info.replace(new_info) {
                if existing.convener != convener {
                    Err(Error::<T>::NotTheConvener)?
                }
            }

            registries
                .try_insert(registry_id)
                .map(drop)
                .map_err(|_| Error::<T>::TooManyRegistries)
        })?;

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
    ) -> Result<StepStorageAccesses, StepError> {
        let schemas: SchemasUpdate<T> = schemas
            .translate_update()
            .map_err(IntoModuleError::into_module_error)
            .map_err(Into::into)
            .map_err(StepError::Conversion)?;

        let mut validation = StorageAccesses::default();
        schemas
            .validate_and_record_diff(actor, registry_id, &registry_info, &mut validation)
            .map_err(|error| StepError::Validation(error.into(), validation.clone()))
            .map(|validated_update| StepStorageAccesses {
                validation,
                execution: validated_update.execute(registry_id),
            })
    }

    pub(super) fn update_delegated_issuers_(
        UpdateDelegatedIssuers {
            registry_id,
            delegated,
            ..
        }: UpdateDelegatedIssuers<T>,
        (): (),
        issuer: Issuer,
    ) -> DispatchResult {
        ensure!(
            TrustRegistryIssuerSchemas::<T>::contains_key(registry_id, issuer),
            Error::<T>::NoSuchIssuer
        );
        let delegated: DelegatedUpdate<T> = delegated
            .translate_update()
            .map_err(IntoModuleError::into_module_error)?;

        TrustRegistryIssuerConfigurations::<T>::try_mutate(registry_id, issuer, |config| {
            delegated.ensure_valid(&issuer, &config.delegated)?;

            let issuer_schema_ids = TrustRegistryIssuerSchemas::<T>::get(registry_id, issuer);
            let issuers_diff: MultiTargetUpdate<Issuer, IncOrDec> = delegated
                .keys_diff(&config.delegated)
                .translate_update()
                .map_err(IntoModuleError::<T>::into_module_error)?;

            for (delegated_issuer, update) in issuers_diff.iter() {
                let schema_ids_update: MultiTargetUpdate<_, IncOrDec> = issuer_schema_ids
                    .iter()
                    .copied()
                    .zip(repeat(update.clone()))
                    .collect();
                let schema_ids =
                    TrustRegistryDelegatedIssuerSchemas::<T>::get(registry_id, delegated_issuer);

                schema_ids_update.ensure_valid(&issuer, &schema_ids)?;
            }

            for (issuer, update) in issuers_diff {
                let schema_ids_update: MultiTargetUpdate<_, IncOrDec> = issuer_schema_ids
                    .iter()
                    .copied()
                    .zip(repeat(update))
                    .collect();

                TrustRegistryDelegatedIssuerSchemas::<T>::mutate(
                    registry_id,
                    issuer,
                    |schema_ids| {
                        schema_ids_update.apply_update(schema_ids);
                    },
                );
            }

            delegated.apply_update(&mut config.delegated);
            Self::deposit_event(Event::DelegatedIssuersUpdated(registry_id, issuer));

            Ok(())
        })
        .map_err(Error::<T>::into)
    }

    pub(super) fn suspend_issuers_(
        SuspendIssuers {
            registry_id,
            issuers,
            ..
        }: SuspendIssuers<T>,
        registry_info: TrustRegistryInfo<T>,
        convener: Convener,
    ) -> DispatchResult {
        convener.ensure_controls::<T>(&registry_info)?;

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
        registry_info: TrustRegistryInfo<T>,
        convener: Convener,
    ) -> DispatchResult {
        convener.ensure_controls::<T>(&registry_info)?;

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

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct StepStorageAccesses {
    pub validation: StorageAccesses,
    pub execution: StorageAccesses,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepError {
    Conversion(DispatchError),
    Validation(DispatchError, StorageAccesses),
}

impl From<StepError> for DispatchError {
    fn from((StepError::Conversion(error) | StepError::Validation(error, _)): StepError) -> Self {
        error
    }
}

impl From<ActionExecutionError> for StepError {
    fn from(err: ActionExecutionError) -> Self {
        Self::Conversion(err.into())
    }
}

impl From<NonceError> for StepError {
    fn from(err: NonceError) -> Self {
        Self::Conversion(err.into())
    }
}

impl<T: crate::did::Config> From<crate::did::Error<T>> for StepError {
    fn from(err: crate::did::Error<T>) -> Self {
        Self::Conversion(err.into())
    }
}
