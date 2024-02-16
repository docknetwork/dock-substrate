use crate::util::{ActionExecutionError, ApplyUpdate, NonceError, TranslateUpdate, ValidateUpdate};

use super::*;

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
            if let Some(existing) = info.replace(TrustRegistryInfo {
                convener,
                name: name.try_into().map_err(|_| Error::<T>::NameSizeExceeded)?,
                gov_framework: gov_framework
                    .try_into()
                    .map_err(|_| Error::<T>::GovFrameworkSizeExceeded)?,
            }) {
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
    ) -> Result<(u32, u32, u32), StepError> {
        let schemas: SchemasUpdate<T> = schemas
            .translate_update()
            .map_err(IntoModuleError::into_module_error)
            .map_err(Into::into)
            .map_err(StepError::PreValidation)?;

        let mut reads = Default::default();
        schemas
            .validate_and_record_diff(actor, registry_id, &registry_info, &mut reads)
            .map_err(Into::into)
            .map_err(|error| StepError::Validation(error, reads))
            .map(|validated_update| validated_update.execute(registry_id))
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
            delegated.apply_update(&mut config.delegated);

            Self::deposit_event(Event::DelegatedIssuersUpdated(registry_id, issuer));

            Ok(())
        })
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

    pub fn schema_metadata_by_schema_id(
        schema_id: TrustRegistrySchemaId,
    ) -> impl Iterator<Item = (TrustRegistryId, TrustRegistrySchemaMetadata<T>)> {
        TrustRegistrySchemasMetadata::<T>::iter_prefix(schema_id)
    }

    pub fn schema_metadata_by_registry_id(
        registry_id: TrustRegistryId,
    ) -> impl Iterator<Item = (TrustRegistrySchemaId, TrustRegistrySchemaMetadata<T>)> {
        TrustRegistriesStoredSchemas::<T>::get(registry_id)
            .0
            .into_iter()
            .filter_map(move |schema_id| {
                TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id)
                    .map(|schema_metadata| (schema_id, schema_metadata))
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepError {
    PreValidation(DispatchError),
    Validation(DispatchError, (u32, u32, u32)),
}

impl From<StepError> for DispatchError {
    fn from(
        (StepError::PreValidation(error) | StepError::Validation(error, _)): StepError,
    ) -> Self {
        error
    }
}

impl From<ActionExecutionError> for StepError {
    fn from(err: ActionExecutionError) -> Self {
        Self::PreValidation(err.into())
    }
}

impl From<NonceError> for StepError {
    fn from(err: NonceError) -> Self {
        Self::PreValidation(err.into())
    }
}

impl<T: crate::did::Config> From<crate::did::Error<T>> for StepError {
    fn from(err: crate::did::Error<T>) -> Self {
        Self::PreValidation(err.into())
    }
}
