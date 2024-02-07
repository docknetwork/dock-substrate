use crate::util::{ApplyUpdate, UpdateKind, ValidateUpdate};

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
                name,
                gov_framework,
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
    ) -> Result<(u32, u32, u32), DispatchError> {
        let (verifiers_len, issuers_len) =
            Self::try_update_issuers_and_verifiers_with(registry_id, |issuers, verifiers| {
                let is_convener = Convener(*actor).ensure_controls(&registry_info).is_ok();

                for (schema_id, update) in schemas.iter() {
                    let schema_metadata =
                        TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id);

                    if is_convener {
                        update.ensure_valid(&Convener(*actor), &schema_metadata)?;
                    } else {
                        update.ensure_valid(&IssuerOrVerifier(*actor), &schema_metadata)?;
                    }

                    update.record_inner_issuers_and_verifiers_diff(
                        &schema_metadata,
                        *schema_id,
                        issuers,
                        verifiers,
                    )?;
                }

                Ok((verifiers.len(), issuers.len()))
            })?;

        let schemas_len = schemas.len();

        for (schema_id, update) in schemas {
            TrustRegistrySchemasMetadata::<T>::mutate_exists(
                schema_id,
                registry_id,
                |schema_metadata| {
                    let event = match update.kind(&*schema_metadata) {
                        UpdateKind::Add => Event::SchemaMetadataAdded(registry_id, schema_id),
                        UpdateKind::Remove => Event::SchemaMetadataRemoved(registry_id, schema_id),
                        UpdateKind::Replace => Event::SchemaMetadataUpdated(registry_id, schema_id),
                        UpdateKind::None => return,
                    };

                    Self::deposit_event(event);

                    update.apply_update(schema_metadata);
                },
            );
        }

        Ok((verifiers_len as u32, issuers_len as u32, schemas_len as u32))
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
        TrustRegistryStoredSchemas::<T>::iter_prefix(registry_id).filter_map(
            move |(schema_id, ())| {
                TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id)
                    .map(|schema_metadata| (schema_id, schema_metadata))
            },
        )
    }

    /// Set `schema_id`s corresponding to each issuer and verifier of trust registry with given id.
    /// Will check that updates are valid and then update storage in `TrustRegistryVerifierSchemas` and `TrustRegistryIssuerSchemas`
    fn try_update_issuers_and_verifiers_with<R, F>(
        registry_id: TrustRegistryId,
        f: F,
    ) -> Result<R, DispatchError>
    where
        F: FnOnce(
            &mut MultiSchemaUpdate<Issuer>,
            &mut MultiSchemaUpdate<Verifier>,
        ) -> Result<R, DispatchError>,
    {
        let (mut issuers, mut verifiers) = Default::default();

        let res = f(&mut issuers, &mut verifiers)?;

        for (issuer, update) in issuers.iter() {
            let schemas = TrustRegistryIssuerSchemas::<T>::get(registry_id, issuer);
            update.ensure_valid(issuer, &schemas)?;
        }

        for (verifier, update) in verifiers.iter() {
            let schemas = TrustRegistryVerifierSchemas::<T>::get(registry_id, verifier);
            update.ensure_valid(verifier, &schemas)?;
        }

        for (issuer, update) in issuers {
            TrustRegistryIssuerSchemas::<T>::mutate(registry_id, issuer, |schemas| {
                update.apply_update(schemas)
            })
        }

        for (verifier, update) in verifiers {
            TrustRegistryVerifierSchemas::<T>::mutate(registry_id, verifier, |schemas| {
                update.apply_update(schemas)
            })
        }

        Ok(res)
    }
}
