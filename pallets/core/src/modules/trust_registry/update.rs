use super::*;
use crate::{common::Limits, util::batch_update::*};
use types::*;

pub type UnboundedVerifiersUpdate = SetOrModify<
    UnboundedTrustRegistrySchemaVerifiers,
    MultiTargetUpdate<Verifier, AddOrRemoveOrModify<()>>,
>;
pub type VerifiersUpdate<T> = SetOrModify<
    TrustRegistrySchemaVerifiers<T>,
    MultiTargetUpdate<Verifier, AddOrRemoveOrModify<()>>,
>;

pub type UnboundedVerificationPricesUpdate =
    OnlyExistent<MultiTargetUpdate<String, SetOrAddOrRemoveOrModify<VerificationPrice>>>;
pub type VerificationPricesUpdate<T> = OnlyExistent<
    MultiTargetUpdate<
        BoundedString<<T as Limits>::MaxIssuerPriceCurrencySymbolSize>,
        SetOrAddOrRemoveOrModify<VerificationPrice>,
    >,
>;

pub type UnboundedIssuerUpdate =
    SetOrAddOrRemoveOrModify<UnboundedVerificationPrices, UnboundedVerificationPricesUpdate>;
pub type IssuerUpdate<T> =
    SetOrAddOrRemoveOrModify<VerificationPrices<T>, VerificationPricesUpdate<T>>;

pub type UnboundedIssuersUpdate =
    SetOrModify<UnboundedSchemaIssuers, MultiTargetUpdate<Issuer, UnboundedIssuerUpdate>>;
pub type IssuersUpdate<T> =
    SetOrModify<TrustRegistrySchemaIssuers<T>, MultiTargetUpdate<Issuer, IssuerUpdate<T>>>;

pub type UnboundedSchemasUpdate = SetOrModify<
    UnboundedSchemas,
    MultiTargetUpdate<TrustRegistrySchemaId, UnboundedTrustRegistrySchemaMetadataModification>,
>;
pub type SchemasUpdate<T> =
    SetOrModify<Schemas<T>, SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>>;

impl<T: Limits> TryFrom<UnboundedSchemas> for Schemas<T> {
    type Error = Error<T>;

    fn try_from(UnboundedSchemas(schemas): UnboundedSchemas) -> Result<Self, Self::Error> {
        let schemas: BTreeMap<_, _> = schemas
            .into_iter()
            .map(|(schema_id, schema_metadata)| Ok((schema_id, schema_metadata.try_into()?)))
            .collect::<Result<_, _>>()?;

        schemas
            .try_into()
            .map(Self)
            .map_err(|_| Error::<T>::SchemasPerRegistrySizeExceeded)
    }
}

#[derive(Encode, Decode, Clone, PartialEqNoBound, EqNoBound, DebugNoBound, DefaultNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaMetadataUpdate<T: Limits> {
    pub issuers: Option<IssuersUpdate<T>>,
    pub verifiers: Option<VerifiersUpdate<T>>,
}

#[derive(Encode, Decode, Clone, PartialEqNoBound, EqNoBound, DebugNoBound, DefaultNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistrySchemaMetadataUpdate {
    pub issuers: Option<UnboundedIssuersUpdate>,
    pub verifiers: Option<UnboundedVerifiersUpdate>,
}

impl<T: Limits> TranslateUpdate<TrustRegistrySchemaMetadataUpdate<T>>
    for UnboundedTrustRegistrySchemaMetadataUpdate
{
    type Error = Error<T>;

    fn translate_update(self) -> Result<TrustRegistrySchemaMetadataUpdate<T>, Self::Error> {
        let UnboundedTrustRegistrySchemaMetadataUpdate { issuers, verifiers } = self;

        Ok(TrustRegistrySchemaMetadataUpdate {
            issuers: issuers
                .map(TranslateUpdate::translate_update)
                .transpose()
                .map_err(IntoModuleError::into_module_error)?,
            verifiers: verifiers
                .map(TranslateUpdate::translate_update)
                .transpose()
                .map_err(IntoModuleError::into_module_error)?,
        })
    }
}

impl<T: Limits> TrustRegistrySchemaMetadataUpdate<T> {
    fn record_inner_issuers_and_verifiers_diff(
        &self,
        schema_id: TrustRegistrySchemaId,
        entity: &TrustRegistrySchemaMetadata<T>,
        issuers: &mut MultiSchemaUpdate<Issuer>,
        verifiers: &mut MultiSchemaUpdate<Verifier>,
    ) -> Result<(), DuplicateKey> {
        if let Some(verifiers_update) = self.verifiers.as_ref() {
            verifiers_update.record_inner_keys_diff(&entity.verifiers, schema_id, verifiers)?
        }

        if let Some(issuers_update) = self.issuers.as_ref() {
            issuers_update.record_inner_keys_diff(&entity.issuers, schema_id, issuers)?
        }

        Ok(())
    }
}

pub type UnboundedTrustRegistrySchemaMetadataModification = SetOrAddOrRemoveOrModify<
    UnboundedTrustRegistrySchemaMetadata,
    OnlyExistent<UnboundedTrustRegistrySchemaMetadataUpdate>,
>;
pub type TrustRegistrySchemaMetadataModification<T> = SetOrAddOrRemoveOrModify<
    TrustRegistrySchemaMetadata<T>,
    OnlyExistent<TrustRegistrySchemaMetadataUpdate<T>>,
>;

impl<T: Limits> TrustRegistrySchemaMetadataModification<T> {
    pub(super) fn record_inner_diff(
        &self,
        schema_id: TrustRegistrySchemaId,
        entity: &Option<TrustRegistrySchemaMetadata<T>>,
        (issuers, verifiers, schemas): &mut IssuersVerifiersSchemas,
    ) -> Result<(), DuplicateKey> {
        match self.kind(entity) {
            UpdateKind::Add => schemas.insert_update(schema_id, AddOrRemoveOrModify::Add(()))?,
            UpdateKind::Remove => schemas.insert_update(schema_id, AddOrRemoveOrModify::Remove)?,
            _ => {}
        }

        match self {
            Self::Add(new) => new.record_inner_issuers_and_verifiers_diff(
                issuers,
                verifiers,
                MultiTargetUpdate::bind_modifier(
                    MultiTargetUpdate::insert_update,
                    schema_id,
                    AddOrRemoveOrModify::Add(()),
                ),
            ),
            Self::Remove => entity
                .as_ref()
                .expect("An entity expected")
                .record_inner_issuers_and_verifiers_diff(
                    issuers,
                    verifiers,
                    MultiTargetUpdate::bind_modifier(
                        MultiTargetUpdate::insert_update,
                        schema_id,
                        AddOrRemoveOrModify::Remove,
                    ),
                ),
            Self::Set(new) => {
                if let Some(old) = entity {
                    old.record_inner_issuers_and_verifiers_diff(
                        issuers,
                        verifiers,
                        MultiTargetUpdate::bind_modifier(
                            MultiTargetUpdate::insert_update,
                            schema_id,
                            AddOrRemoveOrModify::Remove,
                        ),
                    )?;
                }

                new.record_inner_issuers_and_verifiers_diff(issuers, verifiers, |map| {
                    MultiTargetUpdate::insert_update_or_remove_duplicate_if(
                        map,
                        schema_id,
                        AddOrRemoveOrModify::Add(()),
                        |update| matches!(update, AddOrRemoveOrModify::Remove),
                    )
                })
            }
            Self::Modify(OnlyExistent(update)) => update.record_inner_issuers_and_verifiers_diff(
                schema_id,
                entity.as_ref().expect("An entity expected"),
                issuers,
                verifiers,
            ),
        }
    }
}

impl<T: Limits> ApplyUpdate<TrustRegistrySchemaMetadata<T>>
    for TrustRegistrySchemaMetadataUpdate<T>
{
    fn apply_update(
        self,
        TrustRegistrySchemaMetadata { issuers, verifiers }: &mut TrustRegistrySchemaMetadata<T>,
    ) {
        let Self {
            issuers: issuers_update,
            verifiers: verifiers_update,
        } = self;

        if let Some(update) = issuers_update {
            update.apply_update(issuers);
        }
        if let Some(update) = verifiers_update {
            update.apply_update(verifiers);
        }
    }

    fn kind(
        &self,
        TrustRegistrySchemaMetadata { issuers, verifiers }: &TrustRegistrySchemaMetadata<T>,
    ) -> UpdateKind {
        match (
            self.issuers
                .as_ref()
                .map(|update| update.kind(issuers))
                .unwrap_or_default(),
            self.verifiers
                .as_ref()
                .map(|update| update.kind(verifiers))
                .unwrap_or_default(),
        ) {
            (UpdateKind::None, UpdateKind::None) => UpdateKind::None,
            _ => UpdateKind::Replace,
        }
    }
}

impl<A, T: Limits> ValidateUpdate<A, TrustRegistrySchemaMetadata<T>>
    for TrustRegistrySchemaMetadataUpdate<T>
where
    A: CanUpdateAndCanUpdateKeyed<TrustRegistrySchemaIssuers<T>>
        + CanUpdateAndCanUpdateKeyed<TrustRegistrySchemaVerifiers<T>>
        + CanUpdateAndCanUpdateKeyed<VerificationPrices<T>>
        + CanUpdate<VerificationPrice>,
{
    fn ensure_valid(
        &self,
        actor: &A,
        TrustRegistrySchemaMetadata { issuers, verifiers }: &TrustRegistrySchemaMetadata<T>,
    ) -> Result<(), UpdateError> {
        if let Some(update) = self.issuers.as_ref() {
            update.ensure_valid(actor, issuers)?;
        }
        if let Some(update) = self.verifiers.as_ref() {
            update.ensure_valid(actor, verifiers)?;
        }

        Ok(())
    }
}

impl ApplyUpdate<UnboundedTrustRegistrySchemaMetadata>
    for UnboundedTrustRegistrySchemaMetadataUpdate
{
    fn apply_update(
        self,
        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers }: &mut UnboundedTrustRegistrySchemaMetadata,
    ) {
        let Self {
            issuers: issuers_update,
            verifiers: verifiers_update,
        } = self;

        if let Some(update) = issuers_update {
            update.apply_update(issuers);
        }
        if let Some(update) = verifiers_update {
            update.apply_update(verifiers);
        }
    }

    fn kind(
        &self,
        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers }: &UnboundedTrustRegistrySchemaMetadata,
    ) -> UpdateKind {
        match (
            self.issuers
                .as_ref()
                .map(|update| update.kind(issuers))
                .unwrap_or_default(),
            self.verifiers
                .as_ref()
                .map(|update| update.kind(verifiers))
                .unwrap_or_default(),
        ) {
            (UpdateKind::None, UpdateKind::None) => UpdateKind::None,
            _ => UpdateKind::Replace,
        }
    }
}

pub trait ValidateTrustRegistryUpdate<T: Config> {
    type Context;
    type Result;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        context: &mut Self::Context,
    ) -> Result<Validated<Self::Result>, DispatchError>;
}

pub trait ExecutableTrustRegistryUpdate<T: Config> {
    type Output;

    fn execute(self, registry_id: TrustRegistryId) -> Self::Output;
}

/// An update that passed validation.
pub struct Validated<V>(V);

pub type IssuersVerifiersSchemas = (
    MultiSchemaUpdate<Issuer>,
    MultiSchemaUpdate<Verifier>,
    SchemaUpdate,
);

impl<T: Config> ValidateTrustRegistryUpdate<T> for Schemas<T> {
    type Context = IssuersVerifiersSchemas;
    type Result = SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>;

    fn validate_and_record_diff(
        mut self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        ctx: &mut Self::Context,
    ) -> Result<Validated<Self::Result>, DispatchError> {
        Convener(*actor).ensure_controls(registry_info)?;
        let schema_ids = self.0.keys().cloned().collect();

        super::TrustRegistriesStoredSchemas::<T>::get(registry_id)
            .union(&schema_ids)
            .filter_map(|&schema_id| {
                let existing_schema =
                    super::TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id);
                let update = self
                    .take(&schema_id)
                    .map(TrustRegistrySchemaMetadataModification::<T>::Set)
                    .unwrap_or(TrustRegistrySchemaMetadataModification::<T>::Remove);

                if update.kind(&existing_schema) == UpdateKind::None {
                    None?
                }

                update
                    .record_inner_diff(schema_id, &existing_schema, ctx)
                    .map(move |()| Some((schema_id, update)))
                    .map_err(Into::into)
                    .transpose()
            })
            .collect::<Result<_, _>>()
            .map(Validated)
    }
}

impl<T: Config> ValidateTrustRegistryUpdate<T>
    for SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>
{
    type Context = IssuersVerifiersSchemas;
    type Result = Self;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        ctx: &mut Self::Context,
    ) -> Result<Validated<Self>, DispatchError> {
        self.0
            .into_iter()
            .filter_map(|(schema_id, update)| {
                let schema_metadata =
                    super::TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id);

                check_err!(actor.validate_update(registry_info, &update, &schema_metadata));

                if update.kind(&schema_metadata) == UpdateKind::None {
                    None?
                }

                check_err!(update.record_inner_diff(schema_id, &schema_metadata, ctx));

                Some(Ok((schema_id, update)))
            })
            .collect::<Result<_, _>>()
            .map(Validated)
    }
}

impl<T: Config> ExecutableTrustRegistryUpdate<T>
    for Validated<SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>>
{
    type Output = u32;

    fn execute(self, registry_id: TrustRegistryId) -> u32 {
        let Self(updates) = self;

        updates
            .into_iter()
            .map(|(schema_id, update)| {
                super::TrustRegistrySchemasMetadata::<T>::mutate_exists(
                    schema_id,
                    registry_id,
                    |schema_metadata| {
                        let event = match update.kind(&*schema_metadata) {
                            UpdateKind::Add => {
                                super::Event::SchemaMetadataAdded(registry_id, schema_id)
                            }
                            UpdateKind::Remove => {
                                super::Event::SchemaMetadataRemoved(registry_id, schema_id)
                            }
                            UpdateKind::Replace => {
                                super::Event::SchemaMetadataUpdated(registry_id, schema_id)
                            }
                            UpdateKind::None => return,
                        };

                        super::Pallet::<T>::deposit_event(event);

                        update.apply_update(schema_metadata);
                    },
                );
            })
            .count() as u32
    }
}

impl<T: Config> ValidateTrustRegistryUpdate<T> for SchemasUpdate<T> {
    type Context = (u32, u32, u32);
    type Result = (
        SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>,
        IssuersVerifiersSchemas,
    );

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        (ref mut issuers_read, ref mut verifiers_read, ref mut schemas_read): &mut Self::Context,
    ) -> Result<Validated<Self::Result>, DispatchError> {
        let mut issuers_verifiers_schemas = Default::default();
        let Validated(update) = match self {
            Self::Set(schemas) => schemas.validate_and_record_diff(
                actor,
                registry_id,
                registry_info,
                &mut issuers_verifiers_schemas,
            ),
            Self::Modify(update) => update.validate_and_record_diff(
                actor,
                registry_id,
                registry_info,
                &mut issuers_verifiers_schemas,
            ),
        }?;

        let (mut issuers_update, mut verifiers_update, schema_ids_update) =
            issuers_verifiers_schemas;
        *schemas_read = schema_ids_update.len() as u32;

        issuers_update = issuers_update
            .into_iter()
            .filter_map(|(issuer, update)| {
                let schemas = super::TrustRegistryIssuerSchemas::<T>::get(registry_id, issuer);
                *issuers_read += 1;

                check_err!(actor.validate_update(registry_info, &update, &schemas));

                if update.kind(&schemas) == UpdateKind::None {
                    None?
                }

                if schemas.is_empty() {
                    let update_issuer_schemas = MultiTargetUpdate::from_iter(once((
                        registry_id,
                        AddOrRemoveOrModify::<_>::Add(()),
                    )));

                    check_err!(actor.validate_update(
                        registry_info,
                        &update_issuer_schemas,
                        &super::IssuersTrustRegistries::<T>::get(issuer)
                    ))
                }

                Some(Ok((issuer, update)))
            })
            .collect::<Result<_, DispatchError>>()?;

        verifiers_update = verifiers_update
            .into_iter()
            .filter_map(|(verifier, update)| {
                let schemas = super::TrustRegistryVerifierSchemas::<T>::get(registry_id, verifier);
                *verifiers_read += 1;

                check_err!(actor.validate_update(registry_info, &update, &schemas));

                if update.kind(&schemas) == UpdateKind::None {
                    None?
                }

                if schemas.is_empty() {
                    let update_verifier_schemas = MultiTargetUpdate::from_iter(once((
                        registry_id,
                        AddOrRemoveOrModify::<_>::Add(()),
                    )));

                    check_err!(actor.validate_update(
                        registry_info,
                        &update_verifier_schemas,
                        &super::VerifiersTrustRegistries::<T>::get(verifier),
                    ));
                }

                Some(Ok((verifier, update)))
            })
            .collect::<Result<_, DispatchError>>()?;

        if !schema_ids_update.is_empty() {
            let existing_schema_ids = super::TrustRegistriesStoredSchemas::<T>::get(registry_id);

            actor.validate_update(registry_info, &schema_ids_update, &existing_schema_ids)?;
        }

        Ok(Validated((
            update,
            (issuers_update, verifiers_update, schema_ids_update),
        )))
    }
}

impl<T: Config> ExecutableTrustRegistryUpdate<T>
    for Validated<(
        SchemaUpdate<TrustRegistrySchemaMetadataModification<T>>,
        IssuersVerifiersSchemas,
    )>
{
    type Output = (u32, u32, u32);

    fn execute(self, registry_id: TrustRegistryId) -> (u32, u32, u32) {
        let Self((schemas_update, (issuers, verifiers, schemas))) = self;
        let issuers_count = issuers.len() as u32;
        let verifiers_count = verifiers.len() as u32;

        for (issuer, update) in issuers {
            super::TrustRegistryIssuerSchemas::<T>::mutate(registry_id, issuer, |schemas| {
                let mut regs_update = MultiTargetUpdate::default();
                if schemas.is_empty() {
                    regs_update.insert(registry_id, AddOrRemoveOrModify::<_>::Add(()));
                }

                update.apply_update(schemas);

                if schemas.is_empty() {
                    regs_update.insert(registry_id, AddOrRemoveOrModify::Remove);
                }

                if !regs_update.is_empty() {
                    super::IssuersTrustRegistries::<T>::mutate(issuer, |regs| {
                        regs_update.apply_update(regs)
                    });
                }
            })
        }

        for (verifier, update) in verifiers {
            super::TrustRegistryVerifierSchemas::<T>::mutate(registry_id, verifier, |schemas| {
                let mut regs_update = MultiTargetUpdate::default();
                if schemas.is_empty() {
                    regs_update.insert(registry_id, AddOrRemoveOrModify::<_>::Add(()));
                }

                update.apply_update(schemas);

                if schemas.is_empty() {
                    regs_update.insert(registry_id, AddOrRemoveOrModify::Remove);
                }

                if !regs_update.is_empty() {
                    super::VerifiersTrustRegistries::<T>::mutate(verifier, |regs| {
                        regs_update.apply_update(regs)
                    });
                }
            })
        }

        let schemas_count = Validated(schemas_update).execute(registry_id);

        super::TrustRegistriesStoredSchemas::<T>::mutate(registry_id, |schema_set| {
            schemas.apply_update(schema_set)
        });

        (issuers_count, verifiers_count, schemas_count)
    }
}
