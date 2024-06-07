use super::*;
use crate::{common::Limits, util::batch_update::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};
use core::{
    iter,
    iter::once,
    ops::{Deref, DerefMut},
};
use frame_support::{DebugNoBound, DefaultNoBound, EqNoBound, PartialEqNoBound};
use itertools::{EitherOrBoth, Itertools};
use types::*;
use utils::BoundedString;

macro_rules! check_err {
    ($expr: expr) => {
        if let Err(err) = $expr {
            return Some(Err(err.into()));
        }
    };
}

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
    SetOrModify<UnboundedRegistrySchemaIssuers, MultiTargetUpdate<Issuer, UnboundedIssuerUpdate>>;
pub type IssuersUpdate<T> =
    SetOrModify<TrustRegistrySchemaIssuers<T>, MultiTargetUpdate<Issuer, IssuerUpdate<T>>>;

pub type UnboundedSchemasUpdate = SetOrModify<
    UnboundedSchemas,
    MultiTargetUpdate<TrustRegistrySchemaId, UnboundedSchemaMetadataModification>,
>;
pub type SchemasUpdate<T> = SetOrModify<Schemas<T>, SchemaIdUpdate<SchemaMetadataModification<T>>>;

impl<T: Limits> TryFrom<UnboundedSchemas> for Schemas<T> {
    type Error = Error<T>;

    fn try_from(UnboundedSchemas(schemas): UnboundedSchemas) -> Result<Self, Self::Error> {
        let schemas: BTreeMap<_, _> = schemas
            .into_iter()
            .map(|(schema_id, schema_metadata)| Ok((schema_id, schema_metadata.try_into()?)))
            .collect::<Result<_, Error<T>>>()?;

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
        issuers: &mut MultiSchemaIdUpdate<Issuer>,
        verifiers: &mut MultiSchemaIdUpdate<Verifier>,
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

pub type UnboundedSchemaMetadataModification = SetOrAddOrRemoveOrModify<
    UnboundedTrustRegistrySchemaMetadata,
    OnlyExistent<UnboundedTrustRegistrySchemaMetadataUpdate>,
>;
pub type SchemaMetadataModification<T> = SetOrAddOrRemoveOrModify<
    TrustRegistrySchemaMetadata<T>,
    OnlyExistent<TrustRegistrySchemaMetadataUpdate<T>>,
>;

impl<T: Limits> SchemaMetadataModification<T> {
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
}

impl<T: Limits> GetUpdateKind<TrustRegistrySchemaMetadata<T>>
    for TrustRegistrySchemaMetadataUpdate<T>
{
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
}

impl GetUpdateKind<UnboundedTrustRegistrySchemaMetadata>
    for UnboundedTrustRegistrySchemaMetadataUpdate
{
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

/// Validates underlying Trust Registry update, records difference and produces an itermediate structure
/// representing an update that can be executed.
pub trait ValidateTrustRegistryUpdate<T: Config> {
    type Context<'ctx>;
    type Result;

    /// Validates underlying Trust Registry update, records difference and produces an itermediate structure
    /// representing an update that can be executed.
    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        context: &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>>
    where
        Validated<Self::Result>: ExecuteTrustRegistryUpdate<T>;
}

/// Executes an update over the Trust Registry with the supplied identifier.
/// Before calling `execute`, the caller must invoke `ValidateTrustRegistryUpdate::validate_and_record_diff`.
pub trait ExecuteTrustRegistryUpdate<T: Config> {
    type Output;

    /// Executes underlying update over the Trust Registry with the supplied identifier.
    fn execute(self, registry_id: TrustRegistryId) -> Self::Output;
}

/// An update that passed validation.
pub struct Validated<V>(V);

pub type IssuersVerifiersSchemas<
    Issuers = MultiSchemaIdUpdate<Issuer>,
    Verifiers = MultiSchemaIdUpdate<Verifier>,
    Schemas = SchemaIdUpdate,
> = (Issuers, Verifiers, Schemas);

pub struct IssuersSchemasUpdate(MultiSchemaIdUpdate<Issuer>);
pub struct IssuersAndDelegatedIssuersSchemasUpdate(
    MultiSchemaIdUpdate<Issuer>,
    MultiTargetUpdate<Issuer, SchemaIdUpdate<IncOrDec>>,
);

impl<T: Config> ValidateTrustRegistryUpdate<T> for IssuersSchemasUpdate {
    type Context<'ctx> = (&'ctx mut StorageAccesses, &'ctx BTreeSet<Issuer>);
    type Result = IssuersAndDelegatedIssuersSchemasUpdate;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        (storage_accesses, participants): &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>> {
        let Validated(issuers_update) = self.0.validate_and_record_diff(
            actor,
            registry_id,
            registry_info,
            &mut (
                &mut storage_accesses.issuer_schemas,
                &mut storage_accesses.issuer_registries,
                participants,
            ),
        )?;

        let combined_delegated_issuers_update = issuers_update
            .iter()
            .flat_map(|(issuer, updates)| {
                storage_accesses.issuer_configuration += 1;

                TrustRegistryIssuerConfigurations::<T>::get(registry_id, issuer)
                    .delegated
                    .0
                    .into_iter()
                    .map(move |delegated_issuer| (delegated_issuer, updates.clone()))
            })
            .try_fold(
                MultiTargetUpdate::<Issuer, SchemaIdUpdate<IncOrDec>>::default(),
                |mut acc, (delegated_issuer, updates)| {
                    let translated_updates = updates
                        .translate_update()
                        .map_err(IntoModuleError::into_module_error)?;
                    let entry = acc.entry(delegated_issuer).or_default();
                    let existing = core::mem::take(entry);
                    *entry = existing.combine(translated_updates)?;

                    Ok::<_, Error<T>>(acc)
                },
            )?;

        let validated_delegated_issuers_update = combined_delegated_issuers_update
            .into_iter()
            .filter_map(|(delegated_issuer, combined_updates)| {
                storage_accesses.delegated_issuer_schemas += 1;

                let schemas =
                    TrustRegistryDelegatedIssuerSchemas::<T>::get(registry_id, delegated_issuer);

                check_err!(actor.validate_update(registry_info, &combined_updates, &schemas));

                if combined_updates.kind(&schemas) == UpdateKind::None {
                    None?
                }

                Some(Ok((delegated_issuer, combined_updates)))
            })
            .collect::<Result<_, Error<T>>>()?;

        Ok(Validated(IssuersAndDelegatedIssuersSchemasUpdate(
            issuers_update,
            validated_delegated_issuers_update,
        )))
    }
}

impl<T: Config, Target> ValidateTrustRegistryUpdate<T> for MultiSchemaIdUpdate<Target>
where
    Target: HasSchemasAndRegistries<T> + Ord + 'static,
    Target::Schemas: Deref,
    Target::Registries: Deref,
    <Target::Schemas as Deref>::Target: KeyValue,
    <Target::Registries as Deref>::Target: KeyValue,
    SchemaIdUpdate: ValidateUpdate<Convener, Target::Schemas>
        + ValidateUpdate<IssuerOrVerifier, Target::Schemas>,
    RegistryIdUpdate: ValidateUpdate<Convener, Target::Registries>
        + ValidateUpdate<IssuerOrVerifier, Target::Registries>,
{
    type Context<'ctx> = (&'ctx mut u32, &'ctx mut u32, &'ctx BTreeSet<Target>);
    type Result = MultiSchemaIdUpdate<Target>;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        (ref mut schemas, ref mut regs, allowed): &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>> {
        self.into_iter()
            .inspect(|_| **schemas += 1)
            .filter_map(|(target, update)| {
                let schemas = target.schemas(registry_id);

                check_err!(actor.validate_update(registry_info, &update, &schemas));

                match update.kind(&schemas) {
                    UpdateKind::None => None?,
                    UpdateKind::Add => {
                        if !allowed.contains(&target) {
                            return Some(Err(Error::<T>::NotAParticipant));
                        }
                    }
                    _ => {}
                }

                if schemas.is_empty() {
                    let update_target_schemas = MultiTargetUpdate::from_iter(once((
                        registry_id,
                        AddOrRemoveOrModify::<_>::Add(()),
                    )));

                    **regs += 1;

                    check_err!(actor.validate_update(
                        registry_info,
                        &update_target_schemas,
                        &target.registries()
                    ))
                }

                Some(Ok((target, update)))
            })
            .collect::<Result<_, _>>()
            .map(Validated)
    }
}

pub type IssuersVerifiersSchemasWithStorageAccesses<'a> =
    (&'a mut IssuersVerifiersSchemas, &'a mut StorageAccesses);

impl<T: Config> ValidateTrustRegistryUpdate<T> for Schemas<T> {
    type Context<'ctx> = IssuersVerifiersSchemasWithStorageAccesses<'ctx>;
    type Result = SchemaIdUpdate<SchemaMetadataModification<T>>;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        ctx: &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>> {
        let Self(updates) = self;

        let to_set = updates
            .into_iter()
            .map(|(schema_id, update)| (schema_id, SetOrAddOrRemoveOrModify::Set(update)));
        let to_remove = super::TrustRegistriesStoredSchemas::<T>::get(registry_id)
            .0
            .into_iter()
            .zip(iter::repeat(SetOrAddOrRemoveOrModify::Remove));

        use EitherOrBoth::*;
        let updates: SchemaIdUpdate<SchemaMetadataModification<T>> = to_set
            .merge_join_by(to_remove, |(k1, _), (k2, _)| k1.cmp(k2))
            .map(|(Left(update) | Right(update) | Both(update, _))| update)
            .collect();

        updates.validate_and_record_diff(actor, registry_id, registry_info, ctx)
    }
}

impl<T: Config> ValidateTrustRegistryUpdate<T> for SchemaIdUpdate<SchemaMetadataModification<T>> {
    type Context<'ctx> = IssuersVerifiersSchemasWithStorageAccesses<'ctx>;
    type Result = Self;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        (ref mut issuers_verifiers_schemas, ref mut storage_accesses): &mut Self::Context<'_>,
    ) -> Result<Validated<Self>, Error<T>> {
        self.into_iter()
            .inspect(|_| storage_accesses.schemas += 1)
            .filter_map(|(schema_id, update)| {
                let schema_metadata =
                    super::TrustRegistrySchemasMetadata::<T>::get(schema_id, registry_id);

                check_err!(actor.validate_update(registry_info, &update, &schema_metadata));

                if update.kind(&schema_metadata) == UpdateKind::None {
                    None?
                }

                check_err!(update.record_inner_diff(
                    schema_id,
                    &schema_metadata,
                    issuers_verifiers_schemas
                ));

                Some(Ok((schema_id, update)))
            })
            .collect::<Result<_, _>>()
            .map(Validated)
    }
}

impl<T: Config> ValidateTrustRegistryUpdate<T> for SchemaIdUpdate {
    type Context<'ctx> = bool;
    type Result = Self;

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        read_storage: &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>> {
        if !self.is_empty() {
            let existing_schema_ids = super::TrustRegistriesStoredSchemas::<T>::get(registry_id);
            *read_storage = true;

            actor.validate_update(registry_info, &self, &existing_schema_ids)?;
        }

        Ok(Validated(self))
    }
}

impl<T: Config> ValidateTrustRegistryUpdate<T> for SchemasUpdate<T> {
    type Context<'ctx> = StorageAccesses;
    type Result = (
        SchemaIdUpdate<SchemaMetadataModification<T>>,
        IssuersVerifiersSchemas<IssuersAndDelegatedIssuersSchemasUpdate>,
    );

    fn validate_and_record_diff(
        self,
        actor: ConvenerOrIssuerOrVerifier,
        registry_id: TrustRegistryId,
        registry_info: &TrustRegistryInfo<T>,
        storage_accesses: &mut Self::Context<'_>,
    ) -> Result<Validated<Self::Result>, Error<T>> {
        let mut issuers_verifiers_schemas = Default::default();
        let Validated(update) = match self {
            Self::Set(schemas) => schemas.validate_and_record_diff(
                actor,
                registry_id,
                registry_info,
                &mut (&mut issuers_verifiers_schemas, storage_accesses),
            ),
            Self::Modify(update) => update.validate_and_record_diff(
                actor,
                registry_id,
                registry_info,
                &mut (&mut issuers_verifiers_schemas, storage_accesses),
            ),
        }?;

        let (issuers_update, verifiers_update, schema_ids_update) = issuers_verifiers_schemas;
        let participants = IssuersOrVerifiers(
            TrustRegistriesParticipants::<T>::get(TrustRegistryIdForParticipants(registry_id))
                .0
                .into(),
        );

        let Validated(issuers_and_delegated_issuers_update) = IssuersSchemasUpdate(issuers_update)
            .validate_and_record_diff(
                actor,
                registry_id,
                registry_info,
                &mut (storage_accesses, &participants.issuers()),
            )?;

        let Validated(verifiers_update) = verifiers_update.validate_and_record_diff(
            actor,
            registry_id,
            registry_info,
            &mut (
                &mut storage_accesses.verifier_schemas,
                &mut storage_accesses.verifier_registries,
                &participants.verifiers(),
            ),
        )?;

        let Validated(schema_ids_update) = schema_ids_update.validate_and_record_diff(
            actor,
            registry_id,
            registry_info,
            &mut storage_accesses.registry_schemas,
        )?;

        Ok(Validated((
            update,
            (
                issuers_and_delegated_issuers_update,
                verifiers_update,
                schema_ids_update,
            ),
        )))
    }
}

impl<T: Config> ExecuteTrustRegistryUpdate<T>
    for Validated<IssuersAndDelegatedIssuersSchemasUpdate>
{
    type Output = (u32, u32, u32, u32);

    fn execute(self, registry_id: TrustRegistryId) -> Self::Output {
        let Validated(IssuersAndDelegatedIssuersSchemasUpdate(
            issuers_update,
            delegated_issuers_update,
        )) = self;

        let (iss_schemas, iss_regs) =
            ExecuteTrustRegistryUpdate::<T>::execute(Validated(issuers_update), registry_id);

        let mut delegated_issuer_schemas = 0;
        delegated_issuers_update
            .into_iter()
            .for_each(|(delegated_issuer, updates)| {
                delegated_issuer_schemas += 1;

                TrustRegistryDelegatedIssuerSchemas::<T>::mutate(
                    registry_id,
                    delegated_issuer,
                    |schemas| updates.apply_update(schemas),
                )
            });

        (iss_schemas, iss_regs, 0, delegated_issuer_schemas)
    }
}

impl<T: Config, Target: HasSchemasAndRegistries<T> + Ord> ExecuteTrustRegistryUpdate<T>
    for Validated<MultiSchemaIdUpdate<Target>>
where
    Target::Schemas: DerefMut,
    Target::Registries: DerefMut,
    <Target::Schemas as Deref>::Target: KeyValue<Key = TrustRegistrySchemaId, Value = ()>,
    <Target::Registries as Deref>::Target: KeyValue<Key = TrustRegistryId, Value = ()>,
{
    type Output = (u32, u32);

    fn execute(self, registry_id: TrustRegistryId) -> (u32, u32) {
        let Self(updates) = self;

        updates.into_iter().fold(
            (0, 0),
            |(mut schemas_counter, mut regs_counter), (target, update)| {
                target.modify_schemas(registry_id, |schemas| {
                    schemas_counter += 1;

                    let mut regs_update = MultiTargetUpdate::default();
                    if schemas.is_empty() {
                        regs_update.insert(registry_id, AddOrRemoveOrModify::<_>::Add(()));
                    }

                    update.apply_update(schemas);

                    if schemas.is_empty() {
                        regs_update.insert(registry_id, AddOrRemoveOrModify::Remove);
                    }

                    if !regs_update.is_empty() {
                        regs_counter += 1;

                        target.modify_registries(|regs| regs_update.apply_update(regs));
                    }

                    (schemas_counter, regs_counter)
                })
            },
        )
    }
}

impl<T: Config> ExecuteTrustRegistryUpdate<T>
    for Validated<SchemaIdUpdate<SchemaMetadataModification<T>>>
{
    type Output = u32;

    fn execute(self, registry_id: TrustRegistryId) -> u32 {
        let Self(updates) = self;

        updates
            .into_iter()
            .map(|(schema_id, update)| {
                super::TrustRegistrySchemasMetadata::<T>::mutate(
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

                        update.apply_update(schema_metadata);
                        super::Pallet::<T>::deposit_event(event);
                    },
                );
            })
            .count() as u32
    }
}

impl<T: Config> ExecuteTrustRegistryUpdate<T> for Validated<SchemaIdUpdate> {
    type Output = bool;

    fn execute(self, registry_id: TrustRegistryId) -> Self::Output {
        let Self(update) = self;

        if !update.is_empty() {
            super::TrustRegistriesStoredSchemas::<T>::mutate(registry_id, |schema_set| {
                update.apply_update(schema_set)
            });

            true
        } else {
            false
        }
    }
}

impl<T: Config> ExecuteTrustRegistryUpdate<T>
    for Validated<(
        SchemaIdUpdate<SchemaMetadataModification<T>>,
        IssuersVerifiersSchemas<IssuersAndDelegatedIssuersSchemasUpdate>,
    )>
{
    type Output = StorageAccesses;

    fn execute(self, registry_id: TrustRegistryId) -> StorageAccesses {
        let Self((schemas_update, (issuers_update, verifiers_update, schemas_ids_update))) = self;

        let schemas = Validated(schemas_update).execute(registry_id);
        let (issuer_schemas, issuer_registries, issuer_configuration, delegated_issuer_schemas) =
            ExecuteTrustRegistryUpdate::<T>::execute(Validated(issuers_update), registry_id);
        let (verifier_schemas, verifier_registries) =
            ExecuteTrustRegistryUpdate::<T>::execute(Validated(verifiers_update), registry_id);
        let registry_schemas =
            ExecuteTrustRegistryUpdate::<T>::execute(Validated(schemas_ids_update), registry_id);

        StorageAccesses {
            issuer_schemas,
            issuer_registries,
            issuer_configuration,
            delegated_issuer_schemas,
            verifier_schemas,
            verifier_registries,
            schemas,
            registry_schemas,
        }
    }
}
