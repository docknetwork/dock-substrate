use super::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::{convert::identity, iter::repeat};
use itertools::Itertools;
use types::*;

/// Specifies arguments to retrieve trust registries informations by.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct QueryTrustRegistriesBy {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    issuers: Option<AnyOfOrAll<Issuer>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    verifiers: Option<AnyOfOrAll<Verifier>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    issuers_or_verifiers: Option<AnyOfOrAll<IssuerOrVerifier>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    schema_ids: Option<AnyOfOrAll<TrustRegistrySchemaId>>,
}

/// Specifies arguments to retrieve trust registry informations by.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct QueryTrustRegistryBy {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    issuers: Option<AnyOfOrAll<Issuer>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    verifiers: Option<AnyOfOrAll<Verifier>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    issuers_or_verifiers: Option<AnyOfOrAll<IssuerOrVerifier>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    schema_ids: Option<BTreeSet<TrustRegistrySchemaId>>,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum AnyOfOrAll<V: Ord> {
    AnyOf(BTreeSet<V>),
    All(BTreeSet<V>),
}

impl<V: Ord> AnyOfOrAll<V> {
    pub fn satisfy(&self, others: &BTreeSet<V>) -> bool {
        match self {
            Self::AnyOf(values) => !values.is_disjoint(others),
            Self::All(values) => values.is_subset(others),
        }
    }

    pub fn apply<IR, F>(self, f: F) -> BTreeSet<IR::Item>
    where
        F: FnMut(V) -> IR,
        IR: IntoIterator,
        IR::Item: Ord,
    {
        match self {
            Self::AnyOf(issuers) => issuers.into_iter().flat_map(f).collect(),
            Self::All(issuers) => {
                let len = issuers.len();

                issuers
                    .into_iter()
                    .map(f)
                    .kmerge()
                    .dedup_with_count()
                    .filter_map(|(count, value)| (count == len).then_some(value))
                    .collect()
            }
        }
    }
}

impl QueryTrustRegistryBy {
    /// Resolves to a map containing `TrustRegistrySchemaId` -> `AggregatedTrustRegistrySchemaMetadata<T>` pairs.
    pub fn resolve_to_schemas_metadata_in_registry<T: Config>(
        self,
        reg_id: TrustRegistryId,
    ) -> BTreeMap<TrustRegistrySchemaId, AggregatedTrustRegistrySchemaMetadata<T>> {
        let schema_ids = self.resolve_to_schema_ids_in_registry::<T>(reg_id);

        repeat(reg_id)
            .zip(schema_ids)
            .with_schema_metadata()
            .collect()
    }

    pub fn resolve_to_schema_ids_in_registry<T: Config>(
        self,
        reg_id: TrustRegistryId,
    ) -> BTreeSet<TrustRegistrySchemaId> {
        let Self {
            issuers,
            verifiers,
            issuers_or_verifiers,
            schema_ids,
        } = self;

        let issuer_schema_ids = issuers.map(|issuers| {
            issuers.apply(|issuer| Pallet::<T>::registry_issuer_schemas(reg_id, issuer))
        });
        let verifier_schema_ids = verifiers.map(|verifiers| {
            verifiers.apply(|verifier| Pallet::<T>::registry_verifier_schemas(reg_id, verifier))
        });

        let issuers_and_verifiers_schema_ids =
            MaybeDoubleSet(issuer_schema_ids, verifier_schema_ids).intersection();
        let issuers_or_verifiers_schema_ids = issuers_or_verifiers.map(|issuer_or_verifier| {
            issuer_or_verifier.apply(|issuer_or_verifier| {
                Pallet::<T>::registry_issuer_or_verifier_schemas(reg_id, issuer_or_verifier)
            })
        });

        let combined_issuers_verifiers_schema_ids = MaybeDoubleSet(
            issuers_and_verifiers_schema_ids,
            issuers_or_verifiers_schema_ids,
        )
        .union();

        MaybeDoubleSet(combined_issuers_verifiers_schema_ids, schema_ids)
            .intersection()
            .unwrap_or_default()
    }
}

impl QueryTrustRegistriesBy {
    /// Resolves to a map containing `TrustRegistryId` -> `TrustRegistryInfo<T>` pairs.
    pub fn resolve_to_registries_info<T: Config>(
        self,
    ) -> BTreeMap<TrustRegistryId, TrustRegistryInfo<T>> {
        self.resolve_to_registry_ids::<T>()
            .with_registry_info()
            .collect()
    }

    pub fn resolve_to_registry_ids<T: Config>(self) -> BTreeSet<TrustRegistryId> {
        let Self {
            issuers,
            verifiers,
            issuers_or_verifiers,
            schema_ids,
        } = self;

        let issuer_regs = issuers.map(|issuers| issuers.apply(Pallet::<T>::issuer_registries));
        let verifier_regs =
            verifiers.map(|verifiers| verifiers.apply(Pallet::<T>::verifier_registries));

        let issuers_and_verifiers_regs = MaybeDoubleSet(issuer_regs, verifier_regs).intersection();
        let issuers_or_verifiers_regs = issuers_or_verifiers.map(|issuers_or_verifiers| {
            issuers_or_verifiers.apply(Pallet::<T>::issuer_or_verifier_registries)
        });

        let combined_issuers_verifiers_regs =
            MaybeDoubleSet(issuers_or_verifiers_regs, issuers_and_verifiers_regs).intersection();
        let schema_id_regs = schema_ids
            .map(|schema_ids| schema_ids.apply(TrustRegistrySchemasMetadata::<T>::iter_key_prefix));

        MaybeDoubleSet(combined_issuers_verifiers_regs, schema_id_regs)
            .intersection()
            .unwrap_or_default()
    }
}

struct MaybeDoubleSet<V: Ord>(Option<BTreeSet<V>>, Option<BTreeSet<V>>);

impl<V: Ord + Clone> MaybeDoubleSet<V> {
    fn intersection(self) -> Option<BTreeSet<V>> {
        let Self(first, second) = self;

        Some(match (first, second) {
            (Some(first), Some(second)) => first.intersection(&second).cloned().collect(),
            (Some(first), None) => first,
            (None, Some(second)) => second,
            (None, None) => None?,
        })
    }

    fn union(self) -> Option<BTreeSet<V>> {
        let Self(first, second) = self;

        Some(match (first, second) {
            (Some(first), Some(second)) => first.union(&second).cloned().collect(),
            (Some(first), None) => first,
            (None, Some(second)) => second,
            (None, None) => None?,
        })
    }
}

/// Extension that can be used by types implementing `IntoIterator`.
trait IntoIterExt: IntoIterator + Sized {
    /// Transforms value to an iterator emitting `TrustRegistryId`, then transforms result to an iterator producing
    /// `(TrustRegistryId, TrustRegistryInfo<T>)` pairs.
    fn with_registry_info<T>(
        self,
    ) -> WithEntity<Self::IntoIter, TrustRegistryId, TrustRegistryInfo<T>>
    where
        Self: IntoIterator<Item = TrustRegistryId>,
        T: Config;

    /// Transforms value to an iterator emitting `(TrustRegistryId, TrustRegistrySchemaId)`, then transforms result to an iterator producing
    /// `(TrustRegistrySchemaId, AggregatedTrustRegistrySchemaMetadata<T>)` pairs.
    fn with_schema_metadata<T>(
        self,
    ) -> WithEntity<Self::IntoIter, TrustRegistrySchemaId, AggregatedTrustRegistrySchemaMetadata<T>>
    where
        Self: IntoIterator<Item = (TrustRegistryId, TrustRegistrySchemaId)>,
        T: Config;
}

impl<I> IntoIterExt for I
where
    I: IntoIterator,
{
    fn with_registry_info<T>(
        self,
    ) -> WithEntity<Self::IntoIter, TrustRegistryId, TrustRegistryInfo<T>>
    where
        Self: IntoIterator<Item = TrustRegistryId>,
        T: Config,
    {
        WithEntity::new(
            self.into_iter(),
            identity,
            TrustRegistriesInfo::<T>::get as _,
        )
    }

    fn with_schema_metadata<T>(
        self,
    ) -> WithEntity<Self::IntoIter, TrustRegistrySchemaId, AggregatedTrustRegistrySchemaMetadata<T>>
    where
        Self: IntoIterator<Item = (TrustRegistryId, TrustRegistrySchemaId)>,
        T: Config,
    {
        WithEntity::new(
            self.into_iter(),
            take_second::<TrustRegistryId, TrustRegistrySchemaId>,
            Pallet::<T>::aggregate_schema_metadata as _,
        )
    }
}

fn take_second<A, B>((_first, second): (A, B)) -> B {
    second
}

/// A wrapper for the iterator that converts an iterator of identifiers
/// to an iterator of paired identifiers and the corresponding entities.
pub struct WithEntity<I: Iterator, K, V>(I, fn(I::Item) -> K, fn(I::Item) -> Option<V>);

impl<I, K, V> WithEntity<I, K, V>
where
    I: Iterator,
{
    fn new(iter: I, map_key: fn(I::Item) -> K, map_value: fn(I::Item) -> Option<V>) -> Self {
        Self(iter, map_key, map_value)
    }
}

impl<I, K, V> Iterator for WithEntity<I, K, V>
where
    I: Iterator,
    I::Item: Clone,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let id = self.0.next()?;

            if let Some(data) = self.2(id.clone()) {
                break Some((self.1(id), data));
            }
        }
    }
}
