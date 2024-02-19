use super::{
    Config, ConvenerTrustRegistries, Error, IntoModuleError, TrustRegistriesInfo,
    TrustRegistrySchemasMetadata,
};
#[cfg(feature = "serde")]
use crate::util::{btree_map, btree_set, hex};
use crate::{
    common::{AuthorizeTarget, Limits},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    impl_wrapper,
    util::{batch_update::*, BoundedBytes, KeyValue, OptionExt, StorageRef},
};
use alloc::collections::BTreeMap;
use codec::{Decode, Encode, MaxEncodedLen};
use core::{borrow::Borrow, fmt::Debug, iter::once, marker::PhantomData};
use frame_support::*;
use scale_info::prelude::string::String;
use sp_runtime::DispatchError;
use sp_std::{collections::btree_set::BTreeSet, prelude::*};
use utils::BoundedString;

macro_rules! check_err {
    ($expr: expr) => {
        if let Err(err) = $expr {
            return Some(Err(err.into()));
        }
    };
}

/// Trust registry `Convener`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Convener(pub DidOrDidMethodKey);

impl_wrapper!(Convener(DidOrDidMethodKey));

impl<T: Config> StorageRef<T> for Convener {
    type Value = TrustRegistryIdSet<T>;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<TrustRegistryIdSet<T>>) -> Result<R, E>,
    {
        ConvenerTrustRegistries::<T>::try_mutate_exists(self, |entry| f(entry.initialized()))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<TrustRegistryIdSet<T>>) -> R,
    {
        f(Some(ConvenerTrustRegistries::<T>::get(self)))
    }
}

impl AuthorizeTarget<Self, DidKey> for Convener {}
impl AuthorizeTarget<TrustRegistryId, DidKey> for Convener {}
impl AuthorizeTarget<Self, DidMethodKey> for Convener {}
impl AuthorizeTarget<TrustRegistryId, DidMethodKey> for Convener {}

/// Maybe an `Issuer` or a `Verifier` but definitely not a `Convener`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IssuerOrVerifier(pub DidOrDidMethodKey);

impl_wrapper!(IssuerOrVerifier(DidOrDidMethodKey));

/// Both an `Issuer` and a `Verifier`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IssuerAndVerifier(pub DidOrDidMethodKey);

impl_wrapper!(IssuerAndVerifier(DidOrDidMethodKey));

impl Convener {
    pub fn ensure_controls<T: Limits>(
        &self,
        TrustRegistryInfo { convener, .. }: &TrustRegistryInfo<T>,
    ) -> Result<(), Error<T>> {
        ensure!(convener == self, Error::<T>::NotTheConvener);

        Ok(())
    }
}

/// Trust registry `Issuer`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Issuer(pub DidOrDidMethodKey);

impl_wrapper!(Issuer(DidOrDidMethodKey));

impl AuthorizeTarget<TrustRegistryId, DidKey> for Issuer {}
impl AuthorizeTarget<TrustRegistryId, DidMethodKey> for Issuer {}
impl AuthorizeTarget<(), DidKey> for Issuer {}
impl AuthorizeTarget<(), DidMethodKey> for Issuer {}

/// Trust registry `Verifier`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Verifier(pub DidOrDidMethodKey);

impl_wrapper!(Verifier(DidOrDidMethodKey));

/// Trust registry `Convener`/`Issuer`/`Verifier`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct ConvenerOrIssuerOrVerifier(pub DidOrDidMethodKey);

impl_wrapper!(ConvenerOrIssuerOrVerifier(DidOrDidMethodKey));

impl ConvenerOrIssuerOrVerifier {
    pub fn validate_update<T, E, U>(
        &self,
        trust_registry_info: &TrustRegistryInfo<T>,
        update: &U,
        entity: &E,
    ) -> Result<(), UpdateError>
    where
        U: ValidateUpdate<Convener, E> + ValidateUpdate<IssuerOrVerifier, E>,
        T: Limits,
    {
        if Convener(**self)
            .ensure_controls(trust_registry_info)
            .is_ok()
        {
            update.ensure_valid(&Convener(**self), entity)
        } else {
            update.ensure_valid(&IssuerOrVerifier(**self), entity)
        }
    }
}

impl AuthorizeTarget<TrustRegistryId, DidKey> for ConvenerOrIssuerOrVerifier {}
impl AuthorizeTarget<TrustRegistryId, DidMethodKey> for ConvenerOrIssuerOrVerifier {}

/// Price to verify a credential. Lowest denomination should be used.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct VerificationPrice(#[codec(compact)] pub u128);

/// Prices of verifying a credential corresponding to the specific schema metadata per different currencies.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct VerificationPrices<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_map"))]
    pub  BoundedBTreeMap<
        BoundedString<T::MaxIssuerPriceCurrencySymbolSize>,
        VerificationPrice,
        T::MaxIssuerPriceCurrencies,
    >,
);

impl_wrapper!(VerificationPrices<T> where T: Limits => (BoundedBTreeMap<BoundedString<T::MaxIssuerPriceCurrencySymbolSize>, VerificationPrice, T::MaxIssuerPriceCurrencies>));

/// Prices of verifying a credential corresponding to the specific schema metadata per different currencies.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedVerificationPrices(pub BTreeMap<String, VerificationPrice>);

impl_wrapper!(UnboundedVerificationPrices(BTreeMap<String, VerificationPrice>));

#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
pub struct Schemas<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_map"))]
    pub  BoundedBTreeMap<
        TrustRegistrySchemaId,
        TrustRegistrySchemaMetadata<T>,
        T::MaxSchemasPerRegistry,
    >,
);

impl_wrapper!(Schemas<T> where T: Limits => (BoundedBTreeMap<TrustRegistrySchemaId, TrustRegistrySchemaMetadata<T>, T::MaxSchemasPerRegistry>));

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
pub struct UnboundedSchemas(
    pub BTreeMap<TrustRegistrySchemaId, UnboundedTrustRegistrySchemaMetadata>,
);

impl_wrapper!(
    UnboundedSchemas(BTreeMap<TrustRegistrySchemaId, UnboundedTrustRegistrySchemaMetadata>)
);

#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AggregatedIssuerInfo<T: Limits> {
    verification_prices: VerificationPrices<T>,
    suspended: bool,
    delegated: DelegatedIssuers<T>,
}

/// A map from `Issuer` to some value.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "T: Sized, Entry: Serialize",
        deserialize = "T: Sized, Entry: Deserialize<'de>"
    ))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct IssuersWith<T: Limits, Entry: Eq + Clone + Debug>(
    #[cfg_attr(feature = "serde", serde(with = "btree_map"))]
    pub  BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchema>,
);

impl_wrapper!(IssuersWith<T, Entry> where T: Limits, Entry: Eq, Entry: Clone, Entry: Debug => (BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchema>));

/// Schema `Issuer`s (`Issuer` => verification prices).
pub type SchemaIssuers<T> = IssuersWith<T, VerificationPrices<T>>;

/// An unbounded map from `Issuer` to some value.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedIssuersWith<Entry: Eq + Clone + Debug>(pub BTreeMap<Issuer, Entry>);

impl_wrapper!(UnboundedIssuersWith<Entry> where Entry: Eq, Entry: Clone, Entry: Debug => (BTreeMap<Issuer, Entry>));

/// Schema `Verifier`s.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaVerifiers<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchema>,
);

impl_wrapper!(TrustRegistrySchemaVerifiers<T> where T: Limits => (BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchema>));

/// Schema `Verifier`s.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistrySchemaVerifiers(pub BTreeSet<Verifier>);

impl_wrapper!(UnboundedTrustRegistrySchemaVerifiers(BTreeSet<Verifier>));

/// Delegated `Issuer`s.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    DefaultNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DelegatedIssuers<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<Issuer, T::MaxDelegatedIssuers>,
);

impl_wrapper!(DelegatedIssuers<T> where T: Limits => (BoundedBTreeSet<Issuer, T::MaxDelegatedIssuers>));

pub type DelegatedUpdate<T> =
    SetOrModify<DelegatedIssuers<T>, MultiTargetUpdate<Issuer, AddOrRemoveOrModify<()>>>;

/// Unbounded delegated `Issuer`s.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedDelegatedIssuers(pub BTreeSet<Issuer>);

impl_wrapper!(UnboundedDelegatedIssuers(BTreeSet<Issuer>));

impl<T: Limits> TryFrom<UnboundedDelegatedIssuers> for DelegatedIssuers<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedDelegatedIssuers(set): UnboundedDelegatedIssuers,
    ) -> Result<Self, Self::Error> {
        set.try_into()
            .map_err(|_| Error::<T>::DelegatedIssuersSizeExceeded)
            .map(DelegatedIssuers)
    }
}

pub type UnboundedDelegatedUpdate =
    SetOrModify<UnboundedDelegatedIssuers, MultiTargetUpdate<Issuer, AddOrRemoveOrModify<()>>>;

#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    DefaultNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryIssuerConfiguration<T: Limits> {
    pub suspended: bool,
    pub delegated: DelegatedIssuers<T>,
}

/// `Trust Registry` schema metadata.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaMetadata<T: Limits> {
    pub issuers: SchemaIssuers<T>,
    pub verifiers: TrustRegistrySchemaVerifiers<T>,
}

/// Unbounded `Trust Registry` schema metadata.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistrySchemaMetadata {
    pub issuers: UnboundedSchemaIssuers,
    pub verifiers: UnboundedTrustRegistrySchemaVerifiers,
}

impl<T: Limits> TryFrom<UnboundedTrustRegistrySchemaMetadata> for TrustRegistrySchemaMetadata<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers }: UnboundedTrustRegistrySchemaMetadata,
    ) -> Result<Self, Self::Error> {
        let issuers: BTreeMap<Issuer, VerificationPrices<T>> = issuers
            .0
            .into_iter()
            .map(|(issuer, prices)| Ok((issuer, prices.try_into()?)))
            .collect::<Result<_, Error<T>>>()?;

        Ok(Self {
            issuers: IssuersWith(
                issuers
                    .try_into()
                    .map_err(|_| Error::<T>::IssuersSizeExceeded)?,
            ),
            verifiers: TrustRegistrySchemaVerifiers(
                verifiers
                    .0
                    .try_into()
                    .map_err(|_| Error::<T>::VerifiersSizeExceeded)?,
            ),
        })
    }
}

pub type SchemaUpdate<Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<TrustRegistrySchemaId, Update>;
pub type MultiSchemaUpdate<Key, Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<Key, SchemaUpdate<Update>>;

impl<T: Limits> TrustRegistrySchemaMetadata<T> {
    fn record_inner_issuers_and_verifiers_diff<F, U>(
        &self,
        issuers: &mut MultiSchemaUpdate<Issuer, U>,
        verifiers: &mut MultiSchemaUpdate<Verifier, U>,
        mut record_update: F,
    ) -> Result<(), DuplicateKey>
    where
        F: FnMut(&mut MultiTargetUpdate<TrustRegistrySchemaId, U>) -> Result<(), DuplicateKey>,
    {
        for issuer in self.issuers.keys().cloned() {
            record_update(issuers.entry(issuer).or_default())?;
        }

        for verifier in self.verifiers.iter().cloned() {
            record_update(verifiers.entry(verifier).or_default())?;
        }

        Ok(())
    }
}

pub type AggregatedTrustRegistrySchemaIssuers<T> = UnboundedIssuersWith<AggregatedIssuerInfo<T>>;

/// `Trust Registry` schema metadata.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AggregatedTrustRegistrySchemaMetadata<T: Limits> {
    pub issuers: AggregatedTrustRegistrySchemaIssuers<T>,
    pub verifiers: TrustRegistrySchemaVerifiers<T>,
}

impl<T: Config> TrustRegistrySchemaMetadata<T> {
    pub fn aggregate(
        self,
        registry_id: TrustRegistryId,
    ) -> AggregatedTrustRegistrySchemaMetadata<T> {
        let Self { issuers, verifiers } = self;

        let issuers = issuers
            .0
            .into_iter()
            .map(|(issuer, verification_prices)| {
                let TrustRegistryIssuerConfiguration {
                    suspended,
                    delegated,
                } = super::TrustRegistryIssuerConfigurations::<T>::get(registry_id, issuer);

                (
                    issuer,
                    AggregatedIssuerInfo {
                        verification_prices,
                        suspended,
                        delegated,
                    },
                )
            })
            .collect();

        AggregatedTrustRegistrySchemaMetadata {
            issuers: UnboundedIssuersWith(issuers),
            verifiers,
        }
    }
}

/// Set of schemas corresponding to a verifier
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct VerifierSchemas<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerVerifier>,
);

impl_wrapper!(VerifierSchemas<T> where T: Limits => (BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerVerifier>));

/// Set of trust registries corresponding to a verifier
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct VerifierTrustRegistries<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistryId, T::MaxRegistriesPerVerifier>,
);

impl_wrapper!(VerifierTrustRegistries<T> where T: Limits => (BoundedBTreeSet<TrustRegistryId, T::MaxRegistriesPerVerifier>));

/// Set of schemas that belong to the `Trust Registry`
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryStoredSchemas<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerRegistry>,
);

impl_wrapper!(TrustRegistryStoredSchemas<T> where T: Limits => (BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerRegistry>));

/// Set of schemas corresponding to a issuer
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct IssuerSchemas<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerIssuer>,
);

impl_wrapper!(IssuerSchemas<T> where T: Limits => (BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerIssuer>));

/// Set of trust registries corresponding to a issuer
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct IssuerTrustRegistries<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistryId, T::MaxRegistriesPerIssuer>,
);

impl_wrapper!(IssuerTrustRegistries<T> where T: Limits => (BoundedBTreeSet<TrustRegistryId, T::MaxRegistriesPerIssuer>));

#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    DefaultNoBound,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryIdSet<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<TrustRegistryId, T::MaxConvenerRegistries>,
);

impl_wrapper!(TrustRegistryIdSet<T> where T: Limits => (BoundedBTreeSet<TrustRegistryId, T::MaxConvenerRegistries>));

#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryInfo<T: Limits> {
    pub convener: Convener,
    pub name: BoundedString<T::MaxTrustRegistryNameSize>,
    pub gov_framework: BoundedBytes<T::MaxTrustRegistryGovFrameworkSize>,
}

pub type UnboundedSchemaIssuers = UnboundedIssuersWith<UnboundedVerificationPrices>;

impl<T: Limits> TryFrom<UnboundedSchemaIssuers> for SchemaIssuers<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedIssuersWith(issuers): UnboundedSchemaIssuers,
    ) -> Result<Self, Self::Error> {
        let issuers: BTreeMap<_, _> = issuers
            .into_iter()
            .map(|(issuer, prices)| Ok((issuer, prices.try_into()?)))
            .collect::<Result<_, Error<T>>>()?;

        issuers
            .try_into()
            .map(IssuersWith)
            .map_err(|_| Error::<T>::IssuersSizeExceeded)
    }
}

impl<T: Limits> TryFrom<UnboundedTrustRegistrySchemaVerifiers> for TrustRegistrySchemaVerifiers<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedTrustRegistrySchemaVerifiers(verifiers): UnboundedTrustRegistrySchemaVerifiers,
    ) -> Result<Self, Self::Error> {
        verifiers
            .try_into()
            .map(TrustRegistrySchemaVerifiers)
            .map_err(|_| Error::<T>::VerifiersSizeExceeded)
    }
}

impl<T: Limits> TryFrom<UnboundedVerificationPrices> for VerificationPrices<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedVerificationPrices(prices): UnboundedVerificationPrices,
    ) -> Result<Self, Self::Error> {
        let prices: BTreeMap<_, _> = prices
            .into_iter()
            .map(|(cur, value)| {
                cur.try_into()
                    .map_err(|_| Error::<T>::PriceCurrencySymbolSizeExceeded)
                    .map(|cur: BoundedString<T::MaxIssuerPriceCurrencySymbolSize>| (cur, value))
            })
            .collect::<Result<_, Error<T>>>()?;

        prices
            .try_into()
            .map(VerificationPrices)
            .map_err(|_| Error::<T>::VerificationPricesSizeExceeded)
    }
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
    SetOrModify<UnboundedSchemaIssuers, MultiTargetUpdate<Issuer, UnboundedIssuerUpdate>>;
pub type IssuersUpdate<T> =
    SetOrModify<SchemaIssuers<T>, MultiTargetUpdate<Issuer, IssuerUpdate<T>>>;

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

/// Unique identifier for the `Trust Registry`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistryId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

impl_wrapper!(TrustRegistryId([u8; 32]));

impl<T: Config> StorageRef<T> for TrustRegistryId {
    type Value = TrustRegistryInfo<T>;

    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<TrustRegistryInfo<T>>) -> Result<R, E>,
    {
        TrustRegistriesInfo::<T>::try_mutate_exists(self, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<TrustRegistryInfo<T>>) -> R,
    {
        f(TrustRegistriesInfo::<T>::get(self))
    }
}

/// Unique identifier for the `Trust Registry`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

impl_wrapper!(TrustRegistrySchemaId([u8; 32]));

pub trait IntoIterExt: IntoIterator + Sized {
    fn with_trust_registries_info<T>(self) -> WithTrustRegistriesInfo<Self::IntoIter, T>
    where
        Self::Item: Borrow<TrustRegistryId>,
        T: Config;
}

impl<I> IntoIterExt for I
where
    I: IntoIterator,
{
    fn with_trust_registries_info<T>(self) -> WithTrustRegistriesInfo<Self::IntoIter, T>
    where
        Self::Item: Borrow<TrustRegistryId>,
        T: Config,
    {
        WithTrustRegistriesInfo::new(self.into_iter())
    }
}

pub struct WithTrustRegistriesInfo<I, T>(I, PhantomData<T>);

impl<T, I> WithTrustRegistriesInfo<I, T> {
    fn new(iter: I) -> Self {
        Self(iter, PhantomData)
    }
}

impl<T: Config, I> Iterator for WithTrustRegistriesInfo<I, T>
where
    I: Iterator,
    I::Item: Borrow<TrustRegistryId>,
{
    type Item = (TrustRegistryId, TrustRegistryInfo<T>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let id = *self.0.next()?.borrow();

            if let Some(trust_registry_info) = TrustRegistriesInfo::<T>::get(id) {
                break Some((id, trust_registry_info));
            }
        }
    }
}

/// Specifies arguments to retrieve registry informations by.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum TrustRegistriesInfoBy {
    Issuer(Issuer),
    Verifier(Verifier),
    SchemaId(TrustRegistrySchemaId),
    IssuerOrVerifier(IssuerOrVerifier),
    IssuerAndVerifier(IssuerAndVerifier),
    IssuerAndSchemaId(Issuer, TrustRegistrySchemaId),
    VerifierAndSchemaId(Verifier, TrustRegistrySchemaId),
    IssuerOrVerifierAndSchemaId(IssuerOrVerifier, TrustRegistrySchemaId),
    IssuerAndVerifierAndSchemaId(IssuerAndVerifier, TrustRegistrySchemaId),
}

impl TrustRegistriesInfoBy {
    pub fn resolve<T: Config>(self) -> BTreeMap<TrustRegistryId, TrustRegistryInfo<T>> {
        use super::Pallet;

        match self {
            Self::Issuer(issuer) => {
                let IssuerTrustRegistries(registries) = Pallet::<T>::issuer_registries(issuer);

                registries.with_trust_registries_info().collect()
            }
            Self::Verifier(verifier) => {
                let VerifierTrustRegistries(registries) =
                    Pallet::<T>::verifier_registries(verifier);

                registries.with_trust_registries_info().collect()
            }
            Self::SchemaId(schema_id) => {
                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .with_trust_registries_info()
                    .collect()
            }
            Self::IssuerOrVerifier(issuer_or_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_or_verifier));
                let verifier_regs = Pallet::<T>::verifier_registries(Verifier(*issuer_or_verifier));

                issuer_regs
                    .union(&verifier_regs)
                    .with_trust_registries_info()
                    .collect()
            }
            Self::IssuerAndVerifier(issuer_and_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_and_verifier));
                let verifier_regs =
                    Pallet::<T>::verifier_registries(Verifier(*issuer_and_verifier));

                issuer_regs
                    .intersection(&verifier_regs)
                    .with_trust_registries_info()
                    .collect()
            }
            Self::IssuerAndSchemaId(issuer, schema_id) => {
                let issuer_registries = Pallet::<T>::issuer_registries(issuer);

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_registries.contains(reg_id))
                    .with_trust_registries_info()
                    .collect()
            }
            Self::VerifierAndSchemaId(verifier, schema_id) => {
                let verifier_registries = Pallet::<T>::verifier_registries(verifier);

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| verifier_registries.contains(reg_id))
                    .with_trust_registries_info()
                    .collect()
            }
            Self::IssuerOrVerifierAndSchemaId(issuer_or_verifier, schema_id) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_or_verifier));
                let verifier_regs = Pallet::<T>::verifier_registries(Verifier(*issuer_or_verifier));

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_regs.contains(reg_id) || verifier_regs.contains(reg_id))
                    .with_trust_registries_info()
                    .collect()
            }
            Self::IssuerAndVerifierAndSchemaId(issuer_and_verifier, schema_id) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_and_verifier));
                let verifier_regs =
                    Pallet::<T>::verifier_registries(Verifier(*issuer_and_verifier));

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_regs.contains(reg_id) && verifier_regs.contains(reg_id))
                    .with_trust_registries_info()
                    .collect()
            }
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
