use super::{Config, ConvenerTrustRegistries, Error, TrustRegistriesInfo};
#[cfg(feature = "serde")]
use crate::util::{btree_map, btree_set, hex};
use crate::{
    common::{AuthorizeTarget, Limits},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    impl_wrapper,
    util::{batch_update::*, BoundedBytes, BoundedKeyValue, OptionExt, StorageRef},
};
use alloc::collections::BTreeMap;
use codec::{Decode, Encode, MaxEncodedLen};
use core::fmt::Debug;
use frame_support::*;
use scale_info::prelude::string::String;
use sp_runtime::DispatchError;
use sp_std::{collections::btree_set::BTreeSet, prelude::*};
use utils::BoundedString;

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

/// Maybe an `Issuer` or `Verifier` but definitely not a `Convener`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IssuerOrVerifier(pub DidOrDidMethodKey);

impl_wrapper!(IssuerOrVerifier(DidOrDidMethodKey));

impl Convener {
    pub fn ensure_controls<T: Config>(
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
        T::MaxPriceCurrencies,
    >,
);

impl_wrapper!(VerificationPrices<T> where T: Limits => (BoundedBTreeMap<BoundedString<T::MaxIssuerPriceCurrencySymbolSize>, VerificationPrice, T::MaxPriceCurrencies>));

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
pub struct SchemaVerifiers<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchema>,
);

impl_wrapper!(SchemaVerifiers<T> where T: Limits => (BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchema>));

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

impl<T: Limits> DelegatedUpdate<T> {
    pub fn len(&self) -> u32 {
        match self {
            SetOrModify::Set(delegated) => delegated.len(),
            SetOrModify::Modify(update) => update.len() as u32,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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
    pub verifiers: SchemaVerifiers<T>,
}

/// Unbounded `Trust Registry` schema metadata.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistrySchemaMetadata {
    pub issuers: UnboundedSchemaIssuers,
    pub verifiers: UnboundedSchemaVerifiers,
}

impl<T: Limits> From<TrustRegistrySchemaMetadata<T>> for UnboundedTrustRegistrySchemaMetadata {
    fn from(
        TrustRegistrySchemaMetadata { issuers, verifiers }: TrustRegistrySchemaMetadata<T>,
    ) -> Self {
        let issuers = issuers
            .0
            .into_iter()
            .map(|(issuer, prices)| {
                (
                    issuer,
                    prices
                        .0
                        .into_iter()
                        .map(|(cur, price)| (cur.into_inner(), price))
                        .collect(),
                )
            })
            .collect();

        Self {
            issuers,
            verifiers: verifiers.0.into(),
        }
    }
}

impl<T: Limits> TryFrom<UnboundedTrustRegistrySchemaMetadata> for TrustRegistrySchemaMetadata<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedTrustRegistrySchemaMetadata { issuers, verifiers }: UnboundedTrustRegistrySchemaMetadata,
    ) -> Result<Self, Self::Error> {
        let issuers: BTreeMap<Issuer, VerificationPrices<T>> = issuers
            .into_iter()
            .map(|(issuer, prices)| Ok((issuer, prices.try_into()?)))
            .collect::<Result<_, Error<T>>>()?;

        Ok(Self {
            issuers: IssuersWith(
                issuers
                    .try_into()
                    .map_err(|_| Error::<T>::IssuersSizeExceeded)?,
            ),
            verifiers: SchemaVerifiers(
                verifiers
                    .try_into()
                    .map_err(|_| Error::<T>::VerifiersSizeExceeded)?,
            ),
        })
    }
}

pub type MultiSchemaUpdate<Key, Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<Key, MultiTargetUpdate<TrustRegistrySchemaId, Update>>;

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

pub type AggregatedSchemaIssuers<T> = IssuersWith<T, AggregatedIssuerInfo<T>>;

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
    pub issuers: AggregatedSchemaIssuers<T>,
    pub verifiers: SchemaVerifiers<T>,
}

impl<T: Config> TrustRegistrySchemaMetadata<T> {
    pub fn aggregate(
        self,
        registry_id: TrustRegistryId,
    ) -> AggregatedTrustRegistrySchemaMetadata<T> {
        let Self { issuers, verifiers } = self;

        AggregatedTrustRegistrySchemaMetadata {
            issuers: IssuersWith(
                issuers
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
                    .collect::<BTreeMap<_, _>>()
                    .try_into()
                    .unwrap(),
            ),
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

pub type UnboundedSchemaIssuers = BTreeMap<Issuer, UnboundedVerificationPrices>;
pub type UnboundedSchemaVerifiers = BTreeSet<Verifier>;
pub type UnboundedVerificationPrices = BTreeMap<String, VerificationPrice>;

impl<T: Limits> TryFrom<UnboundedSchemaIssuers> for SchemaIssuers<T> {
    type Error = Error<T>;

    fn try_from(issuers: UnboundedSchemaIssuers) -> Result<Self, Self::Error> {
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

impl<T: Limits> TryFrom<UnboundedSchemaVerifiers> for SchemaVerifiers<T> {
    type Error = Error<T>;

    fn try_from(verifiers: UnboundedSchemaVerifiers) -> Result<Self, Self::Error> {
        verifiers
            .try_into()
            .map(SchemaVerifiers)
            .map_err(|_| Error::<T>::VerifiersSizeExceeded)
    }
}

impl<T: Limits> TryFrom<UnboundedVerificationPrices> for VerificationPrices<T> {
    type Error = Error<T>;

    fn try_from(prices: UnboundedVerificationPrices) -> Result<Self, Self::Error> {
        let prices: BTreeMap<_, _> = prices
            .into_iter()
            .map(|(cur, value)| {
                cur.try_into()
                    .map_err(|_| Error::<T>::PriceCurrencySizeExceeded)
                    .map(|cur: BoundedString<T::MaxIssuerPriceCurrencySymbolSize>| (cur, value))
            })
            .collect::<Result<_, Error<T>>>()?;

        prices
            .try_into()
            .map(VerificationPrices)
            .map_err(|_| Error::<T>::VerificationPricesSizeExceeded)
    }
}

pub type UnboundedVerifiersUpdate =
    SetOrModify<UnboundedSchemaVerifiers, MultiTargetUpdate<Verifier, AddOrRemoveOrModify<()>>>;
pub type UnboundedVerificationPricesUpdate =
    OnlyExistent<MultiTargetUpdate<String, SetOrAddOrRemoveOrModify<VerificationPrice>>>;
pub type UnboundedIssuerUpdate =
    SetOrAddOrRemoveOrModify<UnboundedVerificationPrices, UnboundedVerificationPricesUpdate>;
pub type UnboundedIssuersUpdate =
    SetOrModify<UnboundedSchemaIssuers, MultiTargetUpdate<Issuer, UnboundedIssuerUpdate>>;

pub type VerifiersUpdate<T> =
    SetOrModify<SchemaVerifiers<T>, MultiTargetUpdate<Verifier, AddOrRemoveOrModify<()>>>;
pub type VerificationPricesUpdate<T> = OnlyExistent<
    MultiTargetUpdate<
        BoundedString<<T as Limits>::MaxIssuerPriceCurrencySymbolSize>,
        SetOrAddOrRemoveOrModify<VerificationPrice>,
    >,
>;
pub type IssuerUpdate<T> =
    SetOrAddOrRemoveOrModify<VerificationPrices<T>, VerificationPricesUpdate<T>>;
pub type IssuersUpdate<T> =
    SetOrModify<SchemaIssuers<T>, MultiTargetUpdate<Issuer, IssuerUpdate<T>>>;

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

impl<T: Limits> Convert<TrustRegistrySchemaMetadataUpdate<T>>
    for UnboundedTrustRegistrySchemaMetadataUpdate
{
    type Error = DispatchError;

    fn convert(self) -> Result<TrustRegistrySchemaMetadataUpdate<T>, Self::Error> {
        let UnboundedTrustRegistrySchemaMetadataUpdate { issuers, verifiers } = self;

        Ok(TrustRegistrySchemaMetadataUpdate {
            issuers: issuers
                .map(|issuers| issuers.convert())
                .transpose()
                .map_err(Into::<DispatchError>::into)?,
            verifiers: verifiers
                .map(|verifiers| verifiers.convert())
                .transpose()
                .map_err(Into::<DispatchError>::into)?,
        })
    }
}

impl<T: Limits> TrustRegistrySchemaMetadataUpdate<T> {
    fn record_inner_issuers_and_verifiers_diff(
        &self,
        entity: &TrustRegistrySchemaMetadata<T>,
        schema_id: TrustRegistrySchemaId,
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
    pub(super) fn record_inner_issuers_and_verifiers_diff(
        &self,
        entity: &Option<TrustRegistrySchemaMetadata<T>>,
        schema_id: TrustRegistrySchemaId,
        issuers: &mut MultiSchemaUpdate<Issuer>,
        verifiers: &mut MultiSchemaUpdate<Verifier>,
    ) -> Result<(), DuplicateKey> {
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

                new.record_inner_issuers_and_verifiers_diff(
                    issuers,
                    verifiers,
                    MultiTargetUpdate::bind_modifier(
                        MultiTargetUpdate::insert_update_or_remove_duplicate,
                        schema_id,
                        AddOrRemoveOrModify::Add(()),
                    ),
                )
            }
            Self::Modify(OnlyExistent(update)) => update.record_inner_issuers_and_verifiers_diff(
                entity.as_ref().expect("An entity expected"),
                schema_id,
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
