use super::{Config, Error};
#[cfg(feature = "serde")]
use crate::util::{btree_map, btree_set, hex};
use crate::{
    common::Limits,
    did::{AuthorizeTarget, DidKey, DidMethodKey, DidOrDidMethodKey},
    impl_wrapper,
    util::{batch_update::*, BoundedKeyValue},
};
use alloc::collections::BTreeMap;
use codec::{Decode, Encode, MaxEncodedLen};
use core::fmt::Debug;
use frame_support::*;
use sp_std::prelude::*;
use utils::BoundedString;

use super::TrustRegistriesInfo;

/// Trust registry `Convener`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Convener(pub DidOrDidMethodKey);

impl_wrapper!(Convener(DidOrDidMethodKey));

impl AuthorizeTarget<(), DidKey> for Convener {}
impl AuthorizeTarget<TrustRegistryId, DidKey> for Convener {}
impl AuthorizeTarget<(), DidMethodKey> for Convener {}
impl AuthorizeTarget<TrustRegistryId, DidMethodKey> for Convener {}

/// Maybe an `Issuer` or `Verifier` but definitely not a `Convener`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct MaybeIssuerOrVerifier(pub DidOrDidMethodKey);

impl_wrapper!(MaybeIssuerOrVerifier(DidOrDidMethodKey));

impl Convener {
    pub fn is_convener_for<T: Config>(&self, registry_id: TrustRegistryId) -> bool {
        TrustRegistriesInfo::<T>::get(registry_id)
            .map_or(false, |TrustRegistryInfo { convener, .. }| {
                &convener == self
            })
    }

    pub fn ensure_controls<T: Config>(&self, registry_id: TrustRegistryId) -> Result<(), Error<T>> {
        ensure!(
            self.is_convener_for::<T>(registry_id),
            Error::<T>::NotAConvener
        );

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

/// Trust registry `Convener`/`Issuer`/`Verifier`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Price(#[codec(compact)] pub u128);

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
        Price,
        T::MaxIssuerPricesSize,
    >,
);

crate::impl_wrapper!(VerificationPrices<T> where T: Limits => (BoundedBTreeMap<BoundedString<T::MaxIssuerPriceCurrencySymbolSize>, Price, T::MaxIssuerPricesSize>));

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
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
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
    pub  BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchemaSize>,
);

crate::impl_wrapper!(IssuersWith<T, Entry> where T: Limits, Entry: Eq, Entry: Clone, Entry: Debug => (BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchemaSize>));

/// Schema `Issuer`s (`Issuer` => verification prices).
pub type SchemaIssuers<T> = IssuersWith<T, VerificationPrices<T>>;

pub type AggregatedSchemaIssuers<T> = IssuersWith<T, AggregatedIssuerInfo<T>>;

/// Schema `Verifier`s.
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
pub struct SchemaVerifiers<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchemaSize>,
);

crate::impl_wrapper!(SchemaVerifiers<T> where T: Limits => (BoundedBTreeSet<Verifier, T::MaxVerifiersPerSchemaSize>));

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
    pub  BoundedBTreeSet<Issuer, T::MaxDelegatedIssuersSize>,
);

crate::impl_wrapper!(DelegatedIssuers<T> where T: Limits => (BoundedBTreeSet<Issuer, T::MaxDelegatedIssuersSize>));

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
pub struct TrustRegistryIssuerConfig<T: Limits> {
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
                        let TrustRegistryIssuerConfig {
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

/// `Trust Registry` schema metadata.
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

crate::impl_wrapper!(VerifierSchemas<T> where T: Limits => (BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerVerifier>));

/// `Trust Registry` schema metadata.
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

crate::impl_wrapper!(IssuerSchemas<T> where T: Limits => (BoundedBTreeSet<TrustRegistrySchemaId, T::MaxSchemasPerIssuer>));

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

crate::impl_wrapper!(TrustRegistryIdSet<T> where T: Limits => (BoundedBTreeSet<TrustRegistryId, T::MaxConvenerRegistries>));

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
}

pub type VerifiersUpdate<T> =
    SetOrModify<SchemaVerifiers<T>, MultiTargetUpdate<Verifier, AddOrRemoveOrModify<()>>>;

pub type IssuersUpdate<T> = SetOrModify<
    SchemaIssuers<T>,
    MultiTargetUpdate<
        Issuer,
        SetOrModify<
            VerificationPrices<T>,
            AddOrRemoveOrModify<
                VerificationPrices<T>,
                OnlyExistent<
                    MultiTargetUpdate<
                        BoundedString<<T as Limits>::MaxIssuerPriceCurrencySymbolSize>,
                        SetOrModify<Price, AddOrRemoveOrModify<Price>>,
                    >,
                >,
            >,
        >,
    >,
>;

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

/// Unique identifier for the `Trust Registry`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistryId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

crate::impl_wrapper!(TrustRegistryId([u8; 32]));

/// Unique identifier for the `Trust Registry`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

crate::impl_wrapper!(TrustRegistrySchemaId([u8; 32]));
