use super::{
    Config, ConvenerTrustRegistries, Error, TrustRegistriesInfo, TrustRegistriesParticipants,
};
use crate::{
    common::{AuthorizeTarget, Limits, TypesAndLimits},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    hex_debug, impl_wrapper,
    util::{batch_update::*, Associated, BoundedBytes, KeyValue, OptionExt, StorageRef},
};
use alloc::{collections::BTreeMap, string::String};
use codec::{Decode, Encode, MaxEncodedLen};
use core::{fmt::Debug, num::NonZeroU32};
use frame_support::{traits::Get, weights::Weight, *};
use sp_runtime::DispatchResult;
use sp_std::{collections::btree_set::BTreeSet, prelude::*};
use utils::BoundedString;

#[cfg(feature = "serde")]
use crate::util::{btree_map, btree_set, serde_hex};
#[cfg(feature = "serde")]
use serde_with::serde_as;

/// Trust registry `Convener`'s `DID`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Convener(pub DidOrDidMethodKey);

impl_wrapper!(Convener(DidOrDidMethodKey));

impl<T: TypesAndLimits> Associated<T> for Convener {
    type Value = TrustRegistryIdSet<T>;
}

impl<T: Config> StorageRef<T> for Convener {
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

impl<T: TypesAndLimits> Associated<T> for TrustRegistryIdForParticipants {
    type Value = TrustRegistryStoredParticipants<T>;
}

impl<T: Config> StorageRef<T> for TrustRegistryIdForParticipants {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<TrustRegistryStoredParticipants<T>>) -> Result<R, E>,
    {
        TrustRegistriesParticipants::<T>::try_mutate_exists(self, |entry| f(entry.initialized()))
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<TrustRegistryStoredParticipants<T>>) -> R,
    {
        f(Some(TrustRegistriesParticipants::<T>::get(self)))
    }
}

crate::impl_authorize_target!(
    for Self: Convener fn (self, _, action, _) {
        ensure!(
            action.target() == *self,
            crate::did::Error::<T>::InvalidSigner
        );
    }
);

crate::impl_authorize_target!(
    for TrustRegistryId: Convener with Value=TrustRegistryInfo<T> => fn (self, _, _, reg_info_opt) {
        if let Some(reg_info) = reg_info_opt {
            self.ensure_controls(reg_info)?;
        }
    }
);

/// Maybe an `Issuer` or a `Verifier` but definitely not a `Convener`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IssuerOrVerifier(pub DidOrDidMethodKey);

impl_wrapper!(IssuerOrVerifier(DidOrDidMethodKey));

pub struct IssuersOrVerifiers(pub BTreeSet<IssuerOrVerifier>);

impl_wrapper!(IssuersOrVerifiers(BTreeSet<IssuerOrVerifier>));

impl IssuersOrVerifiers {
    pub fn issuers(&self) -> BTreeSet<Issuer> {
        self.0.iter().copied().map(|did| Issuer(*did)).collect()
    }

    pub fn verifiers(&self) -> BTreeSet<Verifier> {
        self.0.iter().copied().map(|did| Verifier(*did)).collect()
    }
}

impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidKey> for IssuerOrVerifier {}
impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidMethodKey> for IssuerOrVerifier {}

#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct DelegatedSchemaCounter(pub NonZeroU32);

impl_wrapper!(DelegatedSchemaCounter(NonZeroU32));

/// Both an `Issuer` and a `Verifier`.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IssuerAndVerifier(pub DidOrDidMethodKey);

impl_wrapper!(IssuerAndVerifier(DidOrDidMethodKey));

impl Convener {
    pub fn controls<T: Limits>(
        &self,
        TrustRegistryInfo { convener, .. }: &TrustRegistryInfo<T>,
    ) -> bool {
        convener == self
    }

    pub fn ensure_controls<T: Config>(&self, info: &TrustRegistryInfo<T>) -> Result<(), Error<T>> {
        ensure!(self.controls(info), Error::<T>::NotTheConvener);

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

impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidKey> for Issuer {}
impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidMethodKey> for Issuer {}

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
    /// Ensures that underlying update is valid.
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
        if Convener(**self).controls(trust_registry_info) {
            update.ensure_valid(&Convener(**self), entity)
        } else {
            update.ensure_valid(&IssuerOrVerifier(**self), entity)
        }
    }
}

impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidKey> for ConvenerOrIssuerOrVerifier {}
impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryId, DidMethodKey>
    for ConvenerOrIssuerOrVerifier
{
}
impl<T: TypesAndLimits>
    AuthorizeTarget<T, (TrustRegistryIdForParticipants, IssuerOrVerifier), DidKey>
    for ConvenerOrIssuerOrVerifier
{
}
impl<T: TypesAndLimits>
    AuthorizeTarget<T, (TrustRegistryIdForParticipants, IssuerOrVerifier), DidMethodKey>
    for ConvenerOrIssuerOrVerifier
{
}
impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryIdForParticipants, DidKey>
    for ConvenerOrIssuerOrVerifier
{
}
impl<T: TypesAndLimits> AuthorizeTarget<T, TrustRegistryIdForParticipants, DidMethodKey>
    for ConvenerOrIssuerOrVerifier
{
}

crate::impl_authorize_target!(
    for (TrustRegistryId, Issuer): Issuer fn (self, _, action, _) {
        ensure!(
            action.target().1 == *self,
            crate::did::Error::<T>::InvalidSigner
        );
    }
);

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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AggregatedIssuerInfo<T: Limits> {
    pub verification_prices: VerificationPrices<T>,
    pub suspended: bool,
    pub delegated: DelegatedIssuers<T>,
}

/// A map from `Issuer` to some value.
#[cfg_attr(feature = "serde", serde_as)]
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    DefaultNoBound,
    scale_info_derive::TypeInfo,
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct IssuersWith<T: Limits, Entry: Eq + Clone + Debug>(
    pub BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchema>,
);

#[cfg(feature = "serde")]
impl<T: Limits, Entry: Eq + Clone + Debug + Serialize> serde::Serialize for IssuersWith<T, Entry> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let items: Vec<_> = self
            .0
            .iter()
            .map(|(issuer, entry)| (issuer.clone(), entry.clone()))
            .collect();

        items.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Limits, Entry: Eq + Clone + Debug + Deserialize<'de>> serde::Deserialize<'de>
    for IssuersWith<T, Entry>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let items = Vec::deserialize(deserializer)?;
        let len = items.len();

        let map = BTreeMap::from_iter(items);
        if len != map.len() {
            Err(D::Error::custom("Duplicate key"))
        } else {
            map.try_into()
                .map_err(|_| D::Error::custom("Issuers size exceeded"))
                .map(Self)
        }
    }
}

impl_wrapper!(IssuersWith<T, Entry> where T: Limits, Entry: Eq, Entry: Clone, Entry: Debug => (BoundedBTreeMap<Issuer, Entry, T::MaxIssuersPerSchema>));

/// Schema `Issuer`s (`Issuer` => verification prices).
pub type TrustRegistrySchemaIssuers<T> = IssuersWith<T, VerificationPrices<T>>;

/// An unbounded map from `Issuer` to some value.
#[cfg_attr(feature = "serde", serde_as)]
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "Entry: Serialize",
        deserialize = "Entry: Deserialize<'de>"
    ))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedIssuersWith<Entry: Eq + Clone + Debug>(
    #[cfg(feature = "serde")]
    #[serde_as(as = "serde_with::Seq<(_, _)>")]
    pub BTreeMap<Issuer, Entry>,
    #[cfg(not(feature = "serde"))] pub BTreeMap<Issuer, Entry>,
);

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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

pub type UnboundedDelegatedIssuersUpdate =
    SetOrModify<UnboundedDelegatedIssuers, MultiTargetUpdate<Issuer, AddOrRemoveOrModify<()>>>;

pub type UnboundedTrustRegistryParticipantsUpdate =
    MultiTargetUpdate<IssuerOrVerifier, AddOrRemoveOrModify<()>>;

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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

/// `TrustRegistry` schema metadata.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaMetadata<T: Limits> {
    pub issuers: TrustRegistrySchemaIssuers<T>,
    pub verifiers: TrustRegistrySchemaVerifiers<T>,
}

/// Unbounded `TrustRegistry` schema metadata.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistrySchemaMetadata {
    pub issuers: UnboundedRegistrySchemaIssuers,
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

pub type RegistryIdUpdate<Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<TrustRegistryId, Update>;
pub type SchemaIdUpdate<Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<TrustRegistrySchemaId, Update>;
pub type MultiSchemaIdUpdate<Key, Update = AddOrRemoveOrModify<()>> =
    MultiTargetUpdate<Key, SchemaIdUpdate<Update>>;

impl<T: Limits> TrustRegistrySchemaMetadata<T> {
    pub fn record_inner_issuers_and_verifiers_diff<F, U>(
        &self,
        issuers: &mut MultiSchemaIdUpdate<Issuer, U>,
        verifiers: &mut MultiSchemaIdUpdate<Verifier, U>,
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

pub type AggregatedTrustRegistrySchemaIssuers<T> = Vec<(Issuer, AggregatedIssuerInfo<T>)>;

/// `TrustRegistry` schema metadata.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

        AggregatedTrustRegistrySchemaMetadata { issuers, verifiers }
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

impl<T: Limits> IntoIterator for VerifierSchemas<T> {
    type IntoIter = alloc::collections::btree_set::IntoIter<TrustRegistrySchemaId>;
    type Item = TrustRegistrySchemaId;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

impl<T: Limits> IntoIterator for VerifierTrustRegistries<T> {
    type IntoIter = alloc::collections::btree_set::IntoIter<TrustRegistryId>;
    type Item = TrustRegistryId;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Set of schemas that belong to the `TrustRegistry`
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

/// Set of `TrustRegistry` participants.
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryStoredParticipants<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
    pub  BoundedBTreeSet<IssuerOrVerifier, T::MaxParticipantsPerRegistry>,
);

impl_wrapper!(TrustRegistryStoredParticipants<T> where T: Limits => (BoundedBTreeSet<IssuerOrVerifier, T::MaxParticipantsPerRegistry>));

/// Information about the `TrustRegistry` participant.
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryStoredParticipantInformation<T: Limits> {
    pub org_name: BoundedString<T::MaxRegistryParticipantOrgNameSize>,
    pub logo: BoundedString<T::MaxRegistryParticipantLogoSize>,
    pub description: BoundedString<T::MaxRegistryParticipantDescriptionSize>,
}

/// Information about the `TrustRegistry` participant.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UnboundedTrustRegistryParticipantInformation {
    pub org_name: String,
    pub logo: String,
    pub description: String,
}

impl<T: Limits> TryFrom<UnboundedTrustRegistryParticipantInformation>
    for TrustRegistryStoredParticipantInformation<T>
{
    type Error = Error<T>;

    fn try_from(
        UnboundedTrustRegistryParticipantInformation {
            org_name,
            logo,
            description,
        }: UnboundedTrustRegistryParticipantInformation,
    ) -> Result<Self, Error<T>> {
        let this = Self {
            org_name: org_name
                .try_into()
                .map_err(|_| Error::<T>::ParticipantOrgNameSizeExceededLimit)?,
            logo: logo
                .try_into()
                .map_err(|_| Error::<T>::ParticipantLogoSizeExceededLimit)?,
            description: description
                .try_into()
                .map_err(|_| Error::<T>::ParticipantDescriptionSizeExceededLimit)?,
        };

        Ok(this)
    }
}

/// Set of schemas corresponding to an `Issuer`.
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

impl<T: Limits> IntoIterator for IssuerSchemas<T> {
    type IntoIter = alloc::collections::btree_set::IntoIter<TrustRegistrySchemaId>;
    type Item = TrustRegistrySchemaId;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Set of schemas corresponding to a delegated `Issuer`
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DelegatedIssuerSchemas<T: Limits>(
    #[cfg_attr(feature = "serde", serde(with = "btree_map"))]
    pub  BoundedBTreeMap<TrustRegistrySchemaId, DelegatedSchemaCounter, T::MaxSchemasPerIssuer>,
);

impl_wrapper!(DelegatedIssuerSchemas<T> where T: Limits => (BoundedBTreeMap<TrustRegistrySchemaId, DelegatedSchemaCounter, T::MaxSchemasPerIssuer>));

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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

impl<T: Limits> IntoIterator for IssuerTrustRegistries<T> {
    type IntoIter = alloc::collections::btree_set::IntoIter<TrustRegistryId>;
    type Item = TrustRegistryId;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct TrustRegistryInfo<T: Limits> {
    pub convener: Convener,
    pub name: BoundedString<T::MaxTrustRegistryNameSize>,
    pub gov_framework: BoundedBytes<T::MaxTrustRegistryGovFrameworkSize>,
}

pub type UnboundedRegistrySchemaIssuers = UnboundedIssuersWith<UnboundedVerificationPrices>;

impl<T: Limits> TryFrom<UnboundedRegistrySchemaIssuers> for TrustRegistrySchemaIssuers<T> {
    type Error = Error<T>;

    fn try_from(
        UnboundedIssuersWith(issuers): UnboundedRegistrySchemaIssuers,
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
            .map(|(sym, value)| {
                sym.try_into()
                    .map_err(|_| Error::<T>::PriceCurrencySymbolSizeExceeded)
                    .map(
                        |bounded_sym: BoundedString<T::MaxIssuerPriceCurrencySymbolSize>| {
                            (bounded_sym, value)
                        },
                    )
            })
            .collect::<Result<_, Error<T>>>()?;

        prices
            .try_into()
            .map(VerificationPrices)
            .map_err(|_| Error::<T>::VerificationPricesSizeExceeded)
    }
}

/// Unique identifier for the `TrustRegistry`.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistryId(#[cfg_attr(feature = "serde", serde(with = "serde_hex"))] pub [u8; 32]);

impl_wrapper!(TrustRegistryId([u8; 32]));
hex_debug!(TrustRegistryId);

#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistryIdForParticipants(pub TrustRegistryId);

impl_wrapper!(TrustRegistryIdForParticipants(TrustRegistryId));
hex_debug!(TrustRegistryIdForParticipants);

impl<T: Limits> Associated<T> for TrustRegistryId {
    type Value = TrustRegistryInfo<T>;
}

impl<T: Config> StorageRef<T> for TrustRegistryId {
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

impl<T: TypesAndLimits> Associated<T> for (TrustRegistryId, Issuer) {
    type Value = TrustRegistryIssuerConfiguration<T>;
}

impl<T: Config> StorageRef<T> for (TrustRegistryId, Issuer) {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<TrustRegistryIssuerConfiguration<T>>) -> Result<R, E>,
    {
        super::TrustRegistryIssuerConfigurations::<T>::try_mutate_exists(self.0, self.1, |opt| {
            f(opt.initialized())
        })
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<TrustRegistryIssuerConfiguration<T>>) -> R,
    {
        f(Some(super::TrustRegistryIssuerConfigurations::<T>::get(
            self.0, self.1,
        )))
    }
}

impl<T: Limits> Associated<T> for (TrustRegistryIdForParticipants, IssuerOrVerifier) {
    type Value = TrustRegistryStoredParticipantInformation<T>;
}

impl<T: Config> StorageRef<T> for (TrustRegistryIdForParticipants, IssuerOrVerifier) {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<TrustRegistryStoredParticipantInformation<T>>) -> Result<R, E>,
    {
        super::TrustRegistryParticipantsInformation::<T>::try_mutate_exists(self.0, self.1, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<TrustRegistryStoredParticipantInformation<T>>) -> R,
    {
        f(super::TrustRegistryParticipantsInformation::<T>::get(
            self.0, self.1,
        ))
    }
}

/// Unique identifier for the `TrustRegistry`.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct TrustRegistrySchemaId(
    #[cfg_attr(feature = "serde", serde(with = "serde_hex"))] pub [u8; 32],
);

impl_wrapper!(TrustRegistrySchemaId([u8; 32]));
hex_debug!(TrustRegistrySchemaId);

/// Number of times storage entities were accessed.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StorageAccesses {
    pub issuer_schemas: u32,
    pub issuer_registries: u32,
    pub issuer_configuration: u32,
    pub delegated_issuer_schemas: u32,
    pub verifier_schemas: u32,
    pub verifier_registries: u32,
    pub schemas: u32,
    pub registry_schemas: bool,
}

impl StorageAccesses {
    pub fn issuers(&self) -> u32 {
        self.issuer_schemas
    }

    pub fn verifiers(&self) -> u32 {
        self.verifier_schemas
    }

    pub fn schemas(&self) -> u32 {
        self.schemas
    }

    pub fn total_count(&self) -> u64 {
        (self.issuer_schemas as u64)
            .saturating_add(self.issuer_registries as u64)
            .saturating_add(self.issuer_configuration as u64)
            .saturating_add(self.delegated_issuer_schemas as u64)
            .saturating_add(self.verifier_schemas as u64)
            .saturating_add(self.verifier_registries as u64)
            .saturating_add(self.schemas as u64)
            .saturating_add(self.registry_schemas as u64)
    }

    pub fn reads<T: Config>(&self) -> Weight {
        T::DbWeight::get().reads(self.total_count())
    }

    pub fn reads_writes<T: Config>(&self) -> Weight {
        let count = self.total_count();

        T::DbWeight::get().reads_writes(count, count)
    }
}

/// An entity that has references to schemas and registries.
pub trait HasSchemasAndRegistries<T> {
    /// Associated `Schemas`.
    type Schemas;
    /// Associated `Registries`.
    type Registries;

    fn schemas(&self, registry_id: TrustRegistryId) -> Self::Schemas;

    fn registries(&self) -> Self::Registries;

    fn modify_schemas<F, R>(&self, registry_id: TrustRegistryId, f: F) -> R
    where
        F: FnOnce(&mut Self::Schemas) -> R;

    fn modify_registries<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Registries) -> R;
}

impl<T: Config> HasSchemasAndRegistries<T> for Issuer {
    type Schemas = IssuerSchemas<T>;
    type Registries = IssuerTrustRegistries<T>;

    fn schemas(&self, registry_id: TrustRegistryId) -> Self::Schemas {
        super::TrustRegistryIssuerSchemas::<T>::get(registry_id, self)
    }

    fn registries(&self) -> Self::Registries {
        super::IssuersTrustRegistries::<T>::get(self)
    }

    fn modify_schemas<F, R>(&self, registry_id: TrustRegistryId, f: F) -> R
    where
        F: FnOnce(&mut Self::Schemas) -> R,
    {
        super::TrustRegistryIssuerSchemas::<T>::mutate(registry_id, self, f)
    }

    fn modify_registries<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Registries) -> R,
    {
        super::IssuersTrustRegistries::<T>::mutate(self, f)
    }
}

impl<T: Config> HasSchemasAndRegistries<T> for Verifier {
    type Schemas = VerifierSchemas<T>;
    type Registries = VerifierTrustRegistries<T>;

    fn schemas(&self, registry_id: TrustRegistryId) -> Self::Schemas {
        super::TrustRegistryVerifierSchemas::<T>::get(registry_id, self)
    }

    fn registries(&self) -> Self::Registries {
        super::VerifiersTrustRegistries::<T>::get(self)
    }

    fn modify_schemas<F, R>(&self, registry_id: TrustRegistryId, f: F) -> R
    where
        F: FnOnce(&mut Self::Schemas) -> R,
    {
        super::TrustRegistryVerifierSchemas::<T>::mutate(registry_id, self, f)
    }

    fn modify_registries<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Registries) -> R,
    {
        super::VerifiersTrustRegistries::<T>::mutate(self, f)
    }
}
