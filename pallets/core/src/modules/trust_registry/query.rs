use super::*;
use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use types::*;
use codec::EncodeLike;
use core::iter::Cloned;

/// Specifies arguments to retrieve registry informations by.
#[derive(Encode, Decode, Clone, Debug, Copy, PartialEq, Eq, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum QueryTrustRegistriesBy {
    Issuer(Issuer),
    Verifier(Verifier),
    SchemaId(TrustRegistrySchemaId),
    IssuerOrVerifier(IssuerOrVerifier),
    IssuerAndVerifier(IssuerAndVerifier),
    SchemaIdWithIssuer(TrustRegistrySchemaId, Issuer),
    SchemaIdWithVerifier(TrustRegistrySchemaId, Verifier),
    SchemaIdWithIssuerOrVerifier(TrustRegistrySchemaId, IssuerOrVerifier),
    SchemaIdWithIssuerAndVerifier(TrustRegistrySchemaId, IssuerAndVerifier),
}

impl QueryTrustRegistriesBy {
    /// Resolves to a map containing `TrustRegistryId` -> `TrustRegistryInfo<T>` pairs.
    pub fn resolve_to_registries_info<T: Config>(
        self,
    ) -> BTreeMap<TrustRegistryId, TrustRegistryInfo<T>> {
        match self {
            Self::Issuer(issuer) => {
                let IssuerTrustRegistries(registries) = Pallet::<T>::issuer_registries(issuer);

                registries.with_registry_info().collect()
            }
            Self::Verifier(verifier) => {
                let VerifierTrustRegistries(registries) =
                    Pallet::<T>::verifier_registries(verifier);

                registries.with_registry_info().collect()
            }
            Self::SchemaId(schema_id) => {
                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .with_registry_info()
                    .collect()
            }
            Self::IssuerOrVerifier(issuer_or_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_or_verifier));
                let verifier_regs = Pallet::<T>::verifier_registries(Verifier(*issuer_or_verifier));

                issuer_regs
                    .union(&verifier_regs)
                    .copied()
                    .with_registry_info()
                    .collect()
            }
            Self::IssuerAndVerifier(issuer_and_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_and_verifier));
                let verifier_regs =
                    Pallet::<T>::verifier_registries(Verifier(*issuer_and_verifier));

                issuer_regs
                    .intersection(&verifier_regs)
                    .copied()
                    .with_registry_info()
                    .collect()
            }
            Self::SchemaIdWithIssuer(schema_id, issuer) => {
                let issuer_registries = Pallet::<T>::issuer_registries(issuer);

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_registries.contains(reg_id))
                    .with_registry_info()
                    .collect()
            }
            Self::SchemaIdWithVerifier(schema_id, verifier) => {
                let verifier_registries = Pallet::<T>::verifier_registries(verifier);

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| verifier_registries.contains(reg_id))
                    .with_registry_info()
                    .collect()
            }
            Self::SchemaIdWithIssuerOrVerifier(schema_id, issuer_or_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_or_verifier));
                let verifier_regs = Pallet::<T>::verifier_registries(Verifier(*issuer_or_verifier));

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_regs.contains(reg_id) || verifier_regs.contains(reg_id))
                    .with_registry_info()
                    .collect()
            }
            Self::SchemaIdWithIssuerAndVerifier(schema_id, issuer_and_verifier) => {
                let issuer_regs = Pallet::<T>::issuer_registries(Issuer(*issuer_and_verifier));
                let verifier_regs =
                    Pallet::<T>::verifier_registries(Verifier(*issuer_and_verifier));

                TrustRegistrySchemasMetadata::<T>::iter_key_prefix(schema_id)
                    .filter(|reg_id| issuer_regs.contains(reg_id) && verifier_regs.contains(reg_id))
                    .with_registry_info()
                    .collect()
            }
        }
    }
}

/// Extension that can be used by types implementing `IntoIterator`.
trait IntoIterExt: IntoIterator + Sized {
    /// Transforms value to an iterator emitting `TrustRegistryId`, then transforms result to an iterator producing
    /// `(TrustRegistryId, TrustRegistryInfo<T>)` pairs.
    fn with_registry_info<T>(self) -> WithEntity<Self::IntoIter, TrustRegistryInfo<T>>
    where
        Self::Item: Clone + EncodeLike<TrustRegistryId>,
        T: Config;
}

impl<I> IntoIterExt for I
where
    I: IntoIterator,
{
    fn with_registry_info<T>(self) -> WithEntity<Self::IntoIter, TrustRegistryInfo<T>>
    where
        Self::Item: Clone + EncodeLike<TrustRegistryId>,
        T: Config,
    {
        WithEntity::new(self.into_iter(), TrustRegistriesInfo::<T>::get as _)
    }
}

/// A wrapper for the iterator that converts an iterator of `TrustRegistryId`
/// to an iterator of `(TrustRegistryId, TrustRegistryInfo<T>)`.
pub struct WithEntity<I: Iterator, E>(I, fn(I::Item) -> Option<E>);

trait GetStorageValue<Key> {
    type Value;

    fn get(key: Key) -> Self::Value;
}

impl<I, E> WithEntity<I, E> where I: Iterator {
    fn new(iter: I, f: fn(I::Item) -> Option<E>) -> Self {
        Self(iter, f)
    }
}

impl<I, E> Iterator for WithEntity<I, E>
where
    I: Iterator,
    I::Item: Clone,
{
    type Item = (I::Item, E);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let id = self.0.next()?;

            if let Some(data) = self.1(id.clone()) {
                break Some((id, data));
            }
        }
    }
}
