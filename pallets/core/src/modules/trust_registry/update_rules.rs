use super::*;
use crate::{common::Limits, util::batch_update::*};

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

impl CanUpdate<VerificationPrice> for Convener {
    fn can_add(&self, _entity: &VerificationPrice) -> bool {
        true
    }

    fn can_remove(&self, _entity: &VerificationPrice) -> bool {
        true
    }

    fn can_replace(&self, _new: &VerificationPrice, _entity: &VerificationPrice) -> bool {
        true
    }
}

impl CanUpdate<VerificationPrice> for IssuerOrVerifier {
    fn can_add(&self, _entity: &VerificationPrice) -> bool {
        true
    }

    fn can_remove(&self, _entity: &VerificationPrice) -> bool {
        true
    }

    fn can_replace(&self, _new: &VerificationPrice, _entity: &VerificationPrice) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<TrustRegistrySchemaIssuers<T>> for IssuerOrVerifier {}
impl<T: Limits> CanUpdate<TrustRegistrySchemaVerifiers<T>> for IssuerOrVerifier {}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaIssuers<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaIssuers<T>>>(
        &self,
        entity: &TrustRegistrySchemaIssuers<T>,
        update: &U,
    ) -> bool {
        Issuer(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaVerifiers<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaVerifiers<T>>>(
        &self,
        entity: &TrustRegistrySchemaVerifiers<T>,
        update: &U,
    ) -> bool {
        Verifier(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<VerificationPrices<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<VerificationPrices<T>>>(
        &self,
        _entity: &VerificationPrices<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaVerifiers<T>> for Verifier {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaVerifiers<T>>>(
        &self,
        entity: &TrustRegistrySchemaVerifiers<T>,
        update: &U,
    ) -> bool {
        entity.0.contains(self) && update.targets(entity).all(|target| target == self)
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaIssuers<T>> for Issuer {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaIssuers<T>>>(
        &self,
        entity: &TrustRegistrySchemaIssuers<T>,
        update: &U,
    ) -> bool {
        entity.0.contains_key(self) && update.targets(entity).all(|target| target == self)
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerSchemas<T>> for Issuer {
    fn can_update_keyed<U: KeyedUpdate<IssuerSchemas<T>>>(
        &self,
        _entity: &IssuerSchemas<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerSchemas<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<IssuerSchemas<T>>>(
        &self,
        _entity: &IssuerSchemas<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerSchemas<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<IssuerSchemas<T>>>(
        &self,
        entity: &IssuerSchemas<T>,
        update: &U,
    ) -> bool {
        Issuer(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierSchemas<T>> for Verifier {
    fn can_update_keyed<U: KeyedUpdate<VerifierSchemas<T>>>(
        &self,
        _entity: &VerifierSchemas<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierSchemas<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<VerifierSchemas<T>>>(
        &self,
        _entity: &VerifierSchemas<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierSchemas<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<VerifierSchemas<T>>>(
        &self,
        entity: &VerifierSchemas<T>,
        update: &U,
    ) -> bool {
        Verifier(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<DelegatedIssuers<T>> for Issuer {
    fn can_update_keyed<U: KeyedUpdate<DelegatedIssuers<T>>>(
        &self,
        _entity: &DelegatedIssuers<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<DelegatedIssuers<T>> for Issuer {
    fn can_replace(&self, _new: &DelegatedIssuers<T>, _existing: &DelegatedIssuers<T>) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<VerificationPrices<T>> for Convener {
    fn can_add(&self, _entity: &VerificationPrices<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &VerificationPrices<T>) -> bool {
        true
    }

    fn can_replace(&self, _new: &VerificationPrices<T>, _existing: &VerificationPrices<T>) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<VerificationPrices<T>> for IssuerOrVerifier {
    fn can_remove(&self, _entity: &VerificationPrices<T>) -> bool {
        true
    }

    fn can_replace(&self, _new: &VerificationPrices<T>, _existing: &VerificationPrices<T>) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaIssuers<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaIssuers<T>>>(
        &self,
        _entity: &TrustRegistrySchemaIssuers<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistrySchemaVerifiers<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistrySchemaVerifiers<T>>>(
        &self,
        _entity: &TrustRegistrySchemaVerifiers<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierTrustRegistries<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<VerifierTrustRegistries<T>>>(
        &self,
        _entity: &VerifierTrustRegistries<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerTrustRegistries<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<IssuerTrustRegistries<T>>>(
        &self,
        _entity: &IssuerTrustRegistries<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerTrustRegistries<T>> for Issuer {
    fn can_update_keyed<U: KeyedUpdate<IssuerTrustRegistries<T>>>(
        &self,
        _entity: &IssuerTrustRegistries<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierTrustRegistries<T>> for Verifier {
    fn can_update_keyed<U: KeyedUpdate<VerifierTrustRegistries<T>>>(
        &self,
        _entity: &VerifierTrustRegistries<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<IssuerTrustRegistries<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<IssuerTrustRegistries<T>>>(
        &self,
        entity: &IssuerTrustRegistries<T>,
        update: &U,
    ) -> bool {
        Issuer(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<VerifierTrustRegistries<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<VerifierTrustRegistries<T>>>(
        &self,
        entity: &VerifierTrustRegistries<T>,
        update: &U,
    ) -> bool {
        Verifier(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistryStoredSchemas<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistryStoredSchemas<T>>>(
        &self,
        _entity: &TrustRegistryStoredSchemas<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<TrustRegistryStoredSchemas<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<TrustRegistryStoredSchemas<T>>>(
        &self,
        _entity: &TrustRegistryStoredSchemas<T>,
        _update: &U,
    ) -> bool {
        false
    }
}

impl<T: Limits> CanUpdate<TrustRegistrySchemaIssuers<T>> for Convener {
    fn can_add(&self, _entity: &TrustRegistrySchemaIssuers<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &TrustRegistrySchemaIssuers<T>) -> bool {
        true
    }

    fn can_replace(
        &self,
        _new: &TrustRegistrySchemaIssuers<T>,
        _existing: &TrustRegistrySchemaIssuers<T>,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<VerificationPrices<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<VerificationPrices<T>>>(
        &self,
        _entity: &VerificationPrices<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<TrustRegistrySchemaVerifiers<T>> for Convener {
    fn can_add(&self, _entity: &TrustRegistrySchemaVerifiers<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &TrustRegistrySchemaVerifiers<T>) -> bool {
        true
    }

    fn can_replace(
        &self,
        _new: &TrustRegistrySchemaVerifiers<T>,
        _existing: &TrustRegistrySchemaVerifiers<T>,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<TrustRegistrySchemaMetadata<T>> for Convener {
    fn can_add(&self, _entity: &TrustRegistrySchemaMetadata<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &TrustRegistrySchemaMetadata<T>) -> bool {
        true
    }

    fn can_replace(
        &self,
        _new: &TrustRegistrySchemaMetadata<T>,
        _entity: &TrustRegistrySchemaMetadata<T>,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<TrustRegistrySchemaMetadata<T>> for IssuerOrVerifier {}
