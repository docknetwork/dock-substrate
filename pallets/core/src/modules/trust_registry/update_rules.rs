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
    A: CanUpdateAndCanUpdateKeyed<SchemaIssuers<T>>
        + CanUpdateAndCanUpdateKeyed<SchemaVerifiers<T>>
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

impl<T: Limits> CanUpdate<SchemaIssuers<T>> for IssuerOrVerifier {}
impl<T: Limits> CanUpdate<SchemaVerifiers<T>> for IssuerOrVerifier {}

impl<T: Limits> CanUpdateKeyed<SchemaIssuers<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<SchemaIssuers<T>>>(
        &self,
        entity: &SchemaIssuers<T>,
        update: &U,
    ) -> bool {
        Issuer(**self).can_update_keyed(entity, update)
    }
}

impl<T: Limits> CanUpdateKeyed<SchemaVerifiers<T>> for IssuerOrVerifier {
    fn can_update_keyed<U: KeyedUpdate<SchemaVerifiers<T>>>(
        &self,
        entity: &SchemaVerifiers<T>,
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

impl<T: Limits> CanUpdateKeyed<SchemaVerifiers<T>> for Verifier {
    fn can_update_keyed<U: KeyedUpdate<SchemaVerifiers<T>>>(
        &self,
        entity: &SchemaVerifiers<T>,
        update: &U,
    ) -> bool {
        entity.0.contains(self) && update.targets(entity).all(|target| target == self)
    }
}

impl<T: Limits> CanUpdateKeyed<SchemaIssuers<T>> for Issuer {
    fn can_update_keyed<U: KeyedUpdate<SchemaIssuers<T>>>(
        &self,
        entity: &SchemaIssuers<T>,
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

impl<T: Limits> CanUpdateKeyed<VerifierSchemas<T>> for Verifier {
    fn can_update_keyed<U: KeyedUpdate<VerifierSchemas<T>>>(
        &self,
        _entity: &VerifierSchemas<T>,
        _update: &U,
    ) -> bool {
        true
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
    fn can_replace(&self, _new: &DelegatedIssuers<T>, _entity: &DelegatedIssuers<T>) -> bool {
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

    fn can_replace(&self, _new: &VerificationPrices<T>, _entity: &VerificationPrices<T>) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<VerificationPrices<T>> for IssuerOrVerifier {
    fn can_add(&self, _entity: &VerificationPrices<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &VerificationPrices<T>) -> bool {
        true
    }

    fn can_replace(&self, _new: &VerificationPrices<T>, _entity: &VerificationPrices<T>) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<SchemaIssuers<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<SchemaIssuers<T>>>(
        &self,
        _entity: &SchemaIssuers<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdateKeyed<SchemaVerifiers<T>> for Convener {
    fn can_update_keyed<U: KeyedUpdate<SchemaVerifiers<T>>>(
        &self,
        _entity: &SchemaVerifiers<T>,
        _update: &U,
    ) -> bool {
        true
    }
}

impl<T: Limits> CanUpdate<SchemaIssuers<T>> for Convener {
    fn can_add(&self, _entity: &SchemaIssuers<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &SchemaIssuers<T>) -> bool {
        true
    }

    fn can_replace(&self, _new: &SchemaIssuers<T>, _entity: &SchemaIssuers<T>) -> bool {
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

impl<T: Limits> CanUpdate<SchemaVerifiers<T>> for Convener {
    fn can_add(&self, _entity: &SchemaVerifiers<T>) -> bool {
        true
    }

    fn can_remove(&self, _entity: &SchemaVerifiers<T>) -> bool {
        true
    }

    fn can_replace(&self, _new: &SchemaVerifiers<T>, _entity: &SchemaVerifiers<T>) -> bool {
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
