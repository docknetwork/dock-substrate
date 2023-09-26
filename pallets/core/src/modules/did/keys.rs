use super::*;
use crate::{deposit_indexed_event, impl_bits_conversion, impl_wrapper_type_info};

/// Valid did key with correct verification relationships.
#[derive(Encode, Clone, Debug, PartialEq, Eq, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct DidKey {
    /// The public key
    public_key: PublicKey,
    /// The different verification relationships the above key has with the DID.
    ver_rels: VerRelType,
}

/// `DidKey` without validity constraint requirement.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct UncheckedDidKey {
    /// The public key
    pub public_key: PublicKey,
    /// The different verification relationships the above key has with the DID.
    pub ver_rels: VerRelType,
}

impl Decode for DidKey {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let decoded = UncheckedDidKey::decode(input)?;

        Self::try_from(decoded)
            .map_err(|err| -> &'static str { err.into() })
            .map_err(Into::into)
    }
}

bitflags::bitflags! {
    /// Different verification relation types specified in the DID spec here https://www.w3.org/TR/did-core/#verification-relationships.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
    pub struct VerRelType: u16 {
        /// No verification relation set.
        const NONE = 0;
        /// https://www.w3.org/TR/did-core/#authentication
        const AUTHENTICATION = 0b0001;
        /// https://www.w3.org/TR/did-core/#assertion
        const ASSERTION = 0b0010;
        /// A key must have this to control a DID
        /// https://www.w3.org/TR/did-core/#capability-invocation
        const CAPABILITY_INVOCATION = 0b0100;
        /// https://www.w3.org/TR/did-core/#key-agreement
        const KEY_AGREEMENT = 0b1000;
        /// Includes `AUTHENTICATION`, `ASSERTION`, `CAPABILITY_INVOCATION`.
        /// We might add more relationships in future but these 3 are all we care about now.
        const ALL_FOR_SIGNING = 0b0111;
    }
}

impl_bits_conversion! { VerRelType from u16 }
impl_wrapper_type_info! { VerRelType(u16) }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DidKeyError {
    KeyAgreementCantBeUsedForSigning,
    SigningKeyCantBeUsedForKeyAgreement,
}

impl From<DidKeyError> for &'static str {
    fn from(err: DidKeyError) -> &'static str {
        match err {
            DidKeyError::KeyAgreementCantBeUsedForSigning => {
                "Key Agreement can't be used for signing"
            }
            DidKeyError::SigningKeyCantBeUsedForKeyAgreement => {
                "Signing key can't be used for Key Agreement"
            }
        }
    }
}

impl<T: Config> From<DidKeyError> for Error<T> {
    fn from(err: DidKeyError) -> Error<T> {
        match err {
            DidKeyError::KeyAgreementCantBeUsedForSigning => {
                Error::<T>::KeyAgreementCantBeUsedForSigning
            }
            DidKeyError::SigningKeyCantBeUsedForKeyAgreement => {
                Error::<T>::SigningKeyCantBeUsedForKeyAgreement
            }
        }
    }
}

impl DidKey {
    /// Constructs new `DidKey` using given public key and verification relationships.
    pub fn new(
        public_key: impl Into<PublicKey>,
        ver_rels: VerRelType,
    ) -> Result<Self, DidKeyError> {
        if ver_rels.is_empty() {
            Ok(Self::new_with_all_relationships(public_key))
        } else {
            let public_key = public_key.into();
            if public_key.can_sign() {
                if ver_rels.intersects(VerRelType::KEY_AGREEMENT) {
                    return Err(DidKeyError::SigningKeyCantBeUsedForKeyAgreement);
                }
            } else if ver_rels != VerRelType::KEY_AGREEMENT {
                return Err(DidKeyError::KeyAgreementCantBeUsedForSigning);
            }

            Ok(Self {
                public_key,
                ver_rels,
            })
        }
    }

    /// Constructs new `DidKey` using given public key and all available verification relationships
    /// for this key.
    pub fn new_with_all_relationships(public_key: impl Into<PublicKey>) -> Self {
        let public_key = public_key.into();
        let ver_rels = if public_key.can_sign() {
            // If the key can be used for signing, mark it with all related relationships.
            VerRelType::ALL_FOR_SIGNING
        } else {
            // The non-signing public key can be used only for key agreement currently.
            VerRelType::KEY_AGREEMENT
        };

        Self {
            public_key,
            ver_rels,
        }
    }

    /// Returns underlying public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns underlying verification relationships.
    pub fn ver_rels(&self) -> VerRelType {
        self.ver_rels
    }

    /// Checks if this key is capable of signing.
    pub fn can_sign(&self) -> bool {
        self.public_key.can_sign()
    }

    /// Checks if this key can has `CAPABILITY_INVOCATION` relation set.
    pub fn can_control(&self) -> bool {
        self.ver_rels.intersects(VerRelType::CAPABILITY_INVOCATION)
    }

    /// Checks if this key can has `AUTHENTICATION` relation set.
    pub fn can_authenticate(&self) -> bool {
        self.ver_rels.intersects(VerRelType::AUTHENTICATION)
    }

    /// Checks if this key can has `KEY_AGREEMENT` relation set.
    pub fn for_key_agreement(&self) -> bool {
        self.ver_rels.intersects(VerRelType::KEY_AGREEMENT)
    }

    /// Checks if this key can has either `AUTHENTICATION` or `CAPABILITY_INVOCATION` relation set.
    pub fn can_authenticate_or_control(&self) -> bool {
        self.ver_rels
            .intersects(VerRelType::AUTHENTICATION | VerRelType::CAPABILITY_INVOCATION)
    }
}

impl UncheckedDidKey {
    /// Constructs new `UncheckedDidKey` using given public key and verification relationships.
    /// This function doesn't require key to have valid verification relationships.
    pub fn new(public_key: impl Into<PublicKey>, ver_rels: VerRelType) -> Self {
        UncheckedDidKey {
            public_key: public_key.into(),
            ver_rels,
        }
    }

    /// Constructs new `UncheckedDidKey` using given public key and all available verification relationships
    /// for this key.
    pub fn new_with_all_relationships(public_key: impl Into<PublicKey>) -> Self {
        DidKey::new_with_all_relationships(public_key).into()
    }
}

impl TryFrom<UncheckedDidKey> for DidKey {
    type Error = DidKeyError;

    fn try_from(
        UncheckedDidKey {
            public_key,
            ver_rels,
        }: UncheckedDidKey,
    ) -> Result<Self, Self::Error> {
        DidKey::new(public_key, ver_rels)
    }
}

impl From<DidKey> for UncheckedDidKey {
    fn from(
        DidKey {
            public_key,
            ver_rels,
        }: DidKey,
    ) -> Self {
        UncheckedDidKey::new(public_key, ver_rels)
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn add_keys_(
        AddKeys { did, keys, .. }: AddKeys<T>,
        OnChainDidDetails {
            active_controllers,
            active_controller_keys,
            last_key_id,
            ..
        }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        let keys: Vec<_> = keys
            .into_iter()
            .map(DidKey::try_from)
            .collect::<Result<_, _>>()
            .map_err(Error::<T>::from)?;

        // If DID was not self controlled first, check if it can become by looking over new keys
        let controller_keys_count = keys.iter().filter(|key| key.can_control()).count() as u32;
        *active_controller_keys += controller_keys_count;

        // Make self controlled if needed
        let add_self_controlled = controller_keys_count > 0 && !Self::is_self_controlled(&did);
        if add_self_controlled {
            DidControllers::<T>::insert(did, Controller(did), ());
            *active_controllers += 1;
        }

        for (key, key_id) in keys.into_iter().zip(last_key_id) {
            DidKeys::<T>::insert(did, key_id, key);
        }

        deposit_indexed_event!(DidKeysAdded(did));
        Ok(())
    }

    pub(crate) fn remove_keys_(
        RemoveKeys { did, keys, .. }: RemoveKeys<T>,
        OnChainDidDetails {
            active_controllers,
            active_controller_keys,
            ..
        }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        for key_id in &keys {
            let key = DidKeys::<T>::get(did, key_id).ok_or(Error::<T>::NoKeyForDid)?;

            if key.can_control() {
                *active_controller_keys -= 1;
            }
        }

        for key in &keys {
            DidKeys::<T>::remove(did, key);
        }

        // If no self-control keys exist for the given DID, remove self-control
        let remove_self_controlled = *active_controller_keys == 0 && Self::is_self_controlled(&did);
        if remove_self_controlled {
            DidControllers::<T>::remove(did, Controller(did));
            *active_controllers -= 1;
        }

        deposit_indexed_event!(DidKeysRemoved(did));
        Ok(())
    }

    /// Return `did`'s key with id `key_id` only if has control capability, otherwise returns an error.
    pub fn control_key(&did: &Controller, key_id: IncId) -> Result<PublicKey, Error<T>> {
        let did_key = DidKeys::<T>::get(*did, key_id).ok_or(Error::<T>::NoKeyForDid)?;

        if did_key.can_control() {
            Ok(did_key.public_key)
        } else {
            Err(Error::<T>::InsufficientVerificationRelationship)
        }
    }

    /// Return `did`'s key with id `key_id` only if it can authenticate or control otherwise returns an error
    pub fn auth_or_control_key(did: &Did, key_id: IncId) -> Result<PublicKey, Error<T>> {
        let did_key = DidKeys::<T>::get(did, key_id).ok_or(Error::<T>::NoKeyForDid)?;

        if did_key.can_authenticate_or_control() {
            Ok(did_key.public_key)
        } else {
            Err(Error::<T>::InsufficientVerificationRelationship)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};
    use sp_core::Pair;

    #[test]
    fn encode() {
        assert_eq!(2u16.encode(), VerRelType::ASSERTION.encode());
        assert_eq!(
            VerRelType::decode(&mut &2u16.encode()[..]).unwrap(),
            VerRelType::ASSERTION
        );
        let (pair_sr, _, _) = sp_application_crypto::sr25519::Pair::generate_with_phrase(None);
        let pk_sr = pair_sr.public().0;

        assert_eq!(
            DidKey::new(PublicKey::sr25519(pk_sr), VerRelType::CAPABILITY_INVOCATION)
                .unwrap()
                .encode(),
            UncheckedDidKey::new(PublicKey::sr25519(pk_sr), VerRelType::CAPABILITY_INVOCATION)
                .encode()
        );
        assert_eq!(
            DidKey::decode(
                &mut &UncheckedDidKey::new(
                    PublicKey::sr25519(pk_sr),
                    VerRelType::CAPABILITY_INVOCATION
                )
                .encode()[..]
            )
            .unwrap(),
            DidKey::new(PublicKey::sr25519(pk_sr), VerRelType::CAPABILITY_INVOCATION).unwrap()
        );
    }
}
