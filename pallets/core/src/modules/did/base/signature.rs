use core::marker::PhantomData;

use super::super::*;
use crate::common::{
    Authorization, AuthorizeSignedAction, AuthorizeTarget, DidMethodKeySigValue, ForSigType,
    GetKey, SigValue, Signature, ToStateChange,
};

/// Either `DidKey` or `DidMethodKey`.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum DidKeyOrDidMethodKey {
    DidKey(DidKey),
    DidMethodKey(DidMethodKey),
}

impl TryFrom<DidKeyOrDidMethodKey> for DidKey {
    type Error = DidMethodKey;

    fn try_from(did_key_or_did_method_key: DidKeyOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_key_or_did_method_key {
            DidKeyOrDidMethodKey::DidKey(did_key) => Ok(did_key),
            DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => Err(did_method_key),
        }
    }
}

impl TryFrom<DidKeyOrDidMethodKey> for DidMethodKey {
    type Error = DidKey;

    fn try_from(did_key_or_did_method_key: DidKeyOrDidMethodKey) -> Result<Self, Self::Error> {
        match did_key_or_did_method_key {
            DidKeyOrDidMethodKey::DidKey(did_key) => Err(did_key),
            DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => Ok(did_method_key),
        }
    }
}

impl<Target, Authorizer> AuthorizeTarget<Target, DidKeyOrDidMethodKey> for Authorizer
where
    Authorizer: AuthorizeTarget<Target, DidKey> + AuthorizeTarget<Target, DidMethodKey>,
{
    fn ensure_authorizes_target<T, A>(
        &self,
        key: &DidKeyOrDidMethodKey,
        action: &A,
    ) -> Result<(), super::Error<T>>
    where
        T: super::Config,
        A: Action<Target = Target>,
    {
        match key {
            DidKeyOrDidMethodKey::DidKey(did_key) => self.ensure_authorizes_target(did_key, action),
            DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => {
                self.ensure_authorizes_target(did_method_key, action)
            }
        }
    }
}

/// `DID`'s signature along with the used `DID`s key reference.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum DidOrDidMethodKeySignature<D: Into<DidOrDidMethodKey>> {
    DidSignature(DidSignature<Did>),
    DidMethodKeySignature(DidMethodKeySignature<DidMethodKey>),
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    __Marker(PhantomData<D>),
}

impl<D: Into<DidOrDidMethodKey>> From<DidSignature<Did>> for DidOrDidMethodKeySignature<D> {
    fn from(sig: DidSignature<Did>) -> Self {
        Self::DidSignature(sig)
    }
}

impl<D: Into<DidOrDidMethodKey>> From<DidMethodKeySignature<DidMethodKey>>
    for DidOrDidMethodKeySignature<D>
{
    fn from(sig: DidMethodKeySignature<DidMethodKey>) -> Self {
        Self::DidMethodKeySignature(sig)
    }
}

impl<D: Into<Did>> ForSigType for DidSignature<D> {
    fn for_sig_type<R>(
        &self,
        for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> Option<R> {
        match self.sig {
            SigValue::Ed25519(_) => for_ed25519(),
            SigValue::Sr25519(_) => for_sr25519(),
            SigValue::Secp256k1(_) => for_secp256k1(),
        }
        .into()
    }
}

impl<D: Into<DidMethodKey>> ForSigType for DidMethodKeySignature<D> {
    fn for_sig_type<R>(
        &self,
        _for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> Option<R> {
        match self.sig {
            DidMethodKeySigValue::Ed25519(_) => for_ed25519(),
            DidMethodKeySigValue::Secp256k1(_) => for_secp256k1(),
        }
        .into()
    }
}

impl<D: Into<DidOrDidMethodKey>> ForSigType for DidOrDidMethodKeySignature<D> {
    fn for_sig_type<R>(
        &self,
        for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> Option<R> {
        match self {
            Self::DidSignature(sig) => sig.for_sig_type(for_sr25519, for_ed25519, for_secp256k1),
            Self::DidMethodKeySignature(sig) => {
                sig.for_sig_type(for_sr25519, for_ed25519, for_secp256k1)
            }
            _ => None,
        }
    }
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[codec(encode_bound(D: Encode + MaxEncodedLen))]
#[scale_info(omit_prefix)]
pub struct DidSignature<D: Into<Did>> {
    /// The DID that created this signature
    pub did: D,
    /// The key-id of above DID used to verify the signature
    pub key_id: IncId,
    /// The actual signature
    pub sig: SigValue,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[codec(encode_bound(D: Encode + MaxEncodedLen))]
#[scale_info(omit_prefix)]
pub struct DidMethodKeySignature<D: Into<DidMethodKey>> {
    pub did_method_key: D,
    pub sig: DidMethodKeySigValue,
}

impl<D: Into<Did> + Clone> Signature for DidSignature<D> {
    type Signer = D;
    type Key = DidKey;

    fn signer(&self) -> Option<D> {
        Some(self.did.clone())
    }

    fn verify_bytes<M>(&self, message: M, public_key: &Self::Key) -> Result<bool, VerificationError>
    where
        M: AsRef<[u8]>,
    {
        self.sig.verify(message.as_ref(), public_key.public_key())
    }
}

impl<D: Into<Did> + Clone> GetKey<DidKey> for DidSignature<D> {
    fn key<T: Config>(&self) -> Option<DidKey> {
        super::Pallet::<T>::did_key(self.did.clone().into(), self.key_id)
    }
}

/// Verifies that `did`'s key with id `key_id` can either authenticate or control otherwise returns an error.
/// Then provided signature will be verified against the supplied public key and `true` returned for a valid signature.

impl<DK: Into<DidMethodKey> + Clone> Signature for DidMethodKeySignature<DK> {
    type Signer = DK;
    type Key = DidMethodKey;

    fn signer(&self) -> Option<DK> {
        Some(self.did_method_key.clone())
    }

    fn verify_bytes<M>(&self, message: M, public_key: &Self::Key) -> Result<bool, VerificationError>
    where
        M: AsRef<[u8]>,
    {
        self.sig.verify(message.as_ref(), public_key)
    }
}

impl<D: Into<DidMethodKey> + Clone> GetKey<DidMethodKey> for DidMethodKeySignature<D> {
    fn key<T: Config>(&self) -> Option<DidMethodKey> {
        Some(self.did_method_key.clone().into())
    }
}

impl<D> Signature for DidOrDidMethodKeySignature<D>
where
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone,
{
    type Signer = D;
    type Key = DidKeyOrDidMethodKey;

    fn signer(&self) -> Option<Self::Signer> {
        Some(match self {
            Self::DidMethodKeySignature(sig) => {
                DidOrDidMethodKey::DidMethodKey(sig.signer()?).into()
            }
            Self::DidSignature(sig) => DidOrDidMethodKey::Did(sig.signer()?).into(),
            Self::__Marker(_) => None::<Self::Signer>?,
        })
    }

    fn verify_bytes<M>(&self, message: M, key: &Self::Key) -> Result<bool, VerificationError>
    where
        M: AsRef<[u8]>,
    {
        match self {
            Self::DidSignature(sig) => match key {
                DidKeyOrDidMethodKey::DidKey(did_key) => sig.verify_bytes(message, did_key),
                _ => Err(VerificationError::IncompatibleKey),
            },
            Self::DidMethodKeySignature(sig) => match key {
                DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => {
                    sig.verify_bytes(message, did_method_key)
                }
                _ => Err(VerificationError::IncompatibleKey),
            },
            Self::__Marker(_) => Err(VerificationError::IncompatibleKey),
        }
    }
}

impl<D> GetKey<DidKeyOrDidMethodKey> for DidOrDidMethodKeySignature<D>
where
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone,
{
    fn key<T: Config>(&self) -> Option<DidKeyOrDidMethodKey> {
        Some(match self {
            Self::DidMethodKeySignature(sig) => DidKeyOrDidMethodKey::DidMethodKey(sig.key::<T>()?),
            Self::DidSignature(sig) => DidKeyOrDidMethodKey::DidKey(sig.key::<T>()?),
            Self::__Marker(_) => None::<DidKeyOrDidMethodKey>?,
        })
    }
}

impl<D: Into<Did>> DidSignature<D> {
    pub fn new(did: impl Into<D>, key_id: impl Into<IncId>, sig: impl Into<SigValue>) -> Self {
        Self {
            did: did.into(),
            key_id: key_id.into(),
            sig: sig.into(),
        }
    }

    /// This is just the weight to verify the signature. It does not include weight to read the DID or the key.
    pub fn weight(&self) -> Weight {
        self.sig.weight()
    }
}

impl<T: Config, A> SignedActionWithNonce<T, A, DidOrDidMethodKeySignature<Controller>>
where
    A: ActionWithNonce<T, Target = Did> + ToStateChange<T>,
    DidOrDidMethodKeySignature<Controller>:
        AuthorizeSignedAction<A, Key = DidKeyOrDidMethodKey, Signer = Controller>,
{
    pub fn execute_from_controller<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut OnChainDidDetails) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
    {
        self.execute_removable_from_controller(|action, reference| {
            f(action, reference.as_mut().unwrap())
        })
    }

    pub fn execute_removable_from_controller<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<OnChainDidDetails>) -> Result<R, E>,
        E: From<ActionExecutionError> + From<NonceError> + From<Error<T>>,
    {
        let SignedActionWithNonce {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        match signer.into() {
            DidOrDidMethodKey::Did(controller) => {
                if controller == action.target() {
                    ActionWrapper::<T, A, Did>::new(action.nonce(), controller, action)
                        .execute_and_increase_nonce(|ActionWrapper { action, .. }, reference| {
                            f(action, reference)
                        })
                        .map_err(Into::into)
                } else {
                    ActionWrapper::<T, A, Did>::new(action.nonce(), controller, action)
                        .execute_and_increase_nonce(|ActionWrapper { action, .. }, _| {
                            action.execute_without_increasing_nonce(|action, reference| {
                                f(action, reference)
                            })
                        })
                        .map_err(Into::into)
                }
            }
            DidOrDidMethodKey::DidMethodKey(controller) => {
                ActionWrapper::<T, A, DidMethodKey>::new(action.nonce(), controller, action)
                    .execute_and_increase_nonce(|ActionWrapper { action, .. }, _| {
                        action.execute_without_increasing_nonce(|action, reference| {
                            f(action, reference)
                        })
                    })
                    .map_err(Into::into)
            }
        }
    }
}
