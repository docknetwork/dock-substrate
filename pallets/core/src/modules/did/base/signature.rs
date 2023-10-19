use core::marker::PhantomData;

use super::super::*;
use crate::common::{DidMethodKeySigValue, ForSigType, SigValue, ToStateChange, Types};
use frame_support::traits::Get;

/// Authorizes action performed by `Self` over supplied target using given key.
pub trait AuthorizeTarget<Target, Key> {
    fn ensure_authorizes_target<T: Config, A>(&self, _: &Key, _: &A) -> Result<(), Error<T>>
    where
        A: Action<Target = Target>,
    {
        Ok(())
    }
}

/// Successfully authorized signer along with its key.
pub struct Authorization<S, K> {
    pub signer: S,
    pub key: K,
}

/// Either `DidKey` or `DidMethodKey`.
pub enum DidKeyOrDidMethodKey {
    DidKey(DidKey),
    DidMethodKey(DidMethodKey),
}

/// Signed entity.
pub trait Signed {
    type Signer: Clone;

    fn signer(&self) -> Self::Signer;
}

type AuthorizationResult<T, S, A> = Result<
    Option<Authorization<<S as Signed>::Signer, <S as AuthorizeSignedAction<A>>::Key>>,
    Error<T>,
>;

/// Authorizes signed action.
pub trait AuthorizeSignedAction<A: Action>: Signed {
    type Key;

    fn authorizes_signed_action<T: Config>(&self, action: &A) -> AuthorizationResult<T, Self, A>
    where
        A: ToStateChange<T>;
}

/// `DID`'s signature along with the used `DID`s key reference.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum DidOrDidMethodKeySignature<D: Into<DidOrDidMethodKey>> {
    DidSignature(DidSignature<Did>),
    DidKeySignature(DidKeySignature<DidMethodKey>),
    #[codec(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    __Marker(PhantomData<D>),
}

impl<D: Into<DidOrDidMethodKey>> From<DidSignature<Did>> for DidOrDidMethodKeySignature<D> {
    fn from(sig: DidSignature<Did>) -> Self {
        Self::DidSignature(sig)
    }
}

impl<D: Into<DidOrDidMethodKey>> From<DidKeySignature<DidMethodKey>>
    for DidOrDidMethodKeySignature<D>
{
    fn from(sig: DidKeySignature<DidMethodKey>) -> Self {
        Self::DidKeySignature(sig)
    }
}

impl<D: Into<Did>> ForSigType for DidSignature<D> {
    fn for_sig_type<R>(
        &self,
        for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> R {
        match self.sig {
            SigValue::Ed25519(_) => for_ed25519(),
            SigValue::Sr25519(_) => for_sr25519(),
            SigValue::Secp256k1(_) => for_secp256k1(),
        }
    }
}

impl<D: Into<DidMethodKey>> ForSigType for DidKeySignature<D> {
    fn for_sig_type<R>(
        &self,
        _for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> R {
        match self.sig {
            DidMethodKeySigValue::Ed25519(_) => for_ed25519(),
            DidMethodKeySigValue::Secp256k1(_) => for_secp256k1(),
        }
    }
}

impl<D: Into<DidOrDidMethodKey>> ForSigType for DidOrDidMethodKeySignature<D> {
    fn weight_for_sig_type<T: frame_system::Config>(
        &self,
        for_sr25519: impl FnOnce() -> Weight,
        for_ed25519: impl FnOnce() -> Weight,
        for_secp256k1: impl FnOnce() -> Weight,
    ) -> Weight {
        match self {
            Self::DidSignature(sig) => {
                sig.weight_for_sig_type::<T>(for_sr25519, for_ed25519, for_secp256k1)
            }
            Self::DidKeySignature(sig) => sig
                .weight_for_sig_type::<T>(for_sr25519, for_ed25519, for_secp256k1)
                .saturating_sub(T::DbWeight::get().reads(1)),
            _ => unreachable!(),
        }
    }

    fn for_sig_type<R>(
        &self,
        for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> R {
        match self {
            Self::DidSignature(sig) => sig.for_sig_type(for_sr25519, for_ed25519, for_secp256k1),
            Self::DidKeySignature(sig) => sig.for_sig_type(for_sr25519, for_ed25519, for_secp256k1),
            _ => unreachable!(),
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
pub struct DidKeySignature<D: Into<DidMethodKey>> {
    pub did_key: D,
    pub sig: DidMethodKeySigValue,
}

impl<D: Into<Did> + Clone> Signed for DidSignature<D> {
    type Signer = D;

    fn signer(&self) -> D {
        self.did.clone()
    }
}

/// Verifies that `did`'s key with id `key_id` can either authenticate or control otherwise returns an error.
/// Then provided signature will be verified against the supplied public key and `true` returned for a valid signature.
impl<D: Into<Did> + Clone, A: Action> AuthorizeSignedAction<A> for DidSignature<D>
where
    D: AuthorizeTarget<A::Target, DidKey>,
{
    type Key = DidKey;

    fn authorizes_signed_action<T: Config>(
        &self,
        action: &A,
    ) -> Result<Option<Authorization<Self::Signer, DidKey>>, Error<T>>
    where
        A: ToStateChange<T>,
    {
        let raw_did = self.did.clone().into();
        let signer_pubkey =
            Pallet::<T>::did_key(raw_did, self.key_id).ok_or(Error::<T>::NoKeyForDid)?;
        let encoded_state_change = action.to_state_change().encode();

        raw_did.ensure_authorizes_target(&signer_pubkey, action)?;
        self.did.ensure_authorizes_target(&signer_pubkey, action)?;

        self.sig
            .verify(&encoded_state_change, signer_pubkey.public_key())
            .map_err(Into::into)
            .map(|yes| {
                yes.then(|| Authorization {
                    signer: self.did.clone(),
                    key: signer_pubkey,
                })
            })
    }
}

impl<DK: Into<DidMethodKey> + Clone> Signed for DidKeySignature<DK> {
    type Signer = DK;

    fn signer(&self) -> DK {
        self.did_key.clone()
    }
}

impl<DK: Into<DidMethodKey> + Clone, A: Action> AuthorizeSignedAction<A> for DidKeySignature<DK>
where
    DK: AuthorizeTarget<A::Target, DidMethodKey>,
{
    type Key = DidMethodKey;

    fn authorizes_signed_action<T: Config>(
        &self,
        action: &A,
    ) -> Result<Option<Authorization<Self::Signer, DidMethodKey>>, Error<T>>
    where
        A: ToStateChange<T>,
    {
        let signer_pubkey = self.did_key.clone().into();
        let encoded_state_change = action.to_state_change().encode();

        signer_pubkey.ensure_authorizes_target(&signer_pubkey, action)?;
        self.did_key
            .ensure_authorizes_target(&signer_pubkey, action)?;

        self.sig
            .verify(&encoded_state_change, &signer_pubkey)
            .map_err(Into::into)
            .map(|yes| {
                yes.then(|| Authorization {
                    signer: self.did_key.clone(),
                    key: signer_pubkey,
                })
            })
    }
}

impl<D> Signed for DidOrDidMethodKeySignature<D>
where
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone,
{
    type Signer = D;

    fn signer(&self) -> Self::Signer {
        match self {
            Self::DidKeySignature(sig) => DidOrDidMethodKey::DidMethodKey(sig.did_key).into(),
            Self::DidSignature(sig) => DidOrDidMethodKey::Did(sig.did).into(),
            Self::__Marker(_) => unreachable!(),
        }
    }
}

impl<D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone, A: Action>
    AuthorizeSignedAction<A> for DidOrDidMethodKeySignature<D>
where
    DidSignature<Did>: AuthorizeSignedAction<A, Key = DidKey, Signer = Did>,
    DidKeySignature<DidMethodKey>:
        AuthorizeSignedAction<A, Key = DidMethodKey, Signer = DidMethodKey>,
    Did: AuthorizeTarget<A::Target, DidKey>,
    DidMethodKey: AuthorizeTarget<A::Target, DidMethodKey>,
    D: AuthorizeTarget<A::Target, DidKey> + AuthorizeTarget<A::Target, DidMethodKey>,
{
    type Key = DidKeyOrDidMethodKey;

    fn authorizes_signed_action<T: Config>(
        &self,
        action: &A,
    ) -> Result<Option<Authorization<Self::Signer, DidKeyOrDidMethodKey>>, Error<T>>
    where
        A: ToStateChange<T>,
    {
        let authorization = match self {
            Self::DidSignature(sig) => sig.authorizes_signed_action(action)?.map(
                |Authorization { signer, key, .. }| Authorization {
                    signer: D::from(DidOrDidMethodKey::Did(signer)),
                    key: DidKeyOrDidMethodKey::DidKey(key),
                },
            ),
            Self::DidKeySignature(sig) => sig.authorizes_signed_action(action)?.map(
                |Authorization { signer, key, .. }| Authorization {
                    signer: DidOrDidMethodKey::DidMethodKey(signer).into(),
                    key: DidKeyOrDidMethodKey::DidMethodKey(key),
                },
            ),
            _ => None,
        };

        if let Some(Authorization { key, signer }) = authorization.as_ref() {
            match key {
                DidKeyOrDidMethodKey::DidKey(did_key) => {
                    signer.ensure_authorizes_target(did_key, action)?
                }
                DidKeyOrDidMethodKey::DidMethodKey(did_method_key) => {
                    signer.ensure_authorizes_target(did_method_key, action)?
                }
            }
        }

        Ok(authorization)
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

pub struct SignedActionWithNonce<T: Types, A, S>
where
    A: ActionWithNonce<T>,
{
    action: A,
    signature: S,
    _marker: PhantomData<T>,
}

impl<T: Types, A, S> SignedActionWithNonce<T, A, S>
where
    A: ActionWithNonce<T>,
{
    pub fn new(action: A, signature: S) -> Self {
        Self {
            action,
            signature,
            _marker: PhantomData,
        }
    }
}

impl<T: crate::did::Config, A, D> SignedActionWithNonce<T, A, DidSignature<D>>
where
    A: ActionWithNonce<T> + ToStateChange<T>,
    D: Into<Did>
        + AuthorizeTarget<A::Target, <DidSignature<D> as AuthorizeSignedAction<A>>::Key>
        + Clone,
    DidSignature<D>: AuthorizeSignedAction<A, Signer = D>,
{
    pub fn execute<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, D) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError> + From<Error<T>>,
    {
        let SignedActionWithNonce {
            action, signature, ..
        } = self;

        ensure!(
            signature.authorizes_signed_action(&action)?.is_some(),
            Error::<T>::InvalidSignature
        );

        WrappedActionWithNonce::<T, A, Did>::new(action.nonce(), signature.signer().into(), action)
            .execute(|WrappedActionWithNonce { action, .. }, _| f(action, signature.signer()))
            .map_err(Into::into)
    }
}

impl<T: crate::did::Config, A, D> SignedActionWithNonce<T, A, DidKeySignature<D>>
where
    A: ActionWithNonce<T> + ToStateChange<T>,
    D: Into<DidMethodKey>
        + AuthorizeTarget<A::Target, <DidKeySignature<D> as AuthorizeSignedAction<A>>::Key>
        + Clone,
    DidKeySignature<D>: AuthorizeSignedAction<A, Signer = D>,
{
    pub fn execute<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, D) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError> + From<Error<T>>,
    {
        let SignedActionWithNonce {
            action, signature, ..
        } = self;

        ensure!(
            signature.authorizes_signed_action(&action)?.is_some(),
            Error::<T>::InvalidSignature
        );

        WrappedActionWithNonce::<T, A, DidMethodKey>::new(
            action.nonce(),
            signature.signer().into(),
            action,
        )
        .execute(|WrappedActionWithNonce { action, .. }, _| f(action, signature.signer()))
        .map_err(Into::into)
    }
}

impl<T: crate::did::Config, A, D> SignedActionWithNonce<T, A, DidOrDidMethodKeySignature<D>>
where
    A: ActionWithNonce<T> + ToStateChange<T>,
    D: Into<DidOrDidMethodKey> + From<DidOrDidMethodKey> + Clone,
    D: AuthorizeTarget<A::Target, DidKey> + AuthorizeTarget<A::Target, DidMethodKey>,
    DidOrDidMethodKeySignature<D>: AuthorizeSignedAction<A, Key = DidKeyOrDidMethodKey, Signer = D>,
{
    pub fn execute<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, D) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError> + From<Error<T>>,
    {
        let SignedActionWithNonce {
            action, signature, ..
        } = self;

        let Authorization { signer, .. } = signature
            .authorizes_signed_action(&action)?
            .ok_or(Error::<T>::InvalidSignature)?;

        match signer.clone().into() {
            DidOrDidMethodKey::Did(did) => {
                WrappedActionWithNonce::<T, A, Did>::new(action.nonce(), did, action)
                    .execute(|WrappedActionWithNonce { action, .. }, _| f(action, signer))
                    .map_err(Into::into)
            }
            DidOrDidMethodKey::DidMethodKey(did_key) => {
                WrappedActionWithNonce::<T, A, DidMethodKey>::new(action.nonce(), did_key, action)
                    .execute(|WrappedActionWithNonce { action, .. }, _| f(action, signer))
                    .map_err(Into::into)
            }
        }
    }
}
impl<T: crate::did::Config, A> SignedActionWithNonce<T, A, DidOrDidMethodKeySignature<Controller>>
where
    A: ActionWithNonce<T, Target = Did> + ToStateChange<T>,
    DidOrDidMethodKeySignature<Controller>:
        AuthorizeSignedAction<A, Key = DidKeyOrDidMethodKey, Signer = Controller>,
{
    pub fn execute_from_controller<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut OnChainDidDetails) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError> + From<Error<T>>,
    {
        self.execute_removable_from_controller(|action, reference| {
            f(action, reference.as_mut().unwrap())
        })
    }

    pub fn execute_removable_from_controller<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(A, &mut Option<OnChainDidDetails>) -> Result<R, E>,
        E: From<UpdateWithNonceError> + From<NonceError> + From<Error<T>>,
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
                    WrappedActionWithNonce::<T, A, Did>::new(action.nonce(), controller, action)
                        .execute(|WrappedActionWithNonce { action, .. }, reference| {
                            f(action, reference)
                        })
                        .map_err(Into::into)
                } else {
                    WrappedActionWithNonce::<T, A, Did>::new(action.nonce(), controller, action)
                        .execute(|WrappedActionWithNonce { action, .. }, _| {
                            action.execute_without_increasing_nonce(|action, reference| {
                                f(action, reference)
                            })
                        })
                        .map_err(Into::into)
                }
            }
            DidOrDidMethodKey::DidMethodKey(controller) => WrappedActionWithNonce::<
                T,
                A,
                DidMethodKey,
            >::new(
                action.nonce(), controller, action
            )
            .execute(|WrappedActionWithNonce { action, .. }, _| {
                action.execute_without_increasing_nonce(|action, reference| f(action, reference))
            })
            .map_err(Into::into),
        }
    }
}
