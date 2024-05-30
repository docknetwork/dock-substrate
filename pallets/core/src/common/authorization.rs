use crate::{
    common::Signature,
    did,
    util::{Action, Associated},
};
use codec::Encode;
use core::ops::Deref;
use sp_runtime::{DispatchError, DispatchResult};

use super::{GetKey, ToStateChange};

/// Authorizes action performed by `Self` over supplied target using given key.
pub trait AuthorizeTarget<Target, Key> {
    /// `Self` can perform supplied action over `target` using the provided key.
    fn ensure_authorizes_target<T, A>(
        &self,
        _: &Key,
        _: &A,
        _: Option<&Target::Value>,
    ) -> DispatchResult
    where
        T: crate::did::Config,
        A: Action<Target = Target>,
        Target: Associated<T>,
    {
        Ok(())
    }
}

type AuthorizationResult<S> =
    Result<Option<Authorization<<S as Signature>::Signer, <S as Signature>::Key>>, DispatchError>;

/// Signature that can authorize a signed action.
pub trait AuthorizeSignedAction<A: Action>: Signature + GetKey<Self::Key>
where
    Self::Signer: AuthorizeTarget<A::Target, Self::Key> + Deref,
    <Self::Signer as Deref>::Target: AuthorizeTarget<A::Target, Self::Key>,
{
    /// This signature allows `Self::Signer` to perform the supplied action.
    fn authorizes_signed_action<T: did::Config>(
        &self,
        action: &A,
        value: Option<&<A::Target as Associated<T>>::Value>,
    ) -> AuthorizationResult<Self>
    where
        A: ToStateChange<T>,
        A::Target: Associated<T>,
    {
        let signer_pubkey = self.key::<T>().ok_or(did::Error::<T>::NoKeyForDid)?;
        let encoded_state_change = action.to_state_change().encode();

        let signer = self.signer().ok_or(did::Error::<T>::InvalidSigner)?;
        (*signer).ensure_authorizes_target(&signer_pubkey, action, value.as_ref().copied())?;
        signer.ensure_authorizes_target(&signer_pubkey, action, value.as_ref().copied())?;

        let ok = self
            .verify_bytes(encoded_state_change, &signer_pubkey)
            .map_err(did::Error::<T>::from)?;

        Ok(ok.then_some(Authorization {
            signer,
            key: signer_pubkey,
        }))
    }
}

impl<A: Action, S> AuthorizeSignedAction<A> for S
where
    S: Signature + GetKey<S::Key>,
    S::Signer: AuthorizeTarget<A::Target, S::Key> + Deref,
    <S::Signer as Deref>::Target: AuthorizeTarget<A::Target, S::Key>,
{
}

/// Successfully authorized signer along with its key.
pub struct Authorization<S, K> {
    pub signer: S,
    pub key: K,
}
