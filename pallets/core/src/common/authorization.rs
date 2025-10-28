use crate::{
    common::Signature,
    did,
    util::{Action, Associated},
};
use codec::Encode;
use core::ops::Deref;
use sp_runtime::{DispatchError, DispatchResult};

use super::{GetKey, ToStateChange, TypesAndLimits};

/// Authorizes action performed by `Self` over supplied target using given key.
pub trait AuthorizeTarget<T, Target, Key>
where
    Target: Associated<T>,
{
    /// `Self` can perform supplied action over `target` using the provided key.
    fn ensure_authorizes_target<A>(
        &self,
        _: &Key,
        _: &A,
        _: Option<&Target::Value>,
    ) -> DispatchResult
    where
        A: Action<Target = Target>,
    {
        Ok(())
    }
}

type AuthorizationResult<S> =
    Result<Option<Authorization<<S as Signature>::Signer, <S as Signature>::Key>>, DispatchError>;

/// Signature that can authorize a signed action.
pub trait AuthorizeSignedAction<T: TypesAndLimits, A: Action>:
    Signature + GetKey<Self::Key>
where
    A: ToStateChange<T>,
    A::Target: Associated<T>,
    // The signer must implement the `AuthorizeTarget` trait, which authorizes the target of the action.
    // Additionally, the signer must implement the `Deref` trait.
    Self::Signer: AuthorizeTarget<T, A::Target, Self::Key> + Deref,
    // The target of the dereferenced signer must also implement the `AuthorizeTarget` trait,
    // ensuring that the underlying target is authorized for the action.
    <Self::Signer as Deref>::Target: AuthorizeTarget<T, A::Target, Self::Key>,
{
    /// This signature allows `Self::Signer` to perform the supplied action.
    fn authorizes_signed_action(
        &self,
        action: &A,
        value: Option<&<A::Target as Associated<T>>::Value>,
    ) -> AuthorizationResult<Self>
    where
        T: crate::did::Config,
    {
        let signer_pubkey = self.key::<T>().ok_or(did::Error::<T>::NoKeyForDid)?;
        let encoded_state_change = action.to_state_change().encode();

        let signer = self.signer().ok_or(did::Error::<T>::InvalidSigner)?;
        // Ensure that signer's underlying value authorizes supplied action.
        (*signer).ensure_authorizes_target(&signer_pubkey, action, value.as_ref().copied())?;
        // Ensure that signer's wrapper value authorizes supplied action.
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

impl<T: TypesAndLimits, A: Action, S> AuthorizeSignedAction<T, A> for S
where
    A::Target: Associated<T>,
    A: ToStateChange<T>,
    S: Signature + GetKey<S::Key>,
    S::Signer: AuthorizeTarget<T, A::Target, S::Key> + Deref,
    <S::Signer as Deref>::Target: AuthorizeTarget<T, A::Target, S::Key>,
{
}

/// Successfully authorized signer along with its key.
pub struct Authorization<S, K> {
    pub signer: S,
    pub key: K,
}
