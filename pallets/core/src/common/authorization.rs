use crate::{common::Signature, did, util::Action};
use codec::Encode;

use super::ToStateChange;

/// Authorizes action performed by `Self` over supplied target using given key.
pub trait AuthorizeTarget<Target, Key> {
    /// `Self` can perform supplied action over `target` using the provided key.
    fn ensure_authorizes_target<T: crate::did::Config, A>(
        &self,
        _: &Key,
        _: &A,
    ) -> Result<(), crate::did::Error<T>>
    where
        A: Action<Target = Target>,
    {
        Ok(())
    }
}

type AuthorizationResult<T, S> = Result<
    Option<Authorization<<S as Signature>::Signer, <S as Signature>::Key>>,
    crate::did::Error<T>,
>;

/// Signature that can authorize a signed action.
pub trait AuthorizeSignedAction<A: Action>: Signature
where
    Self::Signer: AuthorizeTarget<A::Target, Self::Key>,
{
    /// This signature allows `Self::Signer` to perform the supplied action.
    fn authorizes_signed_action<T: crate::did::Config>(
        &self,
        action: &A,
    ) -> AuthorizationResult<T, Self>
    where
        A: ToStateChange<T>,
    {
        let signer_pubkey = self.key::<T>().ok_or(did::Error::<T>::NoKeyForDid)?;
        let encoded_state_change = action.to_state_change().encode();

        self.signer()
            .ensure_authorizes_target(&signer_pubkey, action)?;

        self.verify_raw_bytes(&encoded_state_change, &signer_pubkey)
            .map_err(Into::into)
            .map(|yes| {
                yes.then(|| Authorization {
                    signer: self.signer(),
                    key: signer_pubkey,
                })
            })
    }
}

impl<A: Action, S> AuthorizeSignedAction<A> for S
where
    S: Signature,
    S::Signer: AuthorizeTarget<A::Target, S::Key>,
{
}

/// Successfully authorized signer along with its key.
pub struct Authorization<S, K> {
    pub signer: S,
    pub key: K,
}
