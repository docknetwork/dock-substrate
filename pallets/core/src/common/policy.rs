use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_std::fmt::Debug;

use super::{Limits, ToStateChange};

#[cfg(feature = "serde")]
use crate::util::btree_set;

use crate::{
    did,
    did::{
        AuthorizeAction, Did, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature,
        Signed, SignedActionWithNonce,
    },
    util::{Action, ActionWithNonce, NonceError, UpdateWithNonceError, WithNonce},
};
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{ensure, BoundedBTreeSet};
use sp_runtime::{traits::TryCollect, DispatchError};

/// Authorization logic containing rules to modify some data entity.
#[derive(
    Encode,
    Decode,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    MaxEncodedLen,
    scale_info_derive::TypeInfo,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub enum Policy<T: Limits> {
    /// Set of `DID`s allowed to modify the entity.
    OneOf(
        #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
        BoundedBTreeSet<DidOrDidMethodKey, T::MaxPolicyControllers>,
    ),
}

impl<T: Limits> Policy<T> {
    /// Instantiates `Policy::OneOf` from the given iterator of controllers.
    pub fn one_of(
        controllers: impl IntoIterator<
            IntoIter = impl ExactSizeIterator<Item = impl Into<DidOrDidMethodKey>>,
            Item = impl Into<DidOrDidMethodKey>,
        >,
    ) -> Result<Self, PolicyValidationError> {
        controllers
            .into_iter()
            .map(Into::into)
            .try_collect()
            .map_err(|_| PolicyValidationError::TooManyControllers)
            .map(Self::OneOf)
    }
}

/// An error occurred during `Policy`-based action execution.
pub enum PolicyExecutionError {
    IncorrectNonce,
    NoEntity,
    NotAuthorized,
}

impl From<PolicyExecutionError> for DispatchError {
    fn from(error: PolicyExecutionError) -> Self {
        let raw = match error {
            PolicyExecutionError::IncorrectNonce => "Incorrect nonce",
            PolicyExecutionError::NoEntity => "Entity not found",
            PolicyExecutionError::NotAuthorized => "Provided DID is not authorized",
        };

        DispatchError::Other(raw)
    }
}

/// An error occurred during `Policy` validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValidationError {
    Empty,
    TooManyControllers,
}

impl From<PolicyValidationError> for DispatchError {
    fn from(error: PolicyValidationError) -> Self {
        let raw = match error {
            PolicyValidationError::Empty => "Policy can't be empty (have zero controllers)",
            PolicyValidationError::TooManyControllers => "Policy can't have so many controllers",
        };

        DispatchError::Other(raw)
    }
}

impl<T: Limits> Policy<T> {
    /// Ensures given `Policy` to be valid against supplied config.
    pub fn ensure_valid(&self) -> Result<(), PolicyValidationError> {
        if self.is_empty() {
            Err(PolicyValidationError::Empty)?
        }

        Ok(())
    }

    /// Returns underlying controllers count.
    pub fn len(&self) -> u32 {
        match self {
            Self::OneOf(controllers) => controllers.len() as u32,
        }
    }

    /// Returns `true` if given `Policy` is empty, i.e. doesn't have a single controller.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Executes action over target data providing a mutable reference if all checks succeed.
    ///
    /// Unlike `try_exec_action_over_data`, this action may result in a removal of a data, if the value under option
    /// will be taken.
    ///
    /// Checks:
    /// 1. Verify that `proof` authorizes `action` according to `policy`.
    /// 2. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying data wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    pub fn try_exec_removable_action<V, S, F, R, E>(
        entity: &mut Option<V>,
        f: F,
        action: S,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: crate::did::Config,
        V: HasPolicy<T>,
        F: FnOnce(S, &mut Option<V>) -> Result<R, E>,
        WithNonce<T, S>: ActionWithNonce<T> + ToStateChange<T>,
        Did: AuthorizeAction<<WithNonce<T, S> as Action>::Target, DidKey>,
        DidMethodKey: AuthorizeAction<<WithNonce<T, S> as Action>::Target, DidMethodKey>,
        E: From<PolicyExecutionError>
            + From<did::Error<T>>
            + From<NonceError>
            + From<UpdateWithNonceError>,
    {
        // check the signer set satisfies policy
        match entity
            .as_ref()
            .ok_or(PolicyExecutionError::NoEntity)?
            .policy()
        {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1 && controllers.contains(&proof[0].data().signer()),
                    PolicyExecutionError::NotAuthorized
                );
            }
        }

        rec_update(action, entity, f, &mut proof.into_iter())
    }
}

fn rec_update<T: did::Config, A, R, E, D>(
    action: A,
    data: &mut Option<D>,
    f: impl FnOnce(A, &mut Option<D>) -> Result<R, E>,
    proof: &mut impl Iterator<Item = DidSignatureWithNonce<T>>,
) -> Result<R, E>
where
    E: From<UpdateWithNonceError> + From<NonceError> + From<did::Error<T>>,
    WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
    Did: AuthorizeAction<<WithNonce<T, A> as Action>::Target, DidKey>,
    DidMethodKey: AuthorizeAction<<WithNonce<T, A> as Action>::Target, DidMethodKey>,
{
    if let Some(sig_with_nonce) = proof.next() {
        let action_with_nonce = WithNonce::new_with_nonce(action, sig_with_nonce.nonce);
        let signed_action =
            SignedActionWithNonce::new(action_with_nonce, sig_with_nonce.into_data());

        signed_action.execute(|action, _| rec_update(action.into_data(), data, f, proof))
    } else {
        f(action, data)
    }
}

/// `DID`'s controller.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct PolicyExecutor(pub DidOrDidMethodKey);

crate::impl_wrapper!(PolicyExecutor(DidOrDidMethodKey));

impl<T> AuthorizeAction<T, DidKey> for PolicyExecutor {}
impl<T> AuthorizeAction<T, DidMethodKey> for PolicyExecutor {}

/// `DID`s signature along with the nonce.
pub type DidSignatureWithNonce<T> = WithNonce<T, DidOrDidMethodKeySignature<PolicyExecutor>>;

/// Denotes an entity which has an associated `Policy`.
pub trait HasPolicy<T: Limits> {
    /// Returns underlying `Policy`.
    fn policy(&self) -> &Policy<T>;
}

/// Authorization logic containing rules to modify some data entity.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum OldPolicy<T: Limits> {
    /// Set of `DID`s allowed to modify the entity.
    OneOf(
        #[cfg_attr(feature = "serde", serde(with = "btree_set"))]
        BoundedBTreeSet<Did, T::MaxPolicyControllers>,
    ),
}

impl<T: Limits> From<OldPolicy<T>> for Policy<T> {
    fn from(old_policy: OldPolicy<T>) -> Self {
        match old_policy {
            OldPolicy::OneOf(set) => {
                Self::OneOf(set.into_iter().map(Into::into).try_collect().unwrap())
            }
        }
    }
}
