use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_std::fmt::Debug;

use super::{Limits, ToStateChange};

#[cfg(feature = "serde")]
use crate::util::btree_set;

use crate::{
    common::{AuthorizeTarget, ForSigType, Signature},
    did::{self, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature},
    util::{
        Action, ActionExecutionError, ActionWithNonce, NonceError, StorageRef, Types, WithNonce,
    },
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
    InvalidSigner,
}

impl From<PolicyExecutionError> for DispatchError {
    fn from(error: PolicyExecutionError) -> Self {
        let raw = match error {
            PolicyExecutionError::IncorrectNonce => "Incorrect nonce",
            PolicyExecutionError::NoEntity => "Entity not found",
            PolicyExecutionError::NotAuthorized => "Provided DID is not authorized",
            PolicyExecutionError::InvalidSigner => "Invalid signer",
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
}

fn rec_update<T: did::Config, A, R, E, D>(
    action: A,
    data: D,
    f: impl FnOnce(A, D) -> Result<R, E>,
    proof: &mut impl Iterator<Item = DidSignatureWithNonce<T>>,
) -> Result<R, E>
where
    E: From<ActionExecutionError> + From<NonceError> + From<did::Error<T>>,
    WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
    <WithNonce<T, A> as Action>::Target: StorageRef<T>,
{
    if let Some(sig_with_nonce) = proof.next() {
        let action_with_nonce = WithNonce::new_with_nonce(action, sig_with_nonce.nonce);
        let signed_action = action_with_nonce.signed(sig_with_nonce.into_data());

        signed_action.execute(|action, _, _| rec_update(action.into_data(), data, f, proof))
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

impl<T> AuthorizeTarget<T, DidKey> for PolicyExecutor {}
impl<T> AuthorizeTarget<T, DidMethodKey> for PolicyExecutor {}

/// `DID`s signature along with the nonce.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DidSignatureWithNonce<T: Types> {
    sig: DidOrDidMethodKeySignature<PolicyExecutor>,
    nonce: T::BlockNumber,
}

impl<T: Types> DidSignatureWithNonce<T> {
    pub fn new(sig: DidOrDidMethodKeySignature<PolicyExecutor>, nonce: T::BlockNumber) -> Self {
        Self { sig, nonce }
    }

    pub fn into_data(self) -> DidOrDidMethodKeySignature<PolicyExecutor> {
        self.sig
    }
}

impl<T: Types> ForSigType for DidSignatureWithNonce<T> {
    fn for_sig_type<R>(
        &self,
        for_sr25519: impl FnOnce() -> R,
        for_ed25519: impl FnOnce() -> R,
        for_secp256k1: impl FnOnce() -> R,
    ) -> Option<R> {
        self.sig
            .for_sig_type(for_sr25519, for_ed25519, for_secp256k1)
    }
}

/// Denotes an entity which has an associated `Policy`.
pub trait HasPolicy<T: Limits>: Sized {
    /// Returns underlying `Policy`.
    fn policy(&self) -> &Policy<T>;

    /// Executes action over target data providing a mutable reference if all checks succeed.
    ///
    /// Checks:
    /// 1. Verify that `proof` authorizes `action` according to `policy`.
    /// 2. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying data wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    fn execute_readonly<A, F, R, E>(
        self,
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: did::Config,
        F: FnOnce(A, Self) -> Result<R, E>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        E: From<PolicyExecutionError>
            + From<did::Error<T>>
            + From<NonceError>
            + From<ActionExecutionError>,
    {
        // check the signer set satisfies policy
        match self.policy() {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1
                        && controllers.contains(
                            &*proof[0]
                                .sig
                                .signer()
                                .ok_or(PolicyExecutionError::InvalidSigner)?
                        ),
                    PolicyExecutionError::NotAuthorized
                );
            }
        }

        rec_update(action, self, f, &mut proof.into_iter())
    }

    /// Executes action over target data providing a mutable reference if all checks succeed.
    ///
    /// Checks:
    /// 1. Verify that `proof` authorizes `action` according to `policy`.
    /// 2. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying data wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    fn execute<A, F, R, E>(
        &mut self,
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: did::Config,
        F: FnOnce(A, &mut Self) -> Result<R, E>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        E: From<PolicyExecutionError>
            + From<did::Error<T>>
            + From<NonceError>
            + From<ActionExecutionError>,
    {
        // check the signer set satisfies policy
        match self.policy() {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1
                        && controllers.contains(
                            &*proof[0]
                                .sig
                                .signer()
                                .ok_or(PolicyExecutionError::InvalidSigner)?
                        ),
                    PolicyExecutionError::NotAuthorized
                );
            }
        }

        rec_update(action, self, f, &mut proof.into_iter())
    }

    /// Executes action over target data providing a mutable reference if all checks succeed.
    ///
    /// Unlike `execute`, this action may result in a removal of a data, if the value under option
    /// will be taken.
    ///
    /// Checks:
    /// 1. Verify that `proof` authorizes `action` according to `policy`.
    /// 2. Verify that the action is not a replayed payload by ensuring each provided controller nonce equals the last nonce plus 1.
    ///
    /// Returns a mutable reference to the underlying data wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    fn execute_removable<A, F, R, E>(
        this_opt: &mut Option<Self>,
        f: F,
        action: A,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: did::Config,
        F: FnOnce(A, &mut Option<Self>) -> Result<R, E>,
        WithNonce<T, A>: ActionWithNonce<T> + ToStateChange<T>,
        <WithNonce<T, A> as Action>::Target: StorageRef<T>,
        E: From<PolicyExecutionError>
            + From<did::Error<T>>
            + From<NonceError>
            + From<ActionExecutionError>,
    {
        // check the signer set satisfies policy
        match this_opt
            .as_ref()
            .ok_or(PolicyExecutionError::NoEntity)?
            .policy()
        {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1
                        && controllers.contains(
                            &*proof[0]
                                .sig
                                .signer()
                                .ok_or(PolicyExecutionError::InvalidSigner)?
                        ),
                    PolicyExecutionError::NotAuthorized
                );
            }
        }

        rec_update(action, this_opt, f, &mut proof.into_iter())
    }
}
