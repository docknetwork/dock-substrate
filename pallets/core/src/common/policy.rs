use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_std::fmt::Debug;

use super::{Limits, ToStateChange};

#[cfg(feature = "serde")]
use crate::util::btree_set;

use crate::{
    common::{AuthorizeTarget, ForSigType, Signature},
    did::{self, Did, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature},
    util::{
        Action, ActionExecutionError, ActionWithNonce, AnyOfOrAll, MultiSignedActionWithNonces,
        NonceError, StorageRef, Types, WithNonce,
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

    pub fn expand(&self) -> AnyOfOrAll<PolicyExecutor> {
        let Self::OneOf(items) = self;

        AnyOfOrAll::AnyOf(items.iter().cloned().map(Into::into).collect())
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
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[codec(encode_bound(N: Encode + MaxEncodedLen))]
#[codec(encode_bound(D: Encode + MaxEncodedLen))]
#[scale_info(omit_prefix)]
pub struct DidSignatureWithNonce<N, D: Into<DidOrDidMethodKey>> {
    pub sig: DidOrDidMethodKeySignature<D>,
    pub nonce: N,
}

impl<N, D: Into<DidOrDidMethodKey>> DidSignatureWithNonce<N, D> {
    pub fn new(sig: DidOrDidMethodKeySignature<D>, nonce: N) -> Self {
        Self { sig, nonce }
    }

    pub fn into_data(self) -> DidOrDidMethodKeySignature<D> {
        self.sig
    }
}

impl<N, D: Into<DidOrDidMethodKey>> ForSigType for DidSignatureWithNonce<N, D> {
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
