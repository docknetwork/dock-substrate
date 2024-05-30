use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_std::fmt::Debug;

use super::Limits;

#[cfg(feature = "serde")]
use crate::util::btree_set;

use crate::{
    common::{AuthorizeTarget, ForSigType},
    did::{DidKey, DidMethodKey, DidOrDidMethodKey},
    util::InclusionRule,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::BoundedBTreeSet;
use sp_runtime::traits::TryCollect;

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
    pub fn one_of<CI>(controllers: CI) -> Result<Self, PolicyValidationError>
    where
        CI: IntoIterator,
        CI::IntoIter: ExactSizeIterator,
        <CI::IntoIter as Iterator>::Item: Into<DidOrDidMethodKey>,
    {
        controllers
            .into_iter()
            .map(Into::into)
            .try_collect()
            .map_err(|_| PolicyValidationError::TooManyControllers)
            .map(Self::OneOf)
    }

    pub fn expand(&self) -> InclusionRule<PolicyExecutor> {
        let Self::OneOf(items) = self;

        InclusionRule::any_of(items.iter().copied().map(Into::into))
    }
}

/// An error occurred during `Policy` validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValidationError {
    Empty,
    TooManyControllers,
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

/// `DID` performing an action according to the policies.
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
#[scale_info(omit_prefix)]
pub struct SignatureWithNonce<N, S> {
    pub sig: S,
    pub nonce: N,
}

impl<N, S> SignatureWithNonce<N, S> {
    pub fn new(sig: S, nonce: N) -> Self {
        Self {
            sig: sig.into(),
            nonce,
        }
    }

    pub fn into_data(self) -> S {
        self.sig
    }
}

impl<N, S> ForSigType for SignatureWithNonce<N, S>
where
    S: ForSigType,
{
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
