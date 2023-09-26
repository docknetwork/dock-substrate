use frame_support::{CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound};
use sp_std::{borrow::Borrow, fmt::Debug};

use super::{Limits, SigValue, ToStateChange, ED25519_WEIGHT, SECP256K1_WEIGHT, SR25519_WEIGHT};
#[cfg(feature = "serde")]
use crate::util::btree_set;
use crate::{
    common::Types,
    did,
    did::{Did, DidSignature},
    util::{NonceError, WithNonce},
};
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    ensure,
    weights::{RuntimeDbWeight, Weight},
    BoundedBTreeSet,
};
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
        BoundedBTreeSet<Did, T::MaxPolicyControllers>,
    ),
}

impl<T: Limits> Policy<T> {
    /// Instantiates `Policy::OneOf` from the given iterator of controllers.
    pub fn one_of(
        controllers: impl IntoIterator<
            IntoIter = impl ExactSizeIterator<Item = impl Borrow<Did>>,
            Item = impl Borrow<Did>,
        >,
    ) -> Result<Self, PolicyValidationError> {
        controllers
            .into_iter()
            .map(|did| *did.borrow())
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
        mut action: S,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: crate::did::Config,
        V: HasPolicy<T>,
        F: FnOnce(S, &mut Option<V>) -> Result<R, E>,
        WithNonce<T, S>: ToStateChange<T>,
        E: From<PolicyExecutionError> + From<did::Error<T>> + From<NonceError>,
    {
        let data = entity.take().ok_or(PolicyExecutionError::NoEntity)?;
        // check the signer set satisfies policy
        match &data.policy() {
            Policy::OneOf(controllers) => {
                ensure!(
                    proof.len() == 1 && controllers.contains(&proof[0].sig.did),
                    PolicyExecutionError::NotAuthorized
                );
            }
        }

        let mut new_did_details = Vec::with_capacity(proof.len());
        // check each signature is valid over payload and signed by the claimed signer
        for DidSignatureWithNonce { sig, nonce } in proof {
            let signer = sig.did;

            // Check if nonce is valid and increase it
            let mut did_detail = did::Pallet::<T>::onchain_did_details(&signer)?;
            did_detail
                .try_update(nonce)
                .map_err(|_| PolicyExecutionError::IncorrectNonce)?;

            let action_with_nonce = WithNonce::new_with_nonce(action, nonce);
            // Verify signature
            let valid =
                did::Pallet::<T>::verify_sig_from_auth_or_control_key(&action_with_nonce, &sig)?;
            action = action_with_nonce.into_data();

            ensure!(valid, PolicyExecutionError::NotAuthorized);
            new_did_details.push((signer, did_detail));
        }

        let mut owned_data_opt = Some(data);
        let res = f(action, &mut owned_data_opt)?;
        *entity = owned_data_opt;

        // The nonce of each DID must be updated
        for (signer, did_details) in new_did_details {
            did::Pallet::<T>::insert_did_details(signer, did_details);
        }

        Ok(res)
    }
}

/// Collection of signatures sent by different DIDs.
#[derive(PartialEq, Eq, Encode, Decode, Clone, DebugNoBound, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DidSignatureWithNonce<T>
where
    T: Types,
{
    /// `DID`'s signature
    pub sig: DidSignature<Did>,
    /// Nonce used to make the above signature
    pub nonce: T::BlockNumber,
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug, Default)]
struct SigTypes<V> {
    sr: V,
    ed: V,
    secp: V,
}

impl<T: Types> DidSignatureWithNonce<T> {
    /// Return counts of different signature types in given `DidSignatureWithNonce` as 3-Tuple as (no. of Sr22519 sigs,
    /// no. of Ed25519 Sigs, no. of Secp256k1 sigs). Useful for weight calculation and thus the return
    /// type is in `Weight` but realistically, it should fit in a u8
    fn count_sig_types(
        auths: impl IntoIterator<Item = impl Borrow<DidSignatureWithNonce<T>>>,
    ) -> SigTypes<u64> {
        let mut counts = SigTypes::default();

        for auth in auths {
            let counter = match auth.borrow().sig.sig {
                SigValue::Sr25519(_) => &mut counts.sr,
                SigValue::Ed25519(_) => &mut counts.ed,
                SigValue::Secp256k1(_) => &mut counts.secp,
            };

            *counter += 1;
        }

        counts
    }

    /// Computes weight of the given `DidSignatureWithNonce`. Considers the no. and types of signatures and no. of reads. Disregards
    /// message size as messages are hashed giving the same output size and hashing itself is very cheap.
    /// The extrinsic using it might decide to consider adding some weight proportional to the message size.
    pub fn auth_weight(
        auths: impl IntoIterator<Item = impl Borrow<DidSignatureWithNonce<T>>>,
        db_weights: RuntimeDbWeight,
    ) -> Weight {
        let SigTypes { sr, ed, secp } = Self::count_sig_types(auths);

        db_weights
            .reads(sr + ed + secp)
            .saturating_add(SR25519_WEIGHT.saturating_mul(sr))
            .saturating_add(ED25519_WEIGHT.saturating_mul(ed))
            .saturating_add(SECP256K1_WEIGHT.saturating_mul(secp))
    }
}

/// Denotes an entity which has an associated `Policy`.
pub trait HasPolicy<T: Limits> {
    /// Returns underlying `Policy`.
    fn policy(&self) -> &Policy<T>;
}
