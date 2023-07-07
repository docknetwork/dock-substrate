use core::{borrow::Borrow, fmt::Debug};

use super::{SigValue, ToStateChange, ED25519_WEIGHT, SECP256K1_WEIGHT, SR25519_WEIGHT};
use crate::{
    did,
    did::{Did, DidSignature},
    util::{NonceError, WithNonce},
};
use alloc::{collections::BTreeSet, vec::Vec};
use codec::{Decode, Encode};
use frame_support::{
    ensure,
    traits::Get,
    weights::{RuntimeDbWeight, Weight},
};
use sp_runtime::DispatchError;

/// Authorization logic containing rules to modify some data entity.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum Policy {
    /// Set of `DID`s allowed to modify the entity.
    OneOf(BTreeSet<Did>),
}

impl Policy {
    /// Instantiates `Policy::OneOf` from the given iterator of controllers.
    pub fn one_of(controllers: impl IntoIterator<Item = impl Borrow<Did>>) -> Self {
        Self::OneOf(controllers.into_iter().map(|did| *did.borrow()).collect())
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

/// Denotes max amount of controllers per a single `Policy`.
pub trait MaxPolicyControllers {
    /// Max amount of controllers per a single `Policy`.
    type MaxPolicyControllers: Get<u32>;
}

impl Policy {
    /// Ensures given `Policy` to be valid against supplied config.
    pub fn ensure_valid<T: MaxPolicyControllers>(&self) -> Result<(), PolicyValidationError> {
        if self.is_empty() {
            Err(PolicyValidationError::Empty)?
        }
        if self.len() > T::MaxPolicyControllers::get() {
            Err(PolicyValidationError::TooManyControllers)?
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
    /// 1. Ensure that the data exists and this is not a replayed payload by checking the equality
    /// with stored block number when the data was last modified.
    /// 2. Verify that `proof` authorizes `action` according to `policy`.
    ///
    /// Returns a mutable reference to the underlying data wrapped into an option if the command is authorized,
    /// otherwise returns Err.
    pub fn try_exec_removable_action<T, V, S, F, R, E>(
        entity: &mut Option<V>,
        f: F,
        mut action: S,
        proof: Vec<DidSignatureWithNonce<T>>,
    ) -> Result<R, E>
    where
        T: did::Config + Debug,
        V: HasPolicy,
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
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct DidSignatureWithNonce<T>
where
    T: frame_system::Config,
{
    /// Signature by DID
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

impl<T: frame_system::Config> DidSignatureWithNonce<T> {
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
pub trait HasPolicy {
    /// Returns underlying `Policy`.
    fn policy(&self) -> &Policy;
}
