use crate as dock;
use crate::{
    did::{self, Did, DidSignature},
    keys_and_sigs::{SigValue, ED25519_WEIGHT, SECP256K1_WEIGHT, SR25519_WEIGHT},
    util::{NonceError, WithNonce},
    Action, StorageVersion, ToStateChange,
};
use alloc::collections::BTreeSet;
use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use sp_std::vec::Vec;

pub use actions::*;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    ensure,
    traits::Get,
    weights::{RuntimeDbWeight, Weight},
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;
use weights::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod r#impl;
#[cfg(test)]
pub mod tests;
mod weights;

/// Points to an on-chain revocation registry.
pub type RegistryId = [u8; 32];

/// Points to a revocation which may or may not exist in a registry.
pub type RevokeId = [u8; 32];

/// Collection of signatures sent by different DIDs.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DidSigs<T: frame_system::Config> {
    /// Signature by DID
    pub sig: DidSignature<Did>,
    /// Nonce used to make the above signature
    pub nonce: T::BlockNumber,
}

/// Authorization logic for a registry.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Policy {
    /// Set of dids allowed to modify a registry.
    OneOf(BTreeSet<Did>),
}

impl Default for Policy {
    fn default() -> Self {
        Self::OneOf(Default::default())
    }
}

impl Policy {
    /// Check for user error in the construction of self.
    /// if self is invalid, return `false`, else return `true`.
    fn valid(&self) -> bool {
        self.len() != 0
    }

    fn len(&self) -> u32 {
        match self {
            Self::OneOf(controllers) => controllers.len() as u32,
        }
    }
}

/// Metadata about a revocation scope.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Registry {
    /// Who is allowed to update this registry.
    pub policy: Policy,
    /// true: credentials can be revoked, but not un-revoked and the registry can't be removed either
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

/// Return counts of different signature types in given `DidSigs` as 3-Tuple as (no. of Sr22519 sigs,
/// no. of Ed25519 Sigs, no. of Secp256k1 sigs). Useful for weight calculation and thus the return
/// type is in `Weight` but realistically, it should fit in a u8
fn count_sig_types<T: frame_system::Config>(auth: &[DidSigs<T>]) -> (Weight, Weight, Weight) {
    let mut sr = 0;
    let mut ed = 0;
    let mut secp = 0;
    for a in auth.iter() {
        match a.sig.sig {
            SigValue::Sr25519(_) => sr += 1,
            SigValue::Ed25519(_) => ed += 1,
            SigValue::Secp256k1(_) => secp += 1,
        }
    }
    (sr, ed, secp)
}

/// Computes weight of the given `DidSigs`. Considers the no. and types of signatures and no. of reads. Disregards
/// message size as messages are hashed giving the same output size and hashing itself is very cheap.
/// The extrinsic using it might decide to consider adding some weight proportional to the message size.
pub fn get_weight_for_did_sigs<T: frame_system::Config>(
    auth: &[DidSigs<T>],
    db_weights: RuntimeDbWeight,
) -> Weight {
    let (sr, ed, secp) = count_sig_types(auth);
    (db_weights.reads(auth.len() as u64)
        + (sr * SR25519_WEIGHT)
        + (ed * ED25519_WEIGHT)
        + (secp * SECP256K1_WEIGHT)) as Weight
}

pub trait Config: system::Config + did::Config {
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
    type MaxControllers: Get<u32>;
}

decl_event!(
    pub enum Event {
        /// Registry with given id created
        RegistryAdded(RegistryId),
        /// Some items were revoked from given registry id
        RevokedInRegistry(RegistryId),
        /// Some items were un-revoked from given registry id
        UnrevokedInRegistry(RegistryId),
        /// Registry with given id removed
        RegistryRemoved(RegistryId),
    }
);

decl_error! {
    /// Revocation Error
    pub enum RevErr for Module<T: Config> where T: Debug {
        /// The authorization policy provided was illegal.
        InvalidPolicy,
        /// Proof of authorization does not meet policy requirements.
        NotAuthorized,
        /// A revocation registry with that name already exists.
        RegExists,
        /// A revocation registry with that name does not exist.
        NoReg,
        /// nonce is incorrect. This is related to replay protection.
        IncorrectNonce,
        /// Too many controllers specified.
        TooManyControllers,
        /// This registry is marked as add_only. Deletion of revocations is not allowed. Deletion of
        /// the registry is not allowed.
        AddOnly,
        /// Action is empty.
        EmptyPayload
    }
}

impl<T: Config + Debug> From<NonceError> for RevErr<T> {
    fn from(NonceError::IncorrectNonce: NonceError) -> Self {
        Self::IncorrectNonce
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Revoke where T: Debug {
        /// Registry metadata
        pub(crate) Registries get(fn get_revocation_registry):
            map hasher(blake2_128_concat) dock::revoke::RegistryId => Option<Registry>;

        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        /// The single global revocation set
        Revocations get(fn get_revocation_status):
            double_map hasher(blake2_128_concat) dock::revoke::RegistryId, hasher(opaque_blake2_256) dock::revoke::RevokeId => Option<()>;

        pub Version get(fn version): StorageVersion;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        fn deposit_event() = default;

        type Error = RevErr<T>;

        /// Create a new revocation registry named `id` with `registry` metadata.
        ///
        /// # Errors
        ///
        /// Returns an error if `id` is already in use as a registry id.
        ///
        /// Returns an error if `registry.policy` is invalid.
        #[weight = SubstrateWeight::<T>::new_registry(add_registry.registry.policy.len())]
        pub fn new_registry(
            origin,
            add_registry: AddRegistry
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::new_registry_(add_registry)?;
            Ok(())
        }

        /// Create some revocations according to the `revoke`` command.
        ///
        /// # Errors
        ///
        /// Returns an error if `revoke.last_modified` does not match the block number when the
        /// registry referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `revoke.registry_id`.
        #[weight = SubstrateWeight::<T>::revoke(&proof[0])(revoke.len())]
        pub fn revoke(
            origin,
            revoke: dock::revoke::RevokeRaw<T>,
            proof: Vec<DidSigs<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(revoke, proof, Self::revoke_)?;
            Ok(())
        }

        /// Delete some revocations according to the `unrevoke` command.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `unrevoke.last_modified` does not match the block number when the
        /// registry referenced by `revoke.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `unrevoke.registry_id`.
        #[weight = SubstrateWeight::<T>::unrevoke(&proof[0])(unrevoke.len())]
        pub fn unrevoke(
            origin,
            unrevoke: dock::revoke::UnRevokeRaw<T>,
            proof: Vec<DidSigs<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(unrevoke, proof, Self::unrevoke_)?;
            Ok(())
        }

        /// Delete an entire registry. Deletes all revocations within the registry, as well as
        /// registry metadata. Once the registry is deleted, it can be reclaimed by any party using
        /// a call to `new_registry`.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        /// Returns an error if `removal.last_modified` does not match the block number when the
        /// registry referenced by `removal.registry_id` was last modified.
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `removal.registry_id`.
        #[weight = SubstrateWeight::<T>::remove_registry(&proof[0])]
        pub fn remove_registry(
            origin,
            removal: dock::revoke::RemoveRegistryRaw<T>,
            proof: Vec<DidSigs<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_registry(removal, proof, Self::remove_registry_)?;
            Ok(())
        }

        fn on_runtime_upgrade() -> Weight {
            T::DbWeight::get().reads(1) + if Self::version() == StorageVersion::SingleKey {
                let weight = crate::migrations::revoke::single_key::migrate_to_multi_key::<T>();
                Version::put(StorageVersion::MultiKey);

                T::DbWeight::get().writes(1) + weight
            } else {
                0
            }
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn revoke(DidSigs { sig, .. }: &DidSigs<T>) -> fn(u32) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::revoke_sr25519,
            SigValue::Ed25519(_) => Self::revoke_ed25519,
            SigValue::Secp256k1(_) => Self::revoke_secp256k1,
        }
    }

    fn unrevoke(DidSigs { sig, .. }: &DidSigs<T>) -> fn(u32) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::unrevoke_sr25519,
            SigValue::Ed25519(_) => Self::unrevoke_ed25519,
            SigValue::Secp256k1(_) => Self::unrevoke_secp256k1,
        }
    }

    fn remove_registry(DidSigs { sig, .. }: &DidSigs<T>) -> Weight {
        (match sig.sig {
            SigValue::Sr25519(_) => Self::remove_registry_sr25519,
            SigValue::Ed25519(_) => Self::remove_registry_ed25519,
            SigValue::Secp256k1(_) => Self::remove_registry_secp256k1,
        })()
    }
}
