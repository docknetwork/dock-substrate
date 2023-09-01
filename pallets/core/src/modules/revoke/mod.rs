use crate as dock;
use crate::{
    common::{
        DidSignatureWithNonce, HasPolicy, MaxPolicyControllers, Policy, SigValue, StorageVersion,
        ToStateChange,
    },
    did::{self},
    util::{Action, NonceError, WithNonce},
};
use alloc::collections::BTreeSet;
use codec::{Decode, Encode};
use sp_std::{fmt::Debug, marker::PhantomData};
use sp_std::vec::Vec;

pub use actions::*;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
    weights::Weight,
};
use frame_system::{self as system, ensure_signed};
use sp_std::prelude::*;
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

/// Metadata about a revocation scope.
#[derive(PartialEq, Eq, Encode, Decode, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Registry {
    /// Who is allowed to update this registry.
    pub policy: Policy,
    /// true: credentials can be revoked, but not un-revoked and the registry can't be removed either
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

impl HasPolicy for Registry {
    fn policy(&self) -> &Policy {
        &self.policy
    }
}

pub trait Config: MaxPolicyControllers + system::Config + did::Config {
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
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
        /// A revocation registry with that name already exists.
        RegExists,
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

        /// The single global revocation set
        // double_map requires and explicit hasher specification for the second key. blake2_256 is
        // the default.
        Revocations get(fn get_revocation_status):
            double_map hasher(blake2_128_concat) dock::revoke::RegistryId, hasher(opaque_blake2_256) dock::revoke::RevokeId => Option<()>;

        pub Version get(fn version): StorageVersion;
    }
    add_extra_genesis {
        build(|_| {
            Version::put(StorageVersion::MultiKey);
        })
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
        #[weight = SubstrateWeight::<T>::new_registry(add_registry.new_registry.policy.len())]
        pub fn new_registry(
            origin,
            add_registry: AddRegistry
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::new_registry_(add_registry)?;
            Ok(())
        }

        /// Create some revocations according to the `revoke` command.
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
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(Self::revoke_, revoke, proof)?;
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
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_registry(Self::unrevoke_, unrevoke, proof)?;
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
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_registry(Self::remove_registry_, removal, proof)?;
            Ok(())
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn revoke(DidSignatureWithNonce { sig, .. }: &DidSignatureWithNonce<T>) -> fn(u32) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::revoke_sr25519,
            SigValue::Ed25519(_) => Self::revoke_ed25519,
            SigValue::Secp256k1(_) => Self::revoke_secp256k1,
        }
    }

    fn unrevoke(DidSignatureWithNonce { sig, .. }: &DidSignatureWithNonce<T>) -> fn(u32) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::unrevoke_sr25519,
            SigValue::Ed25519(_) => Self::unrevoke_ed25519,
            SigValue::Secp256k1(_) => Self::unrevoke_secp256k1,
        }
    }

    fn remove_registry(DidSignatureWithNonce { sig, .. }: &DidSignatureWithNonce<T>) -> Weight {
        (match sig.sig {
            SigValue::Sr25519(_) => Self::remove_registry_sr25519,
            SigValue::Ed25519(_) => Self::remove_registry_ed25519,
            SigValue::Secp256k1(_) => Self::remove_registry_secp256k1,
        }())
    }
}
