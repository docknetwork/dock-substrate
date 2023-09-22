#[cfg(feature = "serde")]
use crate::util::hex;
use crate::{
    common::{self, DidSignatureWithNonce, HasPolicy, Limits, Policy, SigValue, ToStateChange},
    did::{self},
    util::{Action, NonceError, WithNonce},
};
use alloc::collections::BTreeSet;
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::{Index, RangeFull};
use sp_std::{fmt::Debug, marker::PhantomData, vec::Vec};

use frame_support::{dispatch::DispatchResult, ensure, weights::Weight, DebugNoBound};
use frame_system::ensure_signed;
use sp_std::prelude::*;
use weights::*;

pub use actions::*;
pub use pallet::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod r#impl;
#[cfg(test)]
pub mod tests;
mod weights;

/// Points to an on-chain revocation registry.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct RegistryId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

impl Index<RangeFull> for RegistryId {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

crate::impl_wrapper!(RegistryId([u8; 32]));

/// Points to a revocation which may or may not exist in a registry.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct RevokeId(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

impl Index<RangeFull> for RevokeId {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

crate::impl_wrapper!(RevokeId([u8; 32]));

/// Metadata about a revocation scope.
#[derive(
    PartialEq, Eq, Encode, Decode, Clone, DebugNoBound, MaxEncodedLen, scale_info_derive::TypeInfo,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct Registry<T: Limits> {
    /// Who is allowed to update this registry.
    pub policy: Policy<T>,
    /// true: credentials can be revoked, but not un-revoked and the registry can't be removed either
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

impl<T: Limits> HasPolicy<T> for Registry<T> {
    fn policy(&self) -> &Policy<T> {
        &self.policy
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {
        /// The overarching event type.
        type Event: From<Event>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    #[pallet::event]
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

    /// Revocation Error
    #[pallet::error]
    pub enum Error<T> {
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
        EmptyPayload,
    }

    impl<T: Config> From<NonceError> for Error<T> {
        fn from(NonceError::IncorrectNonce: NonceError) -> Self {
            Self::IncorrectNonce
        }
    }

    /// Registry metadata
    #[pallet::storage]
    #[pallet::getter(fn get_revocation_registry)]
    pub type Registries<T: Config> = StorageMap<_, Blake2_128Concat, RegistryId, Registry<T>>;

    /// The single global revocation set
    // double_map requires and explicit hasher specification for the second key. blake2_256 is
    // the default.
    #[pallet::storage]
    #[pallet::getter(fn get_revocation_status)]
    pub type Revocations<T> =
        StorageDoubleMap<_, Blake2_128Concat, RegistryId, Blake2_256, RevokeId, ()>;

    #[pallet::storage]
    #[pallet::getter(fn version)]
    pub type Version<T> = StorageValue<_, common::StorageVersion, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub _marker: PhantomData<T>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                _marker: PhantomData,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            Version::<T>::put(common::StorageVersion::MultiKey);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new revocation registry named `id` with `registry` metadata.
        ///
        /// # Errors
        ///
        /// Returns an error if `id` is already in use as a registry id.
        ///
        /// Returns an error if `registry.policy` is invalid.
        #[pallet::weight(SubstrateWeight::<T>::new_registry(add_registry.new_registry.policy.len()))]
        pub fn new_registry(origin: OriginFor<T>, add_registry: AddRegistry<T>) -> DispatchResult {
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
        #[pallet::weight(SubstrateWeight::<T>::revoke(&proof[0])(revoke.len()))]
        pub fn revoke(
            origin: OriginFor<T>,
            revoke: RevokeRaw<T>,
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
        #[pallet::weight(SubstrateWeight::<T>::unrevoke(&proof[0])(unrevoke.len()))]
        pub fn unrevoke(
            origin: OriginFor<T>,
            unrevoke: UnRevokeRaw<T>,
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
        #[pallet::weight(SubstrateWeight::<T>::remove_registry(&proof[0]))]
        pub fn remove_registry(
            origin: OriginFor<T>,
            removal: RemoveRegistryRaw<T>,
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_registry(Self::remove_registry_, removal, proof)?;
            Ok(())
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
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
