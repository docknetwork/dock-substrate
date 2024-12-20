#[cfg(feature = "serde")]
use crate::util::serde_hex;
use crate::{
    common::{
        self, signatures::ForSigType, Limits, Policy, PolicyExecutor, SignatureWithNonce,
        TypesAndLimits,
    },
    did::{self, DidOrDidMethodKeySignature},
    util::{Action, Associated, InclusionRule, NonceError, StorageRef, WithNonce},
};
use alloc::collections::BTreeSet;
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::{Index, RangeFull};
use sp_std::{marker::PhantomData, vec::Vec};

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
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct RevocationRegistryId(
    #[cfg_attr(feature = "serde", serde(with = "serde_hex"))] pub [u8; 32],
);

impl Index<RangeFull> for RevocationRegistryId {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

impl<T: TypesAndLimits> Associated<T> for RevocationRegistryId {
    type Value = RevocationRegistry<T>;
}

impl<T: Config> StorageRef<T> for RevocationRegistryId {
    fn try_mutate_associated<F, R, E>(self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Option<RevocationRegistry<T>>) -> Result<R, E>,
    {
        Registries::<T>::try_mutate_exists(self, f)
    }

    fn view_associated<F, R>(self, f: F) -> R
    where
        F: FnOnce(Option<RevocationRegistry<T>>) -> R,
    {
        f(Registries::<T>::get(self))
    }
}

crate::hex_debug!(RevocationRegistryId);
crate::impl_wrapper!(RevocationRegistryId([u8; 32]));

/// Points to a revocation which may or may not exist in a registry.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct RevokeId(#[cfg_attr(feature = "serde", serde(with = "serde_hex"))] pub [u8; 32]);

impl Index<RangeFull> for RevokeId {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

crate::hex_debug!(RevokeId);
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
pub struct RevocationRegistry<T: Limits> {
    /// Who is allowed to update this registry.
    pub policy: Policy<T>,
    /// true: credentials can be revoked, but not un-revoked and the registry can't be removed either
    /// false: credentials can be revoked and un-revoked
    pub add_only: bool,
}

impl<T: Limits> RevocationRegistry<T> {
    fn expand_policy(&self) -> Option<InclusionRule<PolicyExecutor>> {
        Some(self.policy.expand())
    }
}

#[frame_support::pallet]
pub mod pallet {
    use self::common::PolicyExecutor;

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
        RegistryAdded(RevocationRegistryId),
        /// Some items were revoked from given registry id
        RevokedInRegistry(RevocationRegistryId),
        /// Some items were un-revoked from given registry id
        UnrevokedInRegistry(RevocationRegistryId),
        /// Registry with given id removed
        RegistryRemoved(RevocationRegistryId),
    }

    /// Revocation Error
    #[pallet::error]
    pub enum Error<T> {
        /// A revocation registry with that name already exists.
        RegExists,
        /// A revocation registry with the provided identifier doesnt exist.
        RegistryDoesntExist,
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
    pub type Registries<T: Config> =
        StorageMap<_, Blake2_128Concat, RevocationRegistryId, RevocationRegistry<T>>;

    /// The single global revocation set
    // double_map requires and explicit hasher specification for the second key. blake2_256 is
    // the default.
    #[pallet::storage]
    #[pallet::getter(fn get_revocation_status)]
    pub type Revocations<T> =
        StorageDoubleMap<_, Blake2_128Concat, RevocationRegistryId, Blake2_256, RevokeId, ()>;

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

            add_registry
                .modify_removable(Self::new_registry_)
                .map_err(Into::into)
        }

        /// Create some revocations according to the `revoke` command.
        ///
        /// # Errors
        ///
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `revoke.registry_id`.
        #[pallet::weight(SubstrateWeight::<T>::revoke(revoke, &proof[0]))]
        pub fn revoke(
            origin: OriginFor<T>,
            revoke: RevokeRaw<T>,
            proof: Vec<
                SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
            >,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            revoke
                .multi_signed(proof)
                .execute_view(Self::revoke_, RevocationRegistry::expand_policy)
                .map_err(Into::into)
        }

        /// Delete some revocations according to the `unrevoke` command.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `unrevoke.registry_id`.
        #[pallet::weight(SubstrateWeight::<T>::unrevoke(unrevoke, &proof[0]))]
        pub fn unrevoke(
            origin: OriginFor<T>,
            unrevoke: UnRevokeRaw<T>,
            proof: Vec<
                SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
            >,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            unrevoke
                .multi_signed(proof)
                .execute_view(Self::unrevoke_, RevocationRegistry::expand_policy)
                .map_err(Into::into)
        }

        /// Delete an entire registry. Deletes all revocations within the registry, as well as
        /// registry metadata. Once the registry is deleted, it can be reclaimed by any party using
        /// a call to `new_registry`.
        ///
        /// # Errors
        ///
        /// Returns an error if the registry referenced by `revoke.registry_id` is `add_only`.
        ///
        ///
        /// Returns an error if `proof` does not satisfy the policy requirements of the registry
        /// referenced by `removal.registry_id`.
        #[pallet::weight(SubstrateWeight::<T>::remove_registry(&proof[0]))]
        pub fn remove_registry(
            origin: OriginFor<T>,
            removal: RemoveRegistryRaw<T>,
            proof: Vec<
                SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
            >,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            removal
                .multi_signed(proof)
                .execute_removable(Self::remove_registry_, |opt| {
                    opt.and_then(RevocationRegistry::expand_policy)
                })
                .map_err(Into::into)
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn revoke(
        revoke: &RevokeRaw<T>,
        sig: &SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
    ) -> Weight {
        let len = revoke.len();

        sig.weight_for_sig_type::<T>(
            || Self::revoke_sr25519(len),
            || Self::revoke_ed25519(len),
            || Self::revoke_secp256k1(len),
        )
    }

    fn unrevoke(
        unrevoke: &UnRevokeRaw<T>,
        sig: &SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
    ) -> Weight {
        let len = unrevoke.len();

        sig.weight_for_sig_type::<T>(
            || Self::unrevoke_sr25519(len),
            || Self::unrevoke_ed25519(len),
            || Self::unrevoke_secp256k1(len),
        )
    }

    fn remove_registry(
        sig: &SignatureWithNonce<T::BlockNumber, DidOrDidMethodKeySignature<PolicyExecutor>>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_registry_sr25519,
            Self::remove_registry_ed25519,
            Self::remove_registry_secp256k1,
        )
    }
}
