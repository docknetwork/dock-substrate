//! Storage for status list-related verifiable credentials:
//! - [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
//! - [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential).
use crate::{
    common::{DidSignatureWithNonce, Policy, PolicyExecutionError, SigValue, ToStateChange},
    deposit_indexed_event, did,
    util::{Action, NonceError, WithNonce},
};
use alloc::vec::*;
use frame_support::pallet_prelude::*;

use frame_system::ensure_signed;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod weights;

pub mod actions;
pub mod types;

pub use actions::*;
pub use pallet::*;
pub use types::*;
use weights::*;

#[frame_support::pallet]

pub mod pallet {
    use super::*;

    use frame_system::pallet_prelude::*;

    /// Error for the StatusListCredential module.
    #[pallet::error]
    pub enum Error<T> {
        /// There is already a `StatusListCredential` with the same id
        StatusListCredentialAlreadyExists,
        /// The `StatusListCredential` byte length is less than `MinStatusListCredentialSize`
        StatusListCredentialTooSmall,
        /// Action can't have an empty payload.
        EmptyPayload,
    }

    #[pallet::event]
    pub enum Event {
        /// `StatusListCredential` with the given id was created.
        StatusListCredentialCreated(StatusListCredentialId),
        /// `StatusListCredential` with the given id was updated.
        StatusListCredentialUpdated(StatusListCredentialId),
        /// `StatusListCredential` with the given id was removed.
        StatusListCredentialRemoved(StatusListCredentialId),
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {
        type Event: From<Event>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    /// Stores `StatusListCredential`s along with their modification policies.
    /// The credential itself is represented as a raw byte sequence and can be either
    /// - [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
    /// - [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential)
    #[pallet::storage]
    #[pallet::getter(fn status_list_credential)]
    pub type StatusListCredentials<T> =
        StorageMap<_, Blake2_128Concat, StatusListCredentialId, StatusListCredentialWithPolicy<T>>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Associates a new `StatusListCredentialWithPolicy` with the supplied identifier.
        /// This method doesn't ensure `StatusListCredential` is a valid `JSON-LD` object.
        #[pallet::weight(SubstrateWeight::<T>::create(credential))]
        pub fn create(
            origin: OriginFor<T>,
            id: StatusListCredentialId,
            credential: StatusListCredentialWithPolicy<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::create_(id, credential)
        }

        /// Updates `StatusListCredential` associated with the supplied identifier.
        /// This method doesn't ensure `StatusListCredential` is a valid `JSON-LD` object.
        #[pallet::weight(SubstrateWeight::<T>::update(&proof[0], update_credential))]
        pub fn update(
            origin: OriginFor<T>,
            update_credential: UpdateStatusListCredentialRaw<T>,
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_status_list_credential(
                Self::update_,
                update_credential,
                proof,
            )
        }

        /// Removes `StatusListCredential` associated with the supplied identifier.
        #[pallet::weight(SubstrateWeight::<T>::remove(&proof[0]))]
        pub fn remove(
            origin: OriginFor<T>,
            remove_credential: RemoveStatusListCredentialRaw<T>,
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_status_list_credential(
                Self::remove_,
                remove_credential,
                proof,
            )
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn create(
        StatusListCredentialWithPolicy {
            status_list_credential,
            policy,
        }: &StatusListCredentialWithPolicy<T>,
    ) -> Weight {
        <Self as WeightInfo>::create(status_list_credential.len(), policy.len())
    }

    fn update(
        DidSignatureWithNonce { sig, .. }: &DidSignatureWithNonce<T>,
        UpdateStatusListCredentialRaw { credential, .. }: &UpdateStatusListCredentialRaw<T>,
    ) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::update_sr25519(credential.len()),
            SigValue::Ed25519(_) => Self::update_ed25519(credential.len()),
            SigValue::Secp256k1(_) => Self::update_secp256k1(credential.len()),
        }
    }

    fn remove(DidSignatureWithNonce { sig, .. }: &DidSignatureWithNonce<T>) -> Weight {
        match sig.sig {
            SigValue::Sr25519(_) => Self::remove_sr25519(),
            SigValue::Ed25519(_) => Self::remove_ed25519(),
            SigValue::Secp256k1(_) => Self::remove_secp256k1(),
        }
    }
}
