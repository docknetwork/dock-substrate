//! Storage for status list-related verifiable credentials:
//! - [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
//! - [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential).
use crate::{
    common::{
        DidSignatureWithNonce, MaxPolicyControllers, Policy, PolicyExecutionError, SigValue,
        ToStateChange,
    },
    deposit_indexed_event, did,
    util::{Action, NonceError, WithNonce},
};
use alloc::vec::*;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, pallet_prelude::*};
use frame_system as system;
use frame_system::ensure_signed;
use sp_std::{fmt::Debug, prelude::*};

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod weights;

pub mod actions;
pub mod types;

pub use actions::*;
pub use types::*;
use weights::*;

pub trait Config: system::Config + did::Config + MaxPolicyControllers {
    /// `StatusListCredential`s with size larger than this won't be accepted.
    type MaxStatusListCredentialSize: Get<u32>;
    /// `StatusListCredential`s with size less than this won't be accepted.
    type MinStatusListCredentialSize: Get<u32>;

    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_error! {
    /// Error for the StatusListCredential module.
    pub enum StatusListCredentialError for Module<T: Config> where T: Debug {
        /// The `StatusListCredential` byte length is greater than `MaxStatusListCredentialSize`
        StatusListCredentialTooBig,
        /// There is already a `StatusListCredential` with the same id
        StatusListCredentialAlreadyExists,
        /// The `StatusListCredential` byte length is less than `MinStatusListCredentialSize`
        StatusListCredentialTooSmall,
        /// Action can't have an empty payload.
        EmptyPayload
    }
}

decl_event! {
    pub enum Event {
        /// `StatusListCredential` with the given id was created.
        StatusListCredentialCreated(StatusListCredentialId),
        /// `StatusListCredential` with the given id was updated.
        StatusListCredentialUpdated(StatusListCredentialId),
        /// `StatusListCredential` with the given id was removed.
        StatusListCredentialRemoved(StatusListCredentialId)
    }
}

decl_storage! {
    trait Store for Module<T: Config> as Credential where T: Debug {
        /// Stores `StatusListCredential`s along with their modification policies.
        /// The credential itself is represented as a raw byte sequence and can be either
        /// - [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
        /// - [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential)
        StatusListCredentials get(fn status_list_credential): map
            hasher(blake2_128_concat) StatusListCredentialId => Option<StatusListCredentialWithPolicy>;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin, T: Debug {
        fn deposit_event() = default;

        /// Associates a new `StatusListCredentialWithPolicy` with the supplied identifier.
        /// This method doesn't ensure `StatusListCredential` is a valid `JSON-LD` object.
        #[weight = SubstrateWeight::<T>::create(credential)]
        pub fn create(
            origin,
            id: StatusListCredentialId,
            credential: StatusListCredentialWithPolicy
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::create_(id, credential)
        }

        /// Updates `StatusListCredential` associated with the supplied identifier.
        /// This method doesn't ensure `StatusListCredential` is a valid `JSON-LD` object.
        #[weight = SubstrateWeight::<T>::update(&proof[0], update_credential)]
        pub fn update(
            origin,
            update_credential: UpdateStatusListCredentialRaw<T>,
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_action_over_status_list_credential(Self::update_, update_credential, proof)
        }

        /// Removes `StatusListCredential` associated with the supplied identifier.
        #[weight = SubstrateWeight::<T>::remove(&proof[0])]
        pub fn remove(
            origin,
            remove_credential: RemoveStatusListCredentialRaw<T>,
            proof: Vec<DidSignatureWithNonce<T>>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::try_exec_removable_action_over_status_list_credential(Self::remove_, remove_credential, proof)
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn create(
        StatusListCredentialWithPolicy {
            status_list_credential,
            policy,
        }: &StatusListCredentialWithPolicy,
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
