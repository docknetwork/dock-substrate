//! Storage for status list-related verifiable credentials:
//! - [`RevocationList2020Credential`](https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential)
//! - [`StatusList2021Credential`](https://www.w3.org/TR/vc-status-list/#statuslist2021credential).
use crate::{
    common::{signatures::ForSigType, DidSignatureWithNonce, HasPolicy},
    deposit_indexed_event, did,
    util::Action,
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

            update_credential.execute(
                |action, credential: &mut StatusListCredentialWithPolicy<T>| {
                    credential.execute(Self::update_, action, proof)
                },
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

            remove_credential.execute_removable(
                |action, credential: &mut Option<StatusListCredentialWithPolicy<T>>| {
                    HasPolicy::execute_removable(credential, Self::remove_, action, proof)
                },
            )
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            use crate::did::Did;
            use core::iter::once;

            // https://dock.subscan.io/extrinsic/26256127-1
            // https://fe.dock.io/#/explorer/query/26256127
            StatusListCredentials::<T>::insert(
                StatusListCredentialId(hex_literal::hex!("37ab4a3c68a0e5cfbc5c751890f6d0c5391ae23ddeaa8bc67a97c2abc72a6f49")),
                StatusListCredentialWithPolicy {
                    policy: crate::common::Policy::one_of(once(Did(hex_literal::hex!("4621801146b77bebe3631d9e223cda95b5411f5d98219f9945b3b17fad258daa")))).unwrap(),
                    status_list_credential:StatusListCredential::StatusList2021Credential(
                        hex_literal::hex!("1f8b0800000000000003b5925d53a3301486ff0bde4a4bc237578b6dad54ad55fcc29d1d272481065aa02494b68eff7d43b5d6d9d9bb9de52ee73d79df27e7f0a6fcc06521e84628de4f652e44c5bd7ebf6ddb5eabf7ca3aed430d387d5c53420bc1d082f7d740393d36ea8cecdbd6b8cf05120d57178c0b790b82aef3d7a9c288e229dfb44ef24889734fdbe8368a0da463cb411a3571126313db26705c2db188864ddd0588429d108a901363cb46ae8d218ab10d919518ae2411db8a76e88fb4660943f1820ebe60a51cee83af3e73bf4992ecf8aab089338ae508defe2bee4967f8c5fc079bacd302978492ae22e50b8307fee183d374ec3f65d159789d36a34b7f68547a5db33329c98b1fbcb3a6ae4ade39f38657b4e0ac2c9477b901ce1b54603a44a2136598a16a4005e05e733d5df380d383b6fe227daaba2c936e0a9f8423024d13b8214b0b1950d3ee6750f6839356e4ef5e9dcf7abf0c8c8424b8a6625e76bd84918f419a439af817603c8c360e986420e791b57457f472d6c274f38c1e436315fa1767cb25336954b52739dd72151cf88ecf449cd3fa5bc6a992b55cd6e976328fc798ddb0c9f9cbe8eefe360c78b00ce07410582fcb738ee1833c4fb7e8f996dd2c388bb2480b16c0edf5a2ddd88c733172109b2ea3ad15bdce60a53677a63557a301ca0ce32adec164f340f1e2fc55cd6f0c07a4ea30f6ed3c48dbc960dd90327e9edd829596ed9ef27897fb62e81f9640eb7f1983f2fe1b1956dca0ad030000").to_vec().try_into().unwrap()
                    )
                }
            );

            T::DbWeight::get().writes(1)
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
        sig: &DidSignatureWithNonce<T>,
        UpdateStatusListCredentialRaw { credential, .. }: &UpdateStatusListCredentialRaw<T>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            || Self::update_sr25519(credential.len()),
            || Self::update_ed25519(credential.len()),
            || Self::update_secp256k1(credential.len()),
        )
    }

    fn remove(sig: &DidSignatureWithNonce<T>) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_sr25519,
            Self::remove_ed25519,
            Self::remove_secp256k1,
        )
    }
}
