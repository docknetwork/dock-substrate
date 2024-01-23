//! Module to store offchain signature keys and parameters for different signature schemes.
//! Currently can be either `BBS`, `BBS+` or `Pointcheval-Sanders`.

use crate::{
    common::{self, signatures::ForSigType},
    did,
    did::{Controller, Did, DidOrDidMethodKeySignature, OnDidRemoval},
    util::{ActionWithNonce, ActionWrapper, IncId},
};
use codec::{Decode, Encode};
use sp_std::prelude::*;

use frame_support::{
    dispatch::{DispatchResult, Weight},
    storage_alias,
    traits::Get,
};
use frame_system::ensure_signed;
use weights::*;

pub use actions::*;
pub use pallet::*;
pub use params::*;
pub use public_key::*;
pub use schemes::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod params;
mod public_key;
mod schemes;
#[cfg(test)]
mod tests;
mod weights;

#[frame_support::pallet]
pub mod pallet {

    use super::*;
    use frame_support::{pallet_prelude::*, Blake2_128Concat};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    /// The module's configuration trait.
    pub trait Config: frame_system::Config + did::Config {
        /// The overarching event type.
        type Event: From<Event>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        ParamsAdded(SignatureParamsOwner, IncId),
        ParamsRemoved(SignatureParamsOwner, IncId),
        KeyAdded(Did, IncId),
        KeyRemoved(Did, IncId),
    }

    #[pallet::error]
    pub enum Error<T> {
        ParamsDontExist,
        IncorrectParamsScheme,
        PublicKeyDoesntExist,
        NotOwner,
        IncorrectNonce,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    /// On adding new params, corresponding counter is increased by 1 but
    /// the counters don't decrease on removal.
    #[pallet::storage]
    #[pallet::getter(fn did_params_counter)]
    pub type ParamsCounter<T> =
        StorageMap<_, Blake2_128Concat, SignatureParamsOwner, IncId, ValueQuery>;

    /// Signature parameters are stored as key value (did, counter) -> signature parameters
    #[pallet::storage]
    #[pallet::getter(fn did_public_key_params)]
    pub type SignatureParams<T> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        SignatureParamsOwner,
        Identity,
        IncId,
        OffchainSignatureParams<T>,
    >;

    /// Public keys are stored as key value (did, counter) -> public key
    #[pallet::storage]
    #[pallet::getter(fn did_public_key)]
    pub type PublicKeys<T> =
        StorageDoubleMap<_, Blake2_128Concat, Did, Identity, IncId, OffchainPublicKey<T>>;

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
        #[pallet::weight(SubstrateWeight::<T>::add_params(params, signature))]
        pub fn add_params(
            origin: OriginFor<T>,
            params: AddOffchainSignatureParams<T>,
            signature: DidOrDidMethodKeySignature<SignatureParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            params
                .signed_with_signer_target(signature)?
                .execute(ActionWrapper::wrap_fn(Self::add_params_))
        }

        /// Add new offchain signature public key. Only the DID controller can add key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module but only by calling `remove_public_key` of this module.
        #[pallet::weight(SubstrateWeight::<T>::add_public(public_key, signature))]
        pub fn add_public_key(
            origin: OriginFor<T>,
            public_key: AddOffchainSignaturePublicKey<T>,
            signature: DidOrDidMethodKeySignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            public_key
                .signed(signature)
                .execute_from_controller(Self::add_public_key_)
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_params(remove, signature))]
        pub fn remove_params(
            origin: OriginFor<T>,
            remove: RemoveOffchainSignatureParams<T>,
            signature: DidOrDidMethodKeySignature<SignatureParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            remove
                .signed(signature)
                .execute_readonly(Self::remove_params_)
        }

        /// Remove existing offchain signature public key. Only the DID controller can remove key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module.
        #[pallet::weight(SubstrateWeight::<T>::remove_public(remove, signature))]
        pub fn remove_public_key(
            origin: OriginFor<T>,
            remove: RemoveOffchainSignaturePublicKey<T>,
            signature: DidOrDidMethodKeySignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            remove
                .signed(signature)
                .execute_from_controller(Self::remove_public_key_)
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let mut reads_writes = 0;

            let params: Vec<_> = {
                #[storage_alias]
                pub type SignatureParams<T: Config> = StorageDoubleMap<
                    Pallet<T>,
                    Blake2_128Concat,
                    Did,
                    Identity,
                    IncId,
                    OffchainSignatureParams<T>,
                >;

                SignatureParams::<T>::drain()
                    .map(|(did, id, params): (Did, _, _)| {
                        (SignatureParamsOwner(did.into()), id, params)
                    })
                    .collect()
            };

            reads_writes += params.len() as u64;
            frame_support::log::info!("Migrated {} offchain signature params", params.len());
            for (owner, id, params) in params {
                SignatureParams::<T>::insert(owner, id, params);
            }

            let params_counters: Vec<_> = {
                #[storage_alias]
                pub type ParamsCounter<T: Config> =
                    StorageMap<Pallet<T>, Blake2_128Concat, Did, IncId, ValueQuery>;

                ParamsCounter::<T>::drain()
                    .map(|(did, counter): (Did, _)| (SignatureParamsOwner(did.into()), counter))
                    .collect()
            };

            reads_writes += params_counters.len() as u64;
            frame_support::log::info!(
                "Migrated {} offchain signature params counters",
                params_counters.len()
            );
            for (did, counter) in params_counters {
                ParamsCounter::<T>::insert(did, counter);
            }

            let mut pks = 0;
            PublicKeys::<T>::translate_values(|key: super::public_key::OldOffchainPublicKey<T>| {
                pks += 1;

                Some(key.into())
            });
            frame_support::log::info!("Migrated {} offchain signature public keys", pks);
            reads_writes += pks;

            T::DbWeight::get().reads_writes(reads_writes, reads_writes)
        }
    }
}

impl<T: Config> OnDidRemoval for Pallet<T> {
    fn on_remove_did(did: Did) -> Weight {
        use sp_io::MultiRemovalResults;
        // TODO: limit and cursor
        let MultiRemovalResults { backend, .. } =
            PublicKeys::<T>::clear_prefix(did, u32::MAX, None);

        T::DbWeight::get().writes(backend as u64)
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn add_params(
        add_params: &AddOffchainSignatureParams<T>,
        sig: &DidOrDidMethodKeySignature<SignatureParamsOwner>,
    ) -> Weight {
        let bytes_len = add_params.params.bytes().len() as u32;
        let label_len = add_params.params.label().map_or(0, |v| v.len()) as u32;

        sig.weight_for_sig_type::<T>(
            || Self::add_params_sr25519(bytes_len, label_len),
            || Self::add_params_ed25519(bytes_len, label_len),
            || Self::add_params_secp256k1(bytes_len, label_len),
        )
    }

    fn add_public(
        public_key: &AddOffchainSignaturePublicKey<T>,
        sig: &DidOrDidMethodKeySignature<Controller>,
    ) -> Weight {
        let len = public_key.key.bytes().len() as u32;

        sig.weight_for_sig_type::<T>(
            || Self::add_public_sr25519(len),
            || Self::add_public_ed25519(len),
            || Self::add_public_secp256k1(len),
        )
    }

    fn remove_params(
        _: &RemoveOffchainSignatureParams<T>,
        sig: &DidOrDidMethodKeySignature<SignatureParamsOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_params_sr25519,
            Self::remove_params_ed25519,
            Self::remove_params_secp256k1,
        )
    }

    fn remove_public(
        _: &RemoveOffchainSignaturePublicKey<T>,
        sig: &DidOrDidMethodKeySignature<Controller>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_public_sr25519,
            Self::remove_public_ed25519,
            Self::remove_public_secp256k1,
        )
    }
}
