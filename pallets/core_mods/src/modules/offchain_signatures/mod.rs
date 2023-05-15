//! Module to store offchain signature keys and parameters for different signature schemes.
//! Currently can be either `BBS`, `BBS+` or `Pointcheval-Sanders`.

use crate::{
    did,
    did::{Controller, Did, DidSignature},
    keys_and_sigs::SigValue,
    util::IncId,
    StorageVersion,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use sp_std::prelude::*;

use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use weights::*;

pub use actions::*;
pub use params::*;
pub use public_key::*;
pub use schemas::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod migration;
mod params;
mod public_key;
mod schemas;
#[cfg(test)]
mod tests;
mod weights;

/// The module's configuration trait.
pub trait Config: system::Config + did::Config {
    /// Maximum size of the label
    type LabelMaxSize: Get<u32>;
    /// Weight consumed per byte of the label.
    type LabelPerByteWeight: Get<Weight>;
    /// Maximum byte size of the parameters. This depends on the chosen elliptic curve and the number
    /// of messages that can be signed.
    type ParamsMaxSize: Get<u32>;
    /// Weight consumed per byte of the params. This will determine the cost of the transaction.
    type ParamsPerByteWeight: Get<Weight>;
    /// Maximum byte size of the `BBS`/`BBS+` (fixed) public key. This depends only on the chosen elliptic curve.
    type BBSPublicKeyMaxSize: Get<u32>;
    /// Maximum byte size of the `PS` public key. This depends on the chosen elliptic curve and the number
    /// of messages that can be signed.
    type PSPublicKeyMaxSize: Get<u32>;
    /// Weight consumed per byte of the public key. This will determine the cost of the transaction.
    type PublicKeyPerByteWeight: Get<Weight>;
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_event!(
    pub enum Event {
        ParamsAdded(SignatureParamsOwner, IncId),
        ParamsRemoved(SignatureParamsOwner, IncId),
        KeyAdded(Did, IncId),
        KeyRemoved(Did, IncId),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> where T: Debug {
        LabelTooBig,
        ParamsTooBig,
        PublicKeyTooBig,
        ParamsDontExist,
        IncorrectParamsScheme,
        PublicKeyDoesntExist,
        NotOwner,
        IncorrectNonce
    }
}

decl_storage! {
    trait Store for Module<T: Config> as OffchainSignatures where T: Debug {
        /// Pair of counters where each is used to assign unique id to parameters and public keys
        /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
        /// the counters don't decrease on removal
        pub ParamsCounter get(fn did_params_counter):
            map hasher(blake2_128_concat) SignatureParamsOwner => IncId;

        /// Signature parameters are stored as key value (did, counter) -> signature parameters
        pub SignatureParams get(fn did_public_key_params):
            double_map hasher(blake2_128_concat) SignatureParamsOwner, hasher(identity) IncId => Option<OffchainSignatureParams>;

        /// Public keys are stored as key value (did, counter) -> public key
        pub PublicKeys get(fn did_public_key):
            double_map hasher(blake2_128_concat) Did, hasher(identity) IncId => Option<OffchainPublicKey>;

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

        type Error = Error<T>;

        const LabelMaxSize: u32 = T::LabelMaxSize::get();
        const LabelPerByteWeight: Weight = T::LabelPerByteWeight::get();
        const ParamsMaxSize: u32 = T::ParamsMaxSize::get();
        const ParamsPerByteWeight: Weight = T::ParamsPerByteWeight::get();
        const BBSPublicKeyMaxSize: u32 = T::BBSPublicKeyMaxSize::get();
        const PSPublicKeyMaxSize: u32 = T::PSPublicKeyMaxSize::get();
        const PublicKeyPerByteWeight: Weight = T::PublicKeyPerByteWeight::get();

        // Note: The weights for the dispatchables below consider only the major contributions, i.e. storage
        // reads and writes, signature verifications and any major contributors to the size of the arguments.
        // Weights are not yet determined by benchmarks and thus ignore processing time and also event storage
        // cost

        #[weight = SubstrateWeight::<T>::add_params(params, signature)]
        pub fn add_params(
            origin,
            params: AddOffchainSignatureParams<T>,
            signature: DidSignature<SignatureParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::add_params_, params, signature)
        }

        /// Add new offchain signature public key. Only the DID controller can add key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module but only by calling `remove_public_key` of this module.
        #[weight = SubstrateWeight::<T>::add_public(public_key, signature)]
        pub fn add_public_key(
            origin,
            public_key: AddOffchainSignaturePublicKey<T>,
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // Only controller can add a key

            did::Pallet::<T>::try_exec_signed_action_from_controller(Self::add_public_key_, public_key, signature)
        }

        #[weight = SubstrateWeight::<T>::remove_params(remove, signature)]
        pub fn remove_params(
            origin,
            remove: RemoveOffchainSignatureParams<T>,
            signature: DidSignature<SignatureParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::remove_params_, remove, signature)
        }

        /// Remove existing offchain signature public key. Only the DID controller can remove key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module.
        #[weight = SubstrateWeight::<T>::remove_public(remove, signature)]
        pub fn remove_public_key(
            origin,
            remove: RemoveOffchainSignaturePublicKey<T>,
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_controller(Self::remove_public_key_, remove, signature)
        }

        fn on_runtime_upgrade() -> Weight {
            migration::migrate::<T, Module<T>>()
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn add_params(
        add_params: &AddOffchainSignatureParams<T>,
        DidSignature { sig, .. }: &DidSignature<SignatureParamsOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_params_sr25519,
            SigValue::Ed25519(_) => Self::add_params_ed25519,
            SigValue::Secp256k1(_) => Self::add_params_secp256k1,
        }(
            add_params.params.bytes().len() as u32,
            add_params.params.label().map_or(0, |v| v.len()) as u32,
        ))
    }

    fn add_public(
        public_key: &AddOffchainSignaturePublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_public_sr25519,
            SigValue::Ed25519(_) => Self::add_public_ed25519,
            SigValue::Secp256k1(_) => Self::add_public_secp256k1,
        }(public_key.key.bytes().len() as u32))
    }

    fn remove_params(
        _: &RemoveOffchainSignatureParams<T>,
        DidSignature { sig, .. }: &DidSignature<SignatureParamsOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_params_sr25519,
            SigValue::Ed25519(_) => Self::remove_params_ed25519,
            SigValue::Secp256k1(_) => Self::remove_params_secp256k1,
        }())
    }

    fn remove_public(
        _: &RemoveOffchainSignaturePublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_public_sr25519,
            SigValue::Ed25519(_) => Self::remove_public_ed25519,
            SigValue::Secp256k1(_) => Self::remove_public_secp256k1,
        }())
    }
}
