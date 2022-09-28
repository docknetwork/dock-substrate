//! Module to store BBS+ keys and parameters.
//! This module might become irrelevant if signature params become part of a standard so they become universal
//! and BBS+ keys are moved to the DID module. Not making this change as it will be a disruption for the client
//! library. This decision must be revisited if the signature params become irrelevant.

use crate::{
    did,
    did::{Controller, Did, DidSignature, OnChainDidDetails},
    keys_and_sigs::SigValue,
    types::CurveType,
    util::IncId,
    StorageVersion,
};
use codec::{Decode, Encode};
use core::fmt::Debug;

pub use actions::*;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};
use weights::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod weights;

pub type BBSPlusParametersStorageKey = (BBSPlusParamsOwner, IncId);
pub type BBSPlusPublicKeyStorageKey = (Did, IncId);
pub type BBSPlusPublicKeyWithParams = (BBSPlusPublicKey, Option<BBSPlusParameters>);

/// DID owner of the BBSPlus parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BBSPlusParamsOwner(pub Did);

crate::impl_wrapper!(BBSPlusParamsOwner, Did, for rand use Did(rand::random()), with tests as bbs_plus_params_owner_tests);

/// Signature params in G1 for BBS+ signatures
#[derive(Encode, Decode, scale_info::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BBSPlusParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Vec<u8>>,
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

/// Public key in G2 for BBS+ signatures
#[derive(Encode, Decode, scale_info::TypeInfo, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BBSPlusPublicKey {
    /// The public key should be for the same curve as the parameters but a public key might not have
    /// parameters on chain
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
    /// The params used to generate the public key (`g2` comes from params)
    pub params_ref: Option<BBSPlusParametersStorageKey>,
}

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
    /// Maximum byte size of the public key. This depends only on the chosen elliptic curve.
    type PublicKeyMaxSize: Get<u32>;
    /// Weight consumed per byte of the public key. This will determine the cost of the transaction.
    type PublicKeyPerByteWeight: Get<Weight>;
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_event!(
    pub enum Event {
        ParamsAdded(BBSPlusParamsOwner, IncId),
        ParamsRemoved(BBSPlusParamsOwner, IncId),
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
        PublicKeyDoesntExist,
        NotOwner,
        IncorrectNonce
    }
}

decl_storage! {
    trait Store for Module<T: Config> as BBSPlusModule where T: Debug {
        /// Pair of counters where each is used to assign unique id to parameters and public keys
        /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
        /// the counters don't decrease on removal
        pub ParamsCounter get(fn params_counter):
            map hasher(blake2_128_concat) BBSPlusParamsOwner => IncId;

        /// Parameters are stored as key value (did, counter) -> params
        pub BbsPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) BBSPlusParamsOwner, hasher(identity) IncId => Option<BBSPlusParameters>;

        /// Public keys are stored as key value (did, counter) -> public key
        /// Its assumed that the public keys are always members of G2. It does impact any logic on the
        /// chain but makes up for one less storage value
        pub BbsPlusKeys get(fn get_key):
            double_map hasher(blake2_128_concat) Did, hasher(identity) IncId => Option<BBSPlusPublicKey>;

        pub Version get(fn version): StorageVersion;
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
        const PublicKeyMaxSize: u32 = T::ParamsMaxSize::get();
        const PublicKeyPerByteWeight: Weight = T::PublicKeyPerByteWeight::get();

        // Note: The weights for the dispatchables below consider only the major contributions, i.e. storage
        // reads and writes, signature verifications and any major contributors to the size of the arguments.
        // Weights are not yet determined by benchmarks and thus ignore processing time and also event storage
        // cost

        #[weight = SubstrateWeight::<T>::add_params(&params, signature)]
        pub fn add_params(
            origin,
            params: AddBBSPlusParams<T>,
            signature: DidSignature<BBSPlusParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::add_params_, params, signature)
        }

        /// Add a BBS+ public key. Only the DID controller can add key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module but only by calling `remove_public_key` of this module.
        #[weight = SubstrateWeight::<T>::add_public(&public_key, signature)]
        pub fn add_public_key(
            origin,
            public_key: AddBBSPlusPublicKey<T>,
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // Only controller can add a key

            <did::Pallet<T>>::try_exec_signed_action_from_controller(Self::add_public_key_, public_key, signature)
        }

        #[weight = SubstrateWeight::<T>::remove_params(&remove, signature)]
        pub fn remove_params(
            origin,
            remove: RemoveBBSPlusParams<T>,
            signature: DidSignature<BBSPlusParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::remove_params_, remove, signature)
        }

        /// Remove BBS+ public key. Only the DID controller can remove key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module.
        #[weight = SubstrateWeight::<T>::remove_public(&remove, signature)]
        pub fn remove_public_key(
            origin,
            remove: RemoveBBSPlusPublicKey<T>,
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            <did::Pallet<T>>::try_exec_signed_action_from_controller(Self::remove_public_key_, remove, signature)
        }

        fn on_runtime_upgrade() -> Weight {
            T::DbWeight::get().reads(1) + if Self::version() == StorageVersion::SingleKey {
                let weight = crate::migrations::bbs_plus::single_key::migrate_to_multi_key::<T>();
                Version::put(StorageVersion::MultiKey);

                T::DbWeight::get().writes(1) + weight
            } else {
                0
            }
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn add_params(
        add_params: &AddBBSPlusParams<T>,
        DidSignature { sig, .. }: &DidSignature<BBSPlusParamsOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_params_sr25519,
            SigValue::Ed25519(_) => Self::add_params_ed25519,
            SigValue::Secp256k1(_) => Self::add_params_secp256k1,
        })(
            add_params.params.bytes.len() as u32,
            add_params.params.label.as_ref().map_or(0, |v| v.len()) as u32,
        )
    }

    fn add_public(
        public_key: &AddBBSPlusPublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_public_sr25519,
            SigValue::Ed25519(_) => Self::add_public_ed25519,
            SigValue::Secp256k1(_) => Self::add_public_secp256k1,
        })(public_key.key.bytes.len() as u32)
    }

    fn remove_params(
        _: &RemoveBBSPlusParams<T>,
        DidSignature { sig, .. }: &DidSignature<BBSPlusParamsOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_params_sr25519,
            SigValue::Ed25519(_) => Self::remove_params_ed25519,
            SigValue::Secp256k1(_) => Self::remove_params_secp256k1,
        })()
    }

    fn remove_public(
        _: &RemoveBBSPlusPublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<Controller>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_public_sr25519,
            SigValue::Ed25519(_) => Self::remove_public_ed25519,
            SigValue::Secp256k1(_) => Self::remove_public_secp256k1,
        })()
    }
}
