use crate::{
    common::{CurveType, SigValue, StorageVersion},
    did,
    did::{Did, DidSignature},
    util::{Bytes, IncId},
};
pub use actions::*;
use arith_utils::DivCeil;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_std::{fmt::Debug, prelude::*};
pub use types::*;
use weights::*;

mod actions;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
mod r#impl;
#[cfg(test)]
mod tests;
mod types;
mod weights;

// The module's configuration trait.
pub trait Config: system::Config + did::Config {
    /// Maximum size of the label
    type LabelMaxSize: Get<u32>;
    /// Weight consumed per byte of the label.
    type LabelPerByteWeight: Get<Weight>;
    /// Maximum byte size of the parameters. This depends only on the chosen elliptic curve.
    type ParamsMaxSize: Get<u32>;
    /// Weight consumed per byte of the params. This will determine the cost of the transaction.
    type ParamsPerByteWeight: Get<Weight>;
    /// Maximum byte size of the public key. This depends only on the chosen elliptic curve.
    type PublicKeyMaxSize: Get<u32>;
    /// Weight consumed per byte of the public key. This will determine the cost of the transaction.
    type PublicKeyPerByteWeight: Get<Weight>;
    /// Maximum byte size of the accumulated value which is just one group element (not the number of members)
    type AccumulatedMaxSize: Get<u32>;
    /// Weight consumed per byte of accumulated.
    type AccumulatedPerByteWeight: Get<Weight>;
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_event!(
    pub enum Event {
        ParamsAdded(AccumulatorOwner, IncId),
        ParamsRemoved(AccumulatorOwner, IncId),
        KeyAdded(AccumulatorOwner, IncId),
        KeyRemoved(AccumulatorOwner, IncId),
        AccumulatorAdded(AccumulatorId, Bytes),
        AccumulatorUpdated(AccumulatorId, Bytes),
        AccumulatorRemoved(AccumulatorId),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> where T: Debug {
        LabelTooBig,
        ParamsTooBig,
        PublicKeyTooBig,
        ParamsDontExist,
        PublicKeyDoesntExist,
        AccumulatedTooBig,
        AccumulatorDoesntExist,
        AccumulatorAlreadyExists,
        NotPublicKeyOwner,
        NotAccumulatorOwner,
        IncorrectNonce,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as AccumulatorModule where T: Debug {
        pub AccumulatorOwnerCounters get(fn did_counters):
            map hasher(blake2_128_concat) AccumulatorOwner => StoredAccumulatorOwnerCounters;

        pub AccumulatorParams get(fn get_params):
            double_map hasher(blake2_128_concat) AccumulatorOwner, hasher(identity) IncId => Option<AccumulatorParameters>;

        /// Public key storage is kept separate from accumulator storage and a single key can be used to manage
        /// several accumulators. It is assumed that whoever (DID) owns the public key, owns the accumulator as
        /// well and only that DID can update accumulator.
        pub AccumulatorKeys get(fn get_key):
            double_map hasher(blake2_128_concat) AccumulatorOwner, hasher(identity) IncId => Option<AccumulatorPublicKey>;

        /// Stores latest accumulator as key value: accumulator id -> (created_at, last_updated_at, Accumulator)
        /// `created_at` is the block number when the accumulator was created and is intended to serve as a starting
        /// point for anyone looking for all updates to the accumulator. `last_updated_at` is the block number when
        /// the last update was sent. `created_at` and `last_updated_at` together indicate which blocks should be
        /// considered for finding accumulator updates.
        /// Historical values and updates are persisted as events indexed with the accumulator id. The reason for
        /// not storing past values is to save storage in chain state. Another option could have been to store
        /// block numbers for the updates so that each block from `created_at` doesn't need to be scanned but
        /// even that requires large storage as we expect millions of updates.
        /// Just keeping the latest accumulated value allows for any potential on chain verification as well.
        pub Accumulators get(fn get_accumulator):
            map hasher(blake2_128_concat) AccumulatorId => Option<AccumulatorWithUpdateInfo<T>>;

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
        const PublicKeyMaxSize: u32 = T::ParamsMaxSize::get();
        const PublicKeyPerByteWeight: Weight = T::PublicKeyPerByteWeight::get();
        const AccumulatedMaxSize: u32 = T::AccumulatedMaxSize::get();
        const AccumulatedPerByteWeight: Weight = T::AccumulatedPerByteWeight::get();

        // Note: The weights for the dispatchables below consider only the major contributions, i.e. storage
        // reads and writes, signature verifications and any major contributors to the size of the arguments.
        // Weights are not yet determined by benchmarks and thus ignore processing time and also event storage
        // cost

        #[weight = SubstrateWeight::<T>::add_params(params, signature)]
        pub fn add_params(
            origin,
            params: AddAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::add_params_, params, signature)
        }

        #[weight = SubstrateWeight::<T>::add_public(public_key, signature)]
        pub fn add_public_key(
            origin,
            public_key: AddAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::add_public_key_, public_key, signature)
        }

        #[weight = SubstrateWeight::<T>::remove_params(remove, signature)]
        pub fn remove_params(
            origin,
            remove: RemoveAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::remove_params_, remove, signature)
        }

        #[weight = SubstrateWeight::<T>::remove_public(remove, signature)]
        pub fn remove_public_key(
            origin,
            remove: RemoveAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::remove_public_key_, remove, signature)
        }

        /// Add a new accumulator with the initial accumulated value. Each accumulator has a unique id and it
        /// refers to a public key. It is assumed that the accumulator is owned by the DID that owns the public key.
        /// It logs an event with the accumulator id and accumulated value. For each new accumulator, its creation block
        /// is recorded in state to indicate from which block, the chain should be scanned for the accumulator's updates.
        /// Note: Weight is same for both kinds of accumulator even when universal takes a bit more space
        #[weight = SubstrateWeight::<T>::add_accumulator(add_accumulator, signature)]
        pub fn add_accumulator(
            origin,
            add_accumulator: AddAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::add_accumulator_, add_accumulator, signature)
        }

        /// Update an existing accumulator. The update contains the new accumulated value, the updates themselves
        /// and the witness updated info. The updates and witness update info are optional as the owner might be
        /// privately communicating the updated witnesses. It logs an event with the accumulator id and the new
        /// accumulated value which is sufficient for a verifier. But the prover (who has a witness to update) needs
        /// the updates and the witness update info and is expected to look into the corresponding extrinsic arguments.
        #[weight = SubstrateWeight::<T>::update_accumulator(update, signature)]
        pub fn update_accumulator(
            origin,
            update: UpdateAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::update_accumulator_, update, signature)
        }

        #[weight = SubstrateWeight::<T>::remove_accumulator(remove, signature)]
        pub fn remove_accumulator(
            origin,
            remove: RemoveAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(Self::remove_accumulator_, remove, signature)
        }
    }
}

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn add_params(
        add_params: &AddAccumulatorParams<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_params_sr25519,
            SigValue::Ed25519(_) => Self::add_params_ed25519,
            SigValue::Secp256k1(_) => Self::add_params_secp256k1,
        }(
            add_params.params.bytes.len() as u32,
            add_params.params.label.as_ref().map_or(0, |v| v.len()) as u32,
        ))
    }

    fn add_public(
        public_key: &AddAccumulatorPublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_public_sr25519,
            SigValue::Ed25519(_) => Self::add_public_ed25519,
            SigValue::Secp256k1(_) => Self::add_public_secp256k1,
        }(public_key.public_key.bytes.len() as u32))
    }

    fn remove_params(
        _: &RemoveAccumulatorParams<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_params_sr25519,
            SigValue::Ed25519(_) => Self::remove_params_ed25519,
            SigValue::Secp256k1(_) => Self::remove_params_secp256k1,
        }())
    }

    fn remove_public(
        _: &RemoveAccumulatorPublicKey<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_public_sr25519,
            SigValue::Ed25519(_) => Self::remove_public_ed25519,
            SigValue::Secp256k1(_) => Self::remove_public_secp256k1,
        }())
    }

    fn add_accumulator(
        acc: &AddAccumulator<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::add_accumulator_sr25519,
            SigValue::Ed25519(_) => Self::add_accumulator_ed25519,
            SigValue::Secp256k1(_) => Self::add_accumulator_secp256k1,
        }(acc.accumulator.accumulated().len() as u32))
    }

    fn remove_accumulator(
        _: &RemoveAccumulator<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::remove_accumulator_sr25519,
            SigValue::Ed25519(_) => Self::remove_accumulator_ed25519,
            SigValue::Secp256k1(_) => Self::remove_accumulator_secp256k1,
        }())
    }

    fn update_accumulator(
        acc: &UpdateAccumulator<T>,
        DidSignature { sig, .. }: &DidSignature<AccumulatorOwner>,
    ) -> Weight {
        (match sig {
            SigValue::Sr25519(_) => Self::update_accumulator_sr25519,
            SigValue::Ed25519(_) => Self::update_accumulator_ed25519,
            SigValue::Secp256k1(_) => Self::update_accumulator_secp256k1,
        })(
            acc.new_accumulated.len() as u32,
            acc.additions.as_ref().map_or(0, |v| v.len()) as u32,
            acc.additions
                .iter()
                .flatten()
                .map(|v| v.len() as u32)
                .sum::<u32>()
                .checked_div_ceil(acc.additions.as_ref().map_or(0, |v| v.len()) as u32)
                .unwrap_or(0),
            acc.removals.as_ref().map_or(0, |v| v.len()) as u32,
            acc.removals
                .iter()
                .flatten()
                .map(|v| v.len() as u32)
                .sum::<u32>()
                .checked_div_ceil(acc.removals.as_ref().map_or(0, |v| v.len()) as u32)
                .unwrap_or(0),
            acc.witness_update_info.as_ref().map_or(0, |v| v.len()) as u32,
        )
    }
}
