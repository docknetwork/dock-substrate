use crate::{
    common::{self, CurveType, SigValue},
    did,
    did::{Did, DidSignature},
    util::{Bytes, IncId},
};
pub use actions::*;
use arith_utils::CheckedDivCeil;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::{DispatchResult, Weight},
    ensure,
};
use sp_std::{fmt::Debug, prelude::*};

pub use pallet::*;
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

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    // The module's configuration trait.
    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {
        /// The overarching event type.
        type Event: From<Event>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        ParamsAdded(AccumulatorOwner, IncId),
        ParamsRemoved(AccumulatorOwner, IncId),
        KeyAdded(AccumulatorOwner, IncId),
        KeyRemoved(AccumulatorOwner, IncId),
        AccumulatorAdded(AccumulatorId, Bytes),
        AccumulatorUpdated(AccumulatorId, Bytes),
        AccumulatorRemoved(AccumulatorId),
    }

    #[pallet::error]
    pub enum Error<T> {
        ParamsDontExist,
        PublicKeyDoesntExist,
        AccumulatedTooBig,
        AccumulatorDoesntExist,
        AccumulatorAlreadyExists,
        NotPublicKeyOwner,
        NotAccumulatorOwner,
        IncorrectNonce,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn did_counters)]
    pub type AccumulatorOwnerCounters<T> = StorageMap<
        _,
        Blake2_128Concat,
        AccumulatorOwner,
        StoredAccumulatorOwnerCounters,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn accumulator_params)]
    pub type AccumulatorParams<T> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        AccumulatorOwner,
        Identity,
        IncId,
        AccumulatorParameters<T>,
    >;

    /// Public key storage is kept separate from accumulator storage and a single key can be used to manage
    /// several accumulators. It is assumed that whoever (DID) owns the public key, owns the accumulator as
    /// well and only that DID can update accumulator.
    #[pallet::storage]
    #[pallet::getter(fn accumulator_key)]
    pub type AccumulatorKeys<T> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        AccumulatorOwner,
        Identity,
        IncId,
        AccumulatorPublicKey<T>,
    >;

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
    #[pallet::storage]
    #[pallet::getter(fn accumulator)]
    pub type Accumulators<T> =
        StorageMap<_, Blake2_128Concat, AccumulatorId, AccumulatorWithUpdateInfo<T>, OptionQuery>;

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
            params: AddAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::add_params_,
                params,
                signature,
            )
        }

        #[pallet::weight(SubstrateWeight::<T>::add_public(public_key, signature))]
        pub fn add_public_key(
            origin: OriginFor<T>,
            public_key: AddAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::add_public_key_,
                public_key,
                signature,
            )
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_params(remove, signature))]
        pub fn remove_params(
            origin: OriginFor<T>,
            remove: RemoveAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::remove_params_,
                remove,
                signature,
            )
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_public(remove, signature))]
        pub fn remove_public_key(
            origin: OriginFor<T>,
            remove: RemoveAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::remove_public_key_,
                remove,
                signature,
            )
        }

        /// Add a new accumulator with the initial accumulated value. Each accumulator has a unique id and it
        /// refers to a public key. It is assumed that the accumulator is owned by the DID that owns the public key.
        /// It logs an event with the accumulator id and accumulated value. For each new accumulator, its creation block
        /// is recorded in state to indicate from which block, the chain should be scanned for the accumulator's updates.
        /// Note: Weight is same for both kinds of accumulator even when universal takes a bit more space
        #[pallet::weight(SubstrateWeight::<T>::add_accumulator(add_accumulator, signature))]
        pub fn add_accumulator(
            origin: OriginFor<T>,
            add_accumulator: AddAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::add_accumulator_,
                add_accumulator,
                signature,
            )
        }

        /// Update an existing accumulator. The update contains the new accumulated value, the updates themselves
        /// and the witness updated info. The updates and witness update info are optional as the owner might be
        /// privately communicating the updated witnesses. It logs an event with the accumulator id and the new
        /// accumulated value which is sufficient for a verifier. But the prover (who has a witness to update) needs
        /// the updates and the witness update info and is expected to look into the corresponding extrinsic arguments.
        #[pallet::weight(SubstrateWeight::<T>::update_accumulator(update, signature))]
        pub fn update_accumulator(
            origin: OriginFor<T>,
            update: UpdateAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::update_accumulator_,
                update,
                signature,
            )
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_accumulator(remove, signature))]
        pub fn remove_accumulator(
            origin: OriginFor<T>,
            remove: RemoveAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Pallet::<T>::try_exec_signed_action_from_onchain_did(
                Self::remove_accumulator_,
                remove,
                signature,
            )
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
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
