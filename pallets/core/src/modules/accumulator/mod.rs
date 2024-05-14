use crate::{
    common::{self, signatures::ForSigType, CurveType},
    did,
    did::{Did, DidOrDidMethodKeySignature},
    util::{ActionWithNonce, ActionWithNonceWrapper, Bytes, IncId},
};
pub use actions::*;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::{DispatchResult, Weight},
    ensure, storage_alias,
    traits::Get,
};
use sp_std::{fmt::Debug, prelude::*};
use utils::CheckedDivCeil;

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
        AccumulatorAlreadyExists,
        AccumulatorDoesntExist,
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
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            params
                .signed_with_signer_target(signature)?
                .execute(ActionWithNonceWrapper::wrap_fn(Self::add_params_))
        }

        #[pallet::weight(SubstrateWeight::<T>::add_public(public_key, signature))]
        pub fn add_public_key(
            origin: OriginFor<T>,
            public_key: AddAccumulatorPublicKey<T>,
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            public_key
                .signed_with_signer_target(signature)?
                .execute(ActionWithNonceWrapper::wrap_fn(Self::add_public_key_))
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_params(remove, signature))]
        pub fn remove_params(
            origin: OriginFor<T>,
            remove: RemoveAccumulatorParams<T>,
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            remove.signed(signature).execute_view(Self::remove_params_)
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_public(remove, signature))]
        pub fn remove_public_key(
            origin: OriginFor<T>,
            remove: RemoveAccumulatorPublicKey<T>,
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            remove
                .signed(signature)
                .execute_view(Self::remove_public_key_)
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
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            add_accumulator
                .signed(signature)
                .execute(Self::add_accumulator_)
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
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            update.signed(signature).execute(Self::update_accumulator_)
        }

        #[pallet::weight(SubstrateWeight::<T>::remove_accumulator(remove, signature))]
        pub fn remove_accumulator(
            origin: OriginFor<T>,
            remove: RemoveAccumulator<T>,
            signature: DidOrDidMethodKeySignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            remove
                .signed(signature)
                .execute_removable(Self::remove_accumulator_)
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            migration::migrate::<T>()
        }
    }
}

mod migration {
    use super::*;
    use crate::{
        common::{Limits, TypesAndLimits},
        util::*,
    };
    use frame_support::pallet_prelude::*;

    #[storage_alias]
    pub type AccumulatorOwnerCounters<T: Config> =
        StorageMap<Pallet<T>, Blake2_128Concat, Did, StoredAccumulatorOwnerCounters, ValueQuery>;

    #[storage_alias]
    pub type AccumulatorParams<T: Config> = StorageDoubleMap<
        Pallet<T>,
        Blake2_128Concat,
        Did,
        Identity,
        IncId,
        AccumulatorParameters<T>,
    >;

    #[derive(
        scale_info_derive::TypeInfo,
        Encode,
        Decode,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        MaxEncodedLen,
    )]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    #[cfg_attr(
        feature = "serde",
        serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
    )]
    #[scale_info(skip_type_params(T))]
    pub struct AccumulatorPublicKey<T: Limits> {
        pub curve_type: CurveType,
        pub bytes: BoundedBytes<T::MaxAccumulatorPublicKeySize>,
        /// The params used to generate the public key (`P_tilde` comes from params)
        pub params_ref: Option<(Did, IncId)>,
    }

    #[storage_alias]
    pub type AccumulatorKeys<T: Config> = StorageDoubleMap<
        Pallet<T>,
        Blake2_128Concat,
        Did,
        Identity,
        IncId,
        AccumulatorPublicKey<T>,
    >;

    pub fn migrate<T: Config>() -> Weight {
        let mut reads_writes = 0;

        let counters: Vec<_> = {
            AccumulatorOwnerCounters::<T>::drain()
                .map(|(did, counters): (Did, _)| (AccumulatorOwner(did.into()), counters))
                .collect()
        };

        reads_writes += counters.len() as u64;
        frame_support::log::info!("Migrated {} accumulator counters", counters.len());
        for (did, counters) in counters {
            super::pallet::AccumulatorOwnerCounters::<T>::insert(did, counters);
        }

        let params: Vec<_> = {
            AccumulatorParams::<T>::drain()
                .map(|(did, id, params): (Did, _, _)| (AccumulatorOwner(did.into()), id, params))
                .collect()
        };

        reads_writes += params.len() as u64;
        frame_support::log::info!("Migrated {} accumulator params", params.len());
        for (did, id, params) in params {
            super::pallet::AccumulatorParams::<T>::insert(did, id, params);
        }

        let keys: Vec<_> = {
            AccumulatorKeys::<T>::drain()
                .map(|(did, id, key): (Did, _, _)| {
                    (
                        AccumulatorOwner(did.into()),
                        id,
                        super::AccumulatorPublicKey {
                            curve_type: key.curve_type,
                            bytes: key.bytes,
                            params_ref: key
                                .params_ref
                                .map(|(did, key_id)| (AccumulatorOwner(did.into()), key_id.into())),
                        },
                    )
                })
                .collect()
        };

        reads_writes += keys.len() as u64;
        frame_support::log::info!("Migrated {} accumulator keys", keys.len());
        for (did, id, params) in keys {
            super::pallet::AccumulatorKeys::<T>::insert(did, id, params);
        }

        #[derive(
            Encode,
            Decode,
            scale_info_derive::TypeInfo,
            CloneNoBound,
            PartialEqNoBound,
            EqNoBound,
            DebugNoBound,
            MaxEncodedLen,
        )]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        pub struct AccumulatorCommon<T: Limits> {
            pub accumulated: BoundedBytes<T::MaxAccumulatorAccumulatedSize>,
            pub key_ref: (Did, IncId),
        }

        impl<T: Limits> From<AccumulatorCommon<T>> for super::AccumulatorCommon<T> {
            fn from(
                AccumulatorCommon {
                    accumulated,
                    key_ref: (did, key_id),
                }: AccumulatorCommon<T>,
            ) -> Self {
                super::AccumulatorCommon {
                    accumulated,
                    key_ref: (AccumulatorOwner(did.into()), key_id),
                }
            }
        }

        impl<T: Limits> From<UniversalAccumulator<T>> for super::UniversalAccumulator<T> {
            fn from(UniversalAccumulator { common, max_size }: UniversalAccumulator<T>) -> Self {
                super::UniversalAccumulator {
                    common: common.into(),
                    max_size,
                }
            }
        }

        #[derive(
            Encode,
            Decode,
            scale_info_derive::TypeInfo,
            CloneNoBound,
            PartialEqNoBound,
            EqNoBound,
            DebugNoBound,
            MaxEncodedLen,
        )]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        pub struct UniversalAccumulator<T: Limits> {
            pub common: AccumulatorCommon<T>,
            /// This is not enforced on chain and serves as metadata only
            pub max_size: u64,
        }

        #[derive(
            Encode,
            Decode,
            scale_info_derive::TypeInfo,
            Clone,
            PartialEq,
            Eq,
            DebugNoBound,
            MaxEncodedLen,
        )]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        pub enum Accumulator<T: Limits> {
            Positive(AccumulatorCommon<T>),
            Universal(UniversalAccumulator<T>),
        }

        impl<T: Limits> From<Accumulator<T>> for super::Accumulator<T> {
            fn from(acc: Accumulator<T>) -> Self {
                match acc {
                    Accumulator::Positive(acc) => super::Accumulator::Positive(acc.into()),
                    Accumulator::Universal(acc) => super::Accumulator::Universal(acc.into()),
                }
            }
        }

        #[derive(
            scale_info_derive::TypeInfo, Encode, Decode, Clone, PartialEq, Eq, Debug, MaxEncodedLen,
        )]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
        #[cfg_attr(
            feature = "serde",
            serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
        )]
        #[scale_info(skip_type_params(T))]
        pub struct AccumulatorWithUpdateInfo<T>
        where
            T: TypesAndLimits,
        {
            pub created_at: T::BlockNumber,
            pub last_updated_at: T::BlockNumber,
            pub accumulator: Accumulator<T>,
        }

        let mut accs = 0;
        Accumulators::<T>::translate_values(
            |AccumulatorWithUpdateInfo {
                 created_at,
                 last_updated_at,
                 accumulator,
             }| {
                accs += 1;

                Some(super::AccumulatorWithUpdateInfo {
                    created_at,
                    last_updated_at,
                    accumulator: accumulator.into(),
                })
            },
        );

        frame_support::log::info!("Migrated {} accumulators", accs);
        reads_writes += accs;

        T::DbWeight::get().reads_writes(reads_writes, reads_writes)
    }
}

impl<T: Config> SubstrateWeight<T> {
    fn add_params(
        add_params: &AddAccumulatorParams<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        let bytes_len = add_params.params.bytes.len() as u32;
        let label_len = add_params.params.label.as_ref().map_or(0, |v| v.len()) as u32;

        sig.weight_for_sig_type::<T>(
            || Self::add_params_sr25519(bytes_len, label_len),
            || Self::add_params_ed25519(bytes_len, label_len),
            || Self::add_params_secp256k1(bytes_len, label_len),
        )
    }

    fn add_public(
        public_key: &AddAccumulatorPublicKey<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        let bytes_len = public_key.public_key.bytes.len() as u32;

        sig.weight_for_sig_type::<T>(
            || Self::add_public_sr25519(bytes_len),
            || Self::add_public_ed25519(bytes_len),
            || Self::add_public_secp256k1(bytes_len),
        )
    }

    fn remove_params(
        _: &RemoveAccumulatorParams<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_params_sr25519,
            Self::remove_params_ed25519,
            Self::remove_params_secp256k1,
        )
    }

    fn remove_public(
        _: &RemoveAccumulatorPublicKey<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_public_sr25519,
            Self::remove_public_ed25519,
            Self::remove_public_secp256k1,
        )
    }

    fn add_accumulator(
        acc: &AddAccumulator<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        let len = acc.accumulator.accumulated().len() as u32;

        sig.weight_for_sig_type::<T>(
            || Self::add_accumulator_sr25519(len),
            || Self::add_accumulator_ed25519(len),
            || Self::add_accumulator_secp256k1(len),
        )
    }

    fn remove_accumulator(
        _: &RemoveAccumulator<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            Self::remove_accumulator_sr25519,
            Self::remove_accumulator_ed25519,
            Self::remove_accumulator_secp256k1,
        )
    }

    fn update_accumulator(
        acc: &UpdateAccumulator<T>,
        sig: &DidOrDidMethodKeySignature<AccumulatorOwner>,
    ) -> Weight {
        let acc_len = acc.new_accumulated.len() as u32;
        let add_len = acc.additions.as_ref().map_or(0, |v| v.len()) as u32;
        let add_avg_len = acc
            .additions
            .iter()
            .flatten()
            .map(|v| v.len() as u32)
            .sum::<u32>()
            .checked_div_ceil(acc.additions.as_ref().map_or(0, |v| v.len()) as u32)
            .unwrap_or(0);

        let rem_len = acc.removals.as_ref().map_or(0, |v| v.len()) as u32;
        let rem_avg_len = acc
            .removals
            .iter()
            .flatten()
            .map(|v| v.len() as u32)
            .sum::<u32>()
            .checked_div_ceil(acc.removals.as_ref().map_or(0, |v| v.len()) as u32)
            .unwrap_or(0);
        let wit_len = acc.witness_update_info.as_ref().map_or(0, |v| v.len()) as u32;

        sig.weight_for_sig_type::<T>(
            || {
                Self::update_accumulator_sr25519(
                    acc_len,
                    add_len,
                    add_avg_len,
                    rem_len,
                    rem_avg_len,
                    wit_len,
                )
            },
            || {
                Self::update_accumulator_ed25519(
                    acc_len,
                    add_len,
                    add_avg_len,
                    rem_len,
                    rem_avg_len,
                    wit_len,
                )
            },
            || {
                Self::update_accumulator_secp256k1(
                    acc_len,
                    add_len,
                    add_avg_len,
                    rem_len,
                    rem_avg_len,
                    wit_len,
                )
            },
        )
    }
}
