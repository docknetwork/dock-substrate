use crate::{
    common::{self, signatures::ForSigType, CurveType},
    did,
    did::DidOrDidMethodKeySignature,
    util::{ActionWithNonce, ActionWrapper, Bytes, IncId},
};
pub use actions::*;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::{DispatchResult, Weight},
    ensure,
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
    use did::Did;
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
                .execute(ActionWrapper::wrap_fn(Self::add_params_))
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
                .execute(ActionWrapper::wrap_fn(Self::add_public_key_))
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
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            // https://dock.subscan.io/extrinsic/28622371-1?event=28622371-2
            // https://fe.dock.io/#/explorer/query/28622371
            AccumulatorOwnerCounters::<T>::insert(
                AccumulatorOwner(
                    Did(hex_literal::hex!(
                        "33665c0bdd23a17e702b106a90d359e1465fe9e756b93c6f24248b9d9992fbe7"
                    ))
                    .into(),
                ),
                StoredAccumulatorOwnerCounters {
                    params_counter: IncId::from(0u8),
                    key_counter: IncId::from(1u8),
                },
            );
            // https://dock.subscan.io/extrinsic/28880175-1?event=28880175-2
            // https://fe.dock.io/#/explorer/query/28880175
            AccumulatorOwnerCounters::<T>::insert(
                AccumulatorOwner(
                    Did(hex_literal::hex!(
                        "d92cbc21bfc3d37f215d4e612f586c73efdc1e53ba6ced25582044013898d221"
                    ))
                    .into(),
                ),
                StoredAccumulatorOwnerCounters {
                    params_counter: IncId::from(0u8),
                    key_counter: IncId::from(1u8),
                },
            );

            // https://dock.subscan.io/extrinsic/28622371-1?event=28622371-2
            // https://fe.dock.io/#/explorer/query/28622371
            AccumulatorKeys::<T>::insert(
                AccumulatorOwner(Did(hex_literal::hex!("33665c0bdd23a17e702b106a90d359e1465fe9e756b93c6f24248b9d9992fbe7")).into()),
                IncId::from(1u8),
                AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: Bytes::from(hex_literal::hex!("864d43414c769767e67ae4c77af19733f43a0866014d266fc45e933835aa47ec0ff00a4cb10a144cc8f9113f649a09ad03ad3c7c820054bd3738c6cd8eb12a049932c4695ebeae30715762aa3bcece2e027d58b07d76bdf7c2d3e881ff214e26").to_vec()).try_into().unwrap(),
                    params_ref:None
                }
            );
            // https://dock.subscan.io/extrinsic/28880175-1?event=28880175-2
            // https://fe.dock.io/#/explorer/query/28880175
            AccumulatorKeys::<T>::insert(
                AccumulatorOwner(Did(hex_literal::hex!("d92cbc21bfc3d37f215d4e612f586c73efdc1e53ba6ced25582044013898d221")).into()),
                IncId::from(1u8),
                AccumulatorPublicKey {
                    curve_type: CurveType::Bls12381,
                    bytes: Bytes::from(hex_literal::hex!("a28dc6c3101f6bf840af1299b0fa5a66296dd449c8109cafea51f9ed44123f12eca3f1d8d5ac3099b0ab21883b2bc5b411f3b2589e15f1d461ee3ce42281254ad89a6c0fbba96518a597b6c8a1bc1346e8ad5ff5a694953792bd387462de347a").to_vec()).try_into().unwrap(),
                    params_ref:None
                }
            );

            // https://dock.subscan.io/extrinsic/28622371-1?event=28622371-2
            // https://fe.dock.io/#/explorer/query/28622371
            Accumulators::<T>::insert(
                AccumulatorId(hex_literal::hex!("1de50299ee71e2ca501e0b0b549cc5e93cc9ff2548a6634b48b806f1a4c22607")),
                AccumulatorWithUpdateInfo {
                    created_at: 28622371u32.into(),
                    last_updated_at:28622371u32.into(),
                    accumulator: Accumulator::Positive(
                        AccumulatorCommon {
                            accumulated: hex_literal::hex!("8fd77827daa553a56128bbb9ffbdcd4066b23493dd5bcbecc81528dff64c2b69d776fda6f0fd39667f6f4a5cbc74f844").to_vec().try_into().unwrap(),
                            key_ref: (AccumulatorOwner(Did(hex_literal::hex!("33665c0bdd23a17e702b106a90d359e1465fe9e756b93c6f24248b9d9992fbe7")).into()), IncId::from(1u8))
                        }
                    )
                }
            );

            // https://dock.subscan.io/extrinsic/28915004-1?event=28915004-2
            // https://fe.dock.io/#/explorer/query/28915004
            Accumulators::<T>::insert(
                AccumulatorId(hex_literal::hex!("0ca1cbbeccf140f252dedb6ca1762dff1eb92d3e006ab526a7945dc30b3777b3")),
                AccumulatorWithUpdateInfo {
                    created_at: 28880175u32.into(),
                    last_updated_at:28915004u32.into(),
                    accumulator: Accumulator::Positive(
                        AccumulatorCommon {
                            accumulated: hex_literal::hex!("a4f797b2ab235877d2d5ad27f6ebc46567ea09ccd247b515572db461bd5330fdf712756f7b671b243584e35f55ce6f55").to_vec().try_into().unwrap(),
                            key_ref: (AccumulatorOwner(Did(hex_literal::hex!("d92cbc21bfc3d37f215d4e612f586c73efdc1e53ba6ced25582044013898d221")).into()), IncId::from(1u8))
                        }
                    )
                }
            );

            T::DbWeight::get().writes(6)
        }
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
