use crate::did;
use crate::did::{Did, DidSignature};
use crate::types::CurveType;
use crate::util::IncId;
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;
use sp_std::vec::Vec;

pub type AccumParametersStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyStorageKey = (AccumulatorOwner, IncId);
pub type AccumPublicKeyWithParams = (AccumulatorPublicKey, Option<AccumulatorParameters>);

/// Accumulator identifier.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AccumulatorId([u8; 32]);

crate::impl_wrapper!(AccumulatorId, [u8; 32]);

/// Accumulator owner - DID with the ability to control given accumulator keys, params, etc.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AccumulatorOwner(pub Did);

crate::impl_wrapper!(AccumulatorOwner, Did);

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Vec<u8>>,
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddAccumulatorParams<T: frame_system::Config> {
    params: AccumulatorParameters,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorPublicKey {
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
    /// The params used to generate the public key (`P_tilde` comes from params)
    pub params_ref: Option<AccumParametersStorageKey>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddAccumulatorPublicKey<T: frame_system::Config> {
    public_key: AccumulatorPublicKey,
    nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulatorParams<T: frame_system::Config> {
    pub params_ref: AccumParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulatorPublicKey<T: frame_system::Config> {
    pub key_ref: AccumPublicKeyStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Accumulator {
    Positive(AccumulatorCommon),
    Universal(UniversalAccumulator),
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorCommon {
    pub accumulated: Vec<u8>,
    pub key_ref: AccumPublicKeyStorageKey,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UniversalAccumulator {
    pub common: AccumulatorCommon,
    /// This is not enforced on chain and serves as metadata only
    pub max_size: u64,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub accumulator: Accumulator,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub new_accumulated: Vec<u8>,
    pub additions: Option<Vec<Vec<u8>>>,
    pub removals: Option<Vec<Vec<u8>>>,
    pub witness_update_info: Option<Vec<u8>>,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    for ():
        AddAccumulatorParams with 1 as len, () as target,
        AddAccumulatorPublicKey with 1 as len, () as target,
        RemoveAccumulatorParams with 1 as len, () as target,
        RemoveAccumulatorPublicKey with 1 as len, () as target,
        AddAccumulator with 1 as len, () as target,
        UpdateAccumulator with 1 as len, () as target,
        RemoveAccumulator with 1 as len, () as target
}

impl Accumulator {
    /// Get reference to the public key of the accumulator
    fn key_ref(&self) -> AccumPublicKeyStorageKey {
        match self {
            Accumulator::Positive(a) => a.key_ref,
            Accumulator::Universal(a) => a.common.key_ref,
        }
    }

    /// DID of the owner of the accumulator
    fn owner_did(&self) -> &AccumulatorOwner {
        match self {
            Accumulator::Positive(a) => &a.key_ref.0,
            Accumulator::Universal(a) => &a.common.key_ref.0,
        }
    }

    fn accumulated(&self) -> &[u8] {
        match self {
            Accumulator::Positive(a) => &a.accumulated,
            Accumulator::Universal(a) => &a.common.accumulated,
        }
    }

    fn set_new_accumulated(&mut self, new_accumulated: Vec<u8>) {
        match self {
            Accumulator::Positive(a) => a.accumulated = new_accumulated,
            Accumulator::Universal(a) => a.common.accumulated = new_accumulated,
        }
    }
}

/// The module's configuration trait.
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
        AccumulatorAdded(AccumulatorId, Vec<u8>),
        AccumulatorUpdated(AccumulatorId, Vec<u8>),
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

#[derive(Encode, Decode, Clone, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoredAccumulatorOwnerCounters {
    params_counter: IncId,
    key_counter: IncId,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorWithUpdateInfo<T: frame_system::Config> {
    created_at: T::BlockNumber,
    last_updated_at: T::BlockNumber,
    accumulator: Accumulator,
}

impl<T: frame_system::Config> AccumulatorWithUpdateInfo<T> {
    fn new(accumulator: Accumulator, block_number: T::BlockNumber) -> Self {
        Self {
            accumulator,
            created_at: block_number,
            last_updated_at: block_number,
        }
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

        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + signature.weight()
            + params.params.bytes.len() as u64 * T::ParamsPerByteWeight::get()
            + params.params.label.as_ref().map_or_else(|| 0, |l| l.len()) as u64 * T::LabelPerByteWeight::get()
        ]
        pub fn add_params(
            origin,
            params: AddAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(params, signature, Self::add_params_)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + {if public_key.public_key.params_ref.is_some() { 1 } else {0}} + signature.weight()
            + public_key.public_key.bytes.len() as u64 * T::PublicKeyPerByteWeight::get()
        ]
        pub fn add_public_key(
            origin,
            public_key: AddAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(public_key, signature, Self::add_public_key_)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_params(
            origin,
            remove: RemoveAccumulatorParams<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(remove, signature, Self::remove_params_)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_public_key(
            origin,
            remove: RemoveAccumulatorPublicKey<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(remove, signature, Self::remove_public_key_)
        }

        /// Add a new accumulator with the initial accumulated value. Each accumulator has a unique id and it
        /// refers to a public key. It is assumed that the accumulator is owned by the DID that owns the public key.
        /// It logs an event with the accumulator id and accumulated value. For each new accumulator, its creation block
        /// is recorded in state to indicate from which block, the chain should be scanned for the accumulator's updates.
        /// Note: Weight is same for both kinds of accumulator even when universal takes a bit more space
        #[weight = T::DbWeight::get().reads_writes(2, 1)
            + signature.weight()
            + add_accumulator.accumulator.accumulated().len() as u64 * T::AccumulatedPerByteWeight::get()
        ]
        pub fn add_accumulator(
            origin,
            add_accumulator: AddAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(add_accumulator, signature, Self::add_accumulator_)
        }

        /// Update an existing accumulator. The update contains the new accumulated value, the updates themselves
        /// and the witness updated info. The updates and witness update info are optional as the owner might be
        /// privately communicating the updated witnesses. It logs an event with the accumulator id and the new
        /// accumulated value which is sufficient for a verifier. But the prover (who has a witness to update) needs
        /// the updates and the witness update info and is expected to look into the corresponding extrinsic arguments.
        #[weight = T::DbWeight::get().reads_writes(2, 1)
            + signature.weight()
            + update.new_accumulated.len() as u64 * T::AccumulatedPerByteWeight::get()
        ]
        pub fn update_accumulator(
            origin,
            update: UpdateAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(update, signature, Self::update_accumulator_)
        }

        #[weight = T::DbWeight::get().reads_writes(1, 2)+ signature.weight()]
        pub fn remove_accumulator(
            origin,
            remove: RemoveAccumulator<T>,
            signature: DidSignature<AccumulatorOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(remove, signature, Self::remove_accumulator_)
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn add_params_(
        AddAccumulatorParams { params, .. }: AddAccumulatorParams<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or_else(|| 0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let params_counter =
            AccumulatorOwnerCounters::mutate(&owner, |counters| *counters.params_counter.inc());
        AccumulatorParams::insert(&owner, params_counter, params);

        Self::deposit_event(Event::ParamsAdded(owner, params_counter));
        Ok(())
    }

    fn add_public_key_(
        AddAccumulatorPublicKey { public_key, .. }: AddAccumulatorPublicKey<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= public_key.bytes.len(),
            Error::<T>::PublicKeyTooBig
        );
        match public_key.params_ref {
            Some(params_ref) => {
                ensure!(
                    AccumulatorParams::contains_key(&params_ref.0, &params_ref.1),
                    Error::<T>::ParamsDontExist
                );
            }
            None => (),
        }

        let keys_counter =
            AccumulatorOwnerCounters::mutate(&owner, |counters| *counters.key_counter.inc());
        AccumulatorKeys::insert(&owner, keys_counter, public_key);

        Self::deposit_event(Event::KeyAdded(owner, keys_counter));
        Ok(())
    }

    fn remove_params_(
        RemoveAccumulatorParams {
            params_ref: (did, counter),
            ..
        }: RemoveAccumulatorParams<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can remove it
        ensure!(did == owner, Error::<T>::NotAccumulatorOwner);
        ensure!(
            AccumulatorParams::contains_key(did, counter),
            Error::<T>::ParamsDontExist
        );

        AccumulatorParams::remove(did, counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    fn remove_public_key_(
        RemoveAccumulatorPublicKey {
            key_ref: (did, counter),
            ..
        }: RemoveAccumulatorPublicKey<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(did == owner, Error::<T>::NotAccumulatorOwner);
        ensure!(
            AccumulatorKeys::contains_key(did, counter),
            Error::<T>::PublicKeyDoesntExist
        );

        AccumulatorKeys::remove(&did, &counter);

        Self::deposit_event(Event::KeyRemoved(did, counter));
        Ok(())
    }

    fn add_accumulator_(
        AddAccumulator {
            id, accumulator, ..
        }: AddAccumulator<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(
            T::AccumulatedMaxSize::get() as usize >= accumulator.accumulated().len(),
            Error::<T>::AccumulatedTooBig
        );
        ensure!(
            !Accumulators::<T>::contains_key(&id),
            Error::<T>::AccumulatorAlreadyExists
        );

        let key_ref = accumulator.key_ref();
        ensure!(
            AccumulatorKeys::contains_key(&key_ref.0, &key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );
        ensure!(key_ref.0 == owner, Error::<T>::NotPublicKeyOwner);

        let accumulated = accumulator.accumulated().to_vec();

        let current_block = <system::Module<T>>::block_number();
        Accumulators::<T>::insert(
            id,
            AccumulatorWithUpdateInfo::new(accumulator, current_block),
        );

        crate::deposit_indexed_event!(AccumulatorAdded(id, accumulated) over id);
        Ok(())
    }

    fn update_accumulator_(
        UpdateAccumulator {
            id,
            new_accumulated,
            ..
        }: UpdateAccumulator<T>,
        owner: AccumulatorOwner,
    ) -> DispatchResult {
        ensure!(
            T::AccumulatedMaxSize::get() as usize >= new_accumulated.len(),
            Error::<T>::AccumulatedTooBig
        );

        Accumulators::<T>::try_mutate(id, |accumulator| -> DispatchResult {
            let accumulator = accumulator
                .as_mut()
                .ok_or(Error::<T>::AccumulatorDoesntExist)?;

            // Only the DID that added the accumulator can update it
            ensure!(
                *accumulator.accumulator.owner_did() == owner,
                Error::<T>::NotAccumulatorOwner
            );

            accumulator
                .accumulator
                .set_new_accumulated(new_accumulated.clone());
            accumulator.last_updated_at = <system::Module<T>>::block_number();

            Ok(())
        })?;

        // The event stores only the accumulated value which can be used by the verifier.
        // For witness update, that information is retrieved by looking at the block and parsing the extrinsic.
        crate::deposit_indexed_event!(AccumulatorUpdated(id, new_accumulated) over id);
        Ok(())
    }

    fn remove_accumulator_(
        RemoveAccumulator { id, .. }: RemoveAccumulator<T>,
        signer: AccumulatorOwner,
    ) -> DispatchResult {
        let accumulator = Accumulators::<T>::get(&id).ok_or(Error::<T>::AccumulatorDoesntExist)?;

        // Only the DID that added the accumulator can remove it
        ensure!(
            *accumulator.accumulator.owner_did() == signer,
            Error::<T>::NotAccumulatorOwner
        );
        Accumulators::<T>::remove(&id);

        crate::deposit_indexed_event!(AccumulatorRemoved(id));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &AccumPublicKeyStorageKey,
    ) -> Option<AccumPublicKeyWithParams> {
        AccumulatorKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = match &pk.params_ref {
                Some(r) => AccumulatorParams::get(r.0, r.1).map(|p| p),
                _ => None,
            };
            (pk, params)
        })
    }

    /// Get accumulated value with public key and params.
    pub fn get_accumulator_with_public_key_and_params(
        id: &AccumulatorId,
    ) -> Option<(Vec<u8>, Option<AccumPublicKeyWithParams>)> {
        Accumulators::<T>::get(&id).map(|stored_acc| {
            let pk_p = Self::get_public_key_with_params(&stored_acc.accumulator.key_ref());
            (stored_acc.accumulator.accumulated().to_vec(), pk_p)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_common::*;
    use frame_support::assert_err;
    use sp_core::{sr25519, H256};

    fn sign_add_params<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        params: &AddAccumulatorParams<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(params, keypair, signer, key_id)
    }

    fn sign_remove_params<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulatorParams<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(remove, keypair, signer, key_id)
    }

    fn sign_add_key<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        public_key: &AddAccumulatorPublicKey<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(public_key, keypair, signer, key_id)
    }

    fn sign_remove_key<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulatorPublicKey<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(remove, keypair, signer, key_id)
    }

    fn sign_add_accum<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        accum: &AddAccumulator<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(accum, keypair, signer, key_id)
    }

    fn sign_remove_accum<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulator<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(remove, keypair, signer, key_id)
    }

    fn sign_update_accum<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        update: &UpdateAccumulator<T>,
        signer: AccumulatorOwner,
        key_id: u32,
    ) -> DidSignature<AccumulatorOwner> {
        did_sig::<T, _, _>(update, keypair, signer, key_id)
    }

    fn accumulator_events() -> Vec<(super::Event, Vec<H256>)> {
        System::events()
            .iter()
            .filter_map(|event_record| {
                let system::EventRecord::<TestEvent, H256> {
                    phase: _p,
                    event,
                    topics,
                } = event_record;
                match event {
                    TestEvent::Accum(e) => Some((e.clone(), topics.clone())),
                    _ => None,
                }
            })
            .collect()
    }

    #[test]
    fn accumulator_errors() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let author = AccumulatorOwner(author);
            let mut next_nonce = 10 + 1;
            check_nonce(&author, next_nonce - 1);

            run_to_block(11);

            let (author_1, author_1_kp) = newdid();
            let author_1 = AccumulatorOwner(author_1);
            let next_nonce_1 = 11 + 1;
            check_nonce(&author_1, next_nonce_1 - 1);

            run_to_block(20);

            let id = AccumulatorId(rand::random());
            let mut accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 300],
                key_ref: (author.clone(), 1u8.into()),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(30);

            accumulator.set_new_accumulated(vec![3; 100]);
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(40);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let ap = AddAccumulatorParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            AccumMod::add_params(Origin::signed(1), ap, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(50);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let ak = AddAccumulatorPublicKey {
                public_key: key.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key::<Test>(&author_kp, &ak, author.clone(), 1);
            AccumMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(60);

            let id = AccumulatorId(rand::random());
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1u8.into()),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Cannot add with same id again
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatorAlreadyExists
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(70);

            let mut update_accum = UpdateAccumulator {
                id: AccumulatorId(rand::random()),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                nonce: next_nonce,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatorDoesntExist
            );

            update_accum.id = id.clone();
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(80);

            let mut update_accum = UpdateAccumulator {
                id: id.clone(),
                new_accumulated: vec![5; 300],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                nonce: next_nonce,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.new_accumulated = vec![5; 100];
            update_accum.additions = Some(vec![
                vec![89; 2],
                vec![45; 6],
                vec![55; 8],
                vec![56; 4],
                vec![57; 5],
                vec![10; 5],
                vec![5; 8],
                vec![35; 2],
                vec![11; 4],
                vec![15; 4],
                vec![25; 5],
            ]);
            update_accum.removals = None;
            update_accum.witness_update_info = Some(vec![11, 12, 21, 23, 35, 50]);
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(90);

            update_accum.nonce = next_nonce - 1;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                sp_runtime::DispatchError::Other("Incorrect nonce")
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.nonce = next_nonce;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            run_to_block(100);

            update_accum.nonce = next_nonce;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only accumulator owner can update it
            update_accum.nonce = next_nonce_1;
            let sig = sign_update_accum(&author_1_kp, &update_accum, author_1.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            update_accum.nonce = next_nonce;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only accumulator owner can remove it
            let rem_accum = RemoveAccumulator {
                id: id.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_accum(&author_1_kp, &rem_accum, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            let rem_accum = RemoveAccumulator {
                id: id.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only key owner can remove it
            let rem = RemoveAccumulatorPublicKey {
                key_ref: (author.clone(), 1u8.into()),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_1_kp, &rem, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_public_key(Origin::signed(1), rem.clone(), sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            let rem = RemoveAccumulatorPublicKey {
                key_ref: (author.clone(), 1u8.into()),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rem, author.clone(), 1);
            AccumMod::remove_public_key(Origin::signed(1), rem, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Only params owner can remove it
            let rem = RemoveAccumulatorParams {
                params_ref: (author.clone(), 1u8.into()),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_params(&author_1_kp, &rem, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_params(Origin::signed(1), rem.clone(), sig),
                Error::<Test>::NotAccumulatorOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rem = RemoveAccumulatorParams {
                params_ref: (author.clone(), 1u8.into()),
                nonce: next_nonce,
            };
            let sig = sign_remove_params(&author_kp, &rem, author.clone(), 1);
            AccumMod::remove_params(Origin::signed(1), rem, sig).unwrap();
            check_nonce(&author, next_nonce);
        });
    }

    #[test]
    fn add_remove_accumulator() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let author = AccumulatorOwner(author);
            let mut next_nonce = 10 + 1;

            run_to_block(20);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let ap = AddAccumulatorParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            AccumMod::add_params(
                Origin::signed(1),
                AddAccumulatorParams {
                    params: params.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                AccumulatorParams::get(&author, IncId::from(1u8)),
                Some(params.clone())
            );
            assert!(accumulator_events()
                .contains(&(super::Event::ParamsAdded(author, 1u8.into()), vec![])));

            run_to_block(30);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let ak = AddAccumulatorPublicKey {
                public_key: key.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key::<Test>(&author_kp, &ak, author.clone(), 1);
            AccumMod::add_public_key(
                Origin::signed(1),
                AddAccumulatorPublicKey {
                    public_key: key.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                AccumulatorKeys::get(&author, IncId::from(1u8)),
                Some(key.clone())
            );
            assert!(accumulator_events()
                .contains(&(super::Event::KeyAdded(author, 1u8.into()), vec![])));

            run_to_block(40);

            let id = AccumulatorId(rand::random());
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1u8.into()),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some(AccumulatorWithUpdateInfo::new(accumulator.clone(), 40))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorAdded(id.clone(), accumulator.accumulated().to_vec()),
                vec![<Test as system::Config>::Hashing::hash(&id[..])]
            )));

            run_to_block(50);

            let mut update_accum = UpdateAccumulator {
                id: id.clone(),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 2, 3, 4]),
                nonce: next_nonce + 1,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                sp_runtime::DispatchError::Other("Incorrect nonce")
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.nonce = next_nonce - 1;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                sp_runtime::DispatchError::Other("Incorrect nonce")
            );
            check_nonce(&author, next_nonce - 1);

            update_accum.nonce = next_nonce;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![4; 32],
                key_ref: (author.clone(), 1u8.into()),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some(AccumulatorWithUpdateInfo {
                    created_at: 40,
                    last_updated_at: 50,
                    accumulator: accumulator.clone()
                })
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(id.clone(), accumulator.accumulated().to_vec()),
                vec![<Test as system::Config>::Hashing::hash(&id[..])]
            )));

            run_to_block(60);

            let update_accum = UpdateAccumulator {
                id: id.clone(),
                new_accumulated: vec![5; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: None,
                witness_update_info: Some(vec![1, 1, 0, 11, 8, 19]),
                nonce: next_nonce,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![5; 32],
                key_ref: (author.clone(), 1u8.into()),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some(AccumulatorWithUpdateInfo {
                    created_at: 40,
                    last_updated_at: 60,
                    accumulator: accumulator.clone()
                })
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(id.clone(), accumulator.accumulated().to_vec()),
                vec![<Test as system::Config>::Hashing::hash(&id[..])]
            )));

            run_to_block(70);

            let mut rem_accum = RemoveAccumulator {
                id: id.clone(),
                nonce: next_nonce - 1,
            };
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                sp_runtime::DispatchError::Other("Incorrect nonce")
            );
            check_nonce(&author, next_nonce - 1);

            rem_accum.nonce = next_nonce + 1;
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                sp_runtime::DispatchError::Other("Incorrect nonce")
            );
            check_nonce(&author, next_nonce - 1);

            rem_accum.nonce = next_nonce;
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig).unwrap();
            check_nonce(&author, next_nonce);
            assert_eq!(Accumulators::<Test>::get(&id), None);
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorRemoved(id.clone()),
                vec![<Test as system::Config>::Hashing::hash(&id[..])]
            )));
        });
    }
}
