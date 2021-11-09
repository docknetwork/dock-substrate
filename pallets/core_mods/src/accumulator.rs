use crate::did;
use crate::did::DidSignature;
use crate::types::CurveType;
use crate::BlockNumber;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Hash;
use sp_std::vec::Vec;

pub type ParametersStorageKey = (did::Did, u32);
pub type PublicKeyStorageKey = (did::Did, u32);
pub type PublicKeyWithParams = (AccumulatorPublicKey, Option<AccumulatorParameters>);
pub type AccumulatorId = [u8; 32];

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
pub struct AccumulatorPublicKey {
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
    /// The params used to generate the public key (`P_tilde` comes from params)
    pub params_ref: Option<ParametersStorageKey>,
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
    pub key_ref: PublicKeyStorageKey,
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
pub struct AddAccumulator {
    pub id: AccumulatorId,
    pub accumulator: Accumulator,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulator {
    pub id: AccumulatorId,
    /// When the accumulator was created. The accumulator id and created_at can be used to uniquely identify
    /// any accumulator across time as there can be only one accumulator with a given id at any point of time.
    /// Eg accumulator with id `xyz` was created at block no 5, removed at block 10, again created at
    /// block 12 (by someone else). Now any update sent between blocks 5 to 10 for id `xyz` cannot be replayed
    /// for accumulator created on block 12
    pub created_at: BlockNumber,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: u32,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorUpdate {
    pub id: AccumulatorId,
    pub new_accumulated: Vec<u8>,
    pub additions: Option<Vec<Vec<u8>>>,
    pub removals: Option<Vec<Vec<u8>>>,
    pub witness_update_info: Option<Vec<u8>>,
    /// When the accumulator was created. The accumulator id and created_at can be used to uniquely identify
    /// any accumulator across time as there can be only one accumulator with a given id at any point of time.
    /// Eg accumulator with id `xyz` was created at block no 5, removed at block 10, again created at
    /// block 12 (by someone else). Now any update sent between blocks 5 to 10 for id `xyz` cannot be replayed
    /// for accumulator created on block 12
    pub created_at: BlockNumber,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: u32,
}

impl Accumulator {
    /// Get reference to the public key of the accumulator
    fn get_key_ref(&self) -> PublicKeyStorageKey {
        match self {
            Accumulator::Positive(a) => a.key_ref,
            Accumulator::Universal(a) => a.common.key_ref,
        }
    }

    /// DID of the owner of the accumulator
    fn get_owner_did(&self) -> &did::Did {
        match self {
            Accumulator::Positive(a) => &a.key_ref.0,
            Accumulator::Universal(a) => &a.common.key_ref.0,
        }
    }

    fn get_accumulated(&self) -> &[u8] {
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
pub trait Config: system::Config + did::Trait {
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
        ParamsAdded(did::Did, u32),
        ParamsRemoved(did::Did, u32),
        KeyAdded(did::Did, u32),
        KeyRemoved(did::Did, u32),
        AccumulatorAdded(AccumulatorId, Vec<u8>),
        AccumulatorUpdated(AccumulatorId, Vec<u8>),
        AccumulatorRemoved(AccumulatorId),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> {
        InvalidSig,
        LabelTooBig,
        ParamsTooBig,
        PublicKeyTooBig,
        ParamsDontExist,
        PublicKeyDoesntExist,
        AccumulatedTooBig,
        AccumulatorDoesntExist,
        AccumulatorAlreadyExists,
        DifferentCreationBlockNo,
        IncorrectNonce,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as AccumulatorModule {
        pub DidCounters get(fn did_counters):
            map hasher(blake2_128_concat) did::Did => (u32, u32);

        pub AccumulatorParams get(fn get_params):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<AccumulatorParameters>;

        /// Public key storage is kept separate from accumulator storage and a single key can be used to manage
        /// several accumulators. It is assumed that whoever (DID) owns the public key, owns the accumulator as
        /// well and only that DID can update accumulator.
        pub AccumulatorKeys get(fn get_key):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<AccumulatorPublicKey>;

        /// Stores latest accumulator as key value: accumulator id -> (created_at, last_updated_at, nonce, Accumulator)
        /// `created_at` is the block number when the accumulator was created and is intended to serve as a starting
        /// point for anyone looking for all updates to the accumulator. `last_updated_at` is the block number when
        /// the last update was sent. `created_at` and `last_updated_at` together indicate which blocks should be
        /// considered for finding accumulator updates.
        /// `nonce` is the an always incrementing number starting at 0 to help with replay protection. Each new
        /// update is supposed to have 1 higher nonce than the current one.
        /// Historical values and updates are persisted as events indexed with the accumulator id. The reason for
        /// not storing past values is to save storage in chain state. Another option could have been to store
        /// block numbers for the updates so that each block from `created_at` doesn't need to be scanned but
        /// even that requires large storage as we expect millions of updates.
        /// Just keeping the latest accumulated value allows for any potential on chain verification as well.
        pub Accumulators get(fn get_accumulator):
            map hasher(blake2_128_concat) AccumulatorId => Option<(T::BlockNumber, T::BlockNumber, u32, Accumulator)>;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
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
            + params.bytes.len() as u64 * T::ParamsPerByteWeight::get()
            + params.label.as_ref().map_or_else(|| 0, |l| l.len()) as u64 * T::LabelPerByteWeight::get()
        ]
        pub fn add_params(
            origin,
            params: AccumulatorParameters,
            signer: did::Did,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_params_(params, signer, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + {if public_key.params_ref.is_some() { 1 } else {0}} + signature.weight()
            + public_key.bytes.len() as u64 * T::PublicKeyPerByteWeight::get()
        ]
        pub fn add_public_key(
            origin,
            public_key: AccumulatorPublicKey,
            signer: did::Did,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_public_key_(public_key, signer, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_params(
            origin,
            params_ref: ParametersStorageKey,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_params_(params_ref, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_public_key(
            origin,
            public_key_ref: PublicKeyStorageKey,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_public_key_(public_key_ref, signature)
        }

        /// Add a new accumulator with the initial accumulated value. Each accumulator has a unique id and it
        /// refers to a public key. It is assumed that the accumulator is owned by the DID that owns the public key.
        /// It logs an event with the accumulator id and accumulated value. For each new accumulator, its creation block
        /// is recorded in state to indicate from which block, the chain should be scanned for the accumulator's updates.
        /// Note: Weight is same for both kinds of accumulator even when universal takes a bit more space
        #[weight = T::DbWeight::get().reads_writes(2, 1)
            + signature.weight()
            + add_accumulator.accumulator.get_accumulated().len() as u64 * T::AccumulatedPerByteWeight::get()
        ]
        pub fn add_accumulator(
            origin,
            add_accumulator: AddAccumulator,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_accumulator_(add_accumulator, signature)
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
            update: AccumulatorUpdate,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::update_accumulator_(update, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(1, 2)+ signature.weight()]
        pub fn remove_accumulator(
            origin,
            remove: RemoveAccumulator,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_accumulator_(remove, signature)
        }
    }
}

impl<T: Config> Module<T> {
    fn add_params_(
        params: AccumulatorParameters,
        signer: did::Did,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or_else(|| 0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let payload = crate::StateChange::AddAccumulatorParams(params.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &signer)?;
        ensure!(valid, Error::<T>::InvalidSig);

        let param_index = Self::on_new_params(params, &signer);

        Self::deposit_event(Event::ParamsAdded(signer, param_index));
        Ok(())
    }

    fn add_public_key_(
        public_key: AccumulatorPublicKey,
        signer: did::Did,
        signature: DidSignature,
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

        let payload = crate::StateChange::AddAccumulatorPublicKey(public_key.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &signer)?;
        ensure!(valid, Error::<T>::InvalidSig);

        let key_index = Self::on_new_key(public_key, &signer);

        Self::deposit_event(Event::KeyAdded(signer, key_index));
        Ok(())
    }

    fn remove_params_(params_ref: ParametersStorageKey, signature: DidSignature) -> DispatchResult {
        ensure!(
            AccumulatorParams::contains_key(&params_ref.0, &params_ref.1),
            Error::<T>::ParamsDontExist
        );

        let payload = crate::StateChange::RemoveAccumulatorParams(params_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &params_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        AccumulatorParams::remove(&params_ref.0, &params_ref.1);

        Self::deposit_event(Event::ParamsRemoved(params_ref.0, params_ref.1));
        Ok(())
    }

    fn remove_public_key_(
        public_key_ref: PublicKeyStorageKey,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            AccumulatorKeys::contains_key(&public_key_ref.0, &public_key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        let payload =
            crate::StateChange::RemoveAccumulatorPublicKey(public_key_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &public_key_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        AccumulatorKeys::remove(&public_key_ref.0, &public_key_ref.1);

        Self::deposit_event(Event::KeyRemoved(public_key_ref.0, public_key_ref.1));
        Ok(())
    }

    fn add_accumulator_(
        add_accumulator: AddAccumulator,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            T::AccumulatedMaxSize::get() as usize
                >= add_accumulator.accumulator.get_accumulated().len(),
            Error::<T>::AccumulatedTooBig
        );
        ensure!(
            !Accumulators::<T>::contains_key(&add_accumulator.id),
            Error::<T>::AccumulatorAlreadyExists
        );

        let key_ref = add_accumulator.accumulator.get_key_ref();
        ensure!(
            AccumulatorKeys::contains_key(&key_ref.0, &key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        let payload = crate::StateChange::AddAccumulator(add_accumulator.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &key_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        let accumulated = add_accumulator.accumulator.get_accumulated().to_vec();

        let current_block_no = <system::Module<T>>::block_number();
        Accumulators::<T>::insert(
            add_accumulator.id,
            (
                current_block_no,
                current_block_no,
                0,
                add_accumulator.accumulator,
            ),
        );

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&add_accumulator.id)],
            <T as Config>::Event::from(Event::AccumulatorAdded(add_accumulator.id, accumulated))
                .into(),
        );
        Ok(())
    }

    fn update_accumulator_(update: AccumulatorUpdate, signature: DidSignature) -> DispatchResult {
        ensure!(
            T::AccumulatedMaxSize::get() as usize >= update.new_accumulated.len(),
            Error::<T>::AccumulatedTooBig
        );

        let accumulator = Accumulators::<T>::get(&update.id);
        ensure!(accumulator.is_some(), Error::<T>::AccumulatorDoesntExist);

        let (created_at, _, nonce, mut accumulator) = accumulator.unwrap();
        ensure!(
            created_at == T::BlockNumber::from(update.created_at),
            Error::<T>::DifferentCreationBlockNo
        );
        ensure!(nonce + 1 == update.nonce, Error::<T>::IncorrectNonce);

        let payload = crate::StateChange::UpdateAccumulator(update.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(
            &signature,
            &payload,
            &accumulator.get_owner_did(),
        )?;
        ensure!(valid, Error::<T>::InvalidSig);

        accumulator.set_new_accumulated(update.new_accumulated.clone());
        let current_block_no = <system::Module<T>>::block_number();
        Accumulators::<T>::insert(
            &update.id,
            (created_at, current_block_no, nonce + 1, accumulator),
        );

        // The event stores only the accumulated value which can be used by the verifier.
        // For witness update, that information is retrieved by looking at the block and parsing the extrinsic.
        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&update.id)],
            <T as Config>::Event::from(Event::AccumulatorUpdated(
                update.id,
                update.new_accumulated,
            ))
            .into(),
        );
        Ok(())
    }

    fn remove_accumulator_(remove: RemoveAccumulator, signature: DidSignature) -> DispatchResult {
        let accumulator = Accumulators::<T>::get(&remove.id);
        ensure!(accumulator.is_some(), Error::<T>::AccumulatorDoesntExist);

        let (created_at, _, nonce, accumulator) = accumulator.unwrap();
        ensure!(
            created_at == T::BlockNumber::from(remove.created_at),
            Error::<T>::DifferentCreationBlockNo
        );
        ensure!(nonce + 1 == remove.nonce, Error::<T>::IncorrectNonce);

        let payload = crate::StateChange::RemoveAccumulator(remove.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(
            &signature,
            &payload,
            &accumulator.get_owner_did(),
        )?;
        ensure!(valid, Error::<T>::InvalidSig);

        Accumulators::<T>::remove(&remove.id);

        <system::Module<T>>::deposit_event_indexed(
            &[<T as system::Config>::Hashing::hash(&remove.id)],
            <T as Config>::Event::from(Event::AccumulatorRemoved(remove.id)).into(),
        );
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &PublicKeyStorageKey,
    ) -> Option<PublicKeyWithParams> {
        AccumulatorKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = match &pk.params_ref {
                Some(r) => AccumulatorParams::get(r.0, r.1),
                _ => None,
            };
            (pk, params)
        })
    }

    /// Get accumulated value with public key and params.
    pub fn get_accumulator_with_public_key_and_params(
        id: &AccumulatorId,
    ) -> Option<(Vec<u8>, Option<PublicKeyWithParams>)> {
        Accumulators::<T>::get(&id).map(|(_, _, _, a)| {
            let pk_p = Self::get_public_key_with_params(&a.get_key_ref());
            (a.get_accumulated().to_vec(), pk_p)
        })
    }

    fn on_new_params(params: AccumulatorParameters, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_param_count = params_count + 1;
        AccumulatorParams::insert(&signer, new_param_count, params);
        DidCounters::insert(&signer, (new_param_count, key_count));
        new_param_count
    }

    fn on_new_key(public_key: AccumulatorPublicKey, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_key_count = key_count + 1;
        AccumulatorKeys::insert(&signer, new_key_count, public_key);
        DidCounters::insert(&signer, (params_count, new_key_count));
        new_key_count
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::did::Bytes64;
    use crate::test_common::*;
    use frame_support::assert_err;
    use sp_core::{sr25519, Pair, H256};

    fn sign_add_params(keypair: &sr25519::Pair, params: AccumulatorParameters) -> DidSignature {
        let payload = crate::StateChange::AddAccumulatorParams(params);
        sign(&payload, keypair)
    }

    fn sign_remove_params(
        keypair: &sr25519::Pair,
        params_ref: ParametersStorageKey,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulatorParams(params_ref);
        sign(&payload, keypair)
    }

    fn sign_add_key(keypair: &sr25519::Pair, key: AccumulatorPublicKey) -> DidSignature {
        let payload = crate::StateChange::AddAccumulatorPublicKey(key);
        sign(&payload, keypair)
    }

    fn sign_remove_key(keypair: &sr25519::Pair, key_ref: PublicKeyStorageKey) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulatorPublicKey(key_ref);
        sign(&payload, keypair)
    }

    fn sign_add_accum(keypair: &sr25519::Pair, accum: AddAccumulator) -> DidSignature {
        let payload = crate::StateChange::AddAccumulator(accum);
        sign(&payload, keypair)
    }

    fn sign_remove_accum(keypair: &sr25519::Pair, accum: RemoveAccumulator) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulator(accum);
        sign(&payload, keypair)
    }

    fn sign_update_accum(keypair: &sr25519::Pair, accum: AccumulatorUpdate) -> DidSignature {
        let payload = crate::StateChange::UpdateAccumulator(accum);
        sign(&payload, keypair)
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
            let (author, author_kp) = newdid();

            let id: AccumulatorId = rand::random();
            let mut accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 300],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, add_accum.clone());
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );

            accumulator.set_new_accumulated(vec![3; 100]);
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, add_accum.clone());
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::PublicKeyDoesntExist
            );

            let (author, author_kp) = newdid();
            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let sig = sign_add_params(&author_kp, params.clone());
            AccumMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let sig = sign_add_key(&author_kp, key.clone());
            AccumMod::add_public_key(Origin::signed(1), key.clone(), author.clone(), sig).unwrap();

            run_to_block(5);

            let id: AccumulatorId = rand::random();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, add_accum.clone());
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig.clone()).unwrap();

            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatorAlreadyExists
            );

            run_to_block(6);

            let mut update_accum = AccumulatorUpdate {
                id: rand::random(),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                created_at: 5,
                nonce: 1,
            };
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatorDoesntExist
            );

            update_accum.id = id.clone();
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(7);

            let mut update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![5; 300],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                created_at: 5,
                nonce: 2,
            };
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );

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
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(20);

            update_accum.created_at = 5;
            update_accum.nonce = 2;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.nonce = 3;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(25);

            update_accum.nonce = 4;
            update_accum.created_at = 20;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::DifferentCreationBlockNo
            );

            update_accum.created_at = 5;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
        });
    }

    #[test]
    fn add_remove_accumulator() {
        ext().execute_with(|| {
            let (author, author_kp) = newdid();
            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let sig = sign_add_params(&author_kp, params.clone());
            AccumMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();
            assert_eq!(AccumulatorParams::get(&author, 1), Some(params.clone()));
            assert!(accumulator_events().contains(&(super::Event::ParamsAdded(author, 1), vec![])));

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let sig = sign_add_key(&author_kp, key.clone());
            AccumMod::add_public_key(Origin::signed(1), key.clone(), author.clone(), sig).unwrap();
            assert_eq!(AccumulatorKeys::get(&author, 1), Some(key.clone()));
            assert!(accumulator_events().contains(&(super::Event::KeyAdded(author, 1), vec![])));

            run_to_block(5);

            let id: AccumulatorId = rand::random();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, add_accum.clone());
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig).unwrap();
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((5, 5, 0, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorAdded(id.clone(), accumulator.get_accumulated().to_vec()),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(8);

            let mut update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 2, 3, 4]),
                created_at: 4,
                nonce: 1,
            };
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::DifferentCreationBlockNo
            );

            update_accum.created_at = 6;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::DifferentCreationBlockNo
            );

            update_accum.created_at = 5;
            update_accum.nonce = 2;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.created_at = 5;
            update_accum.nonce = 0;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.nonce = 1;
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![4; 32],
                key_ref: (author.clone(), 1),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((5, 8, 1, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(
                    id.clone(),
                    accumulator.get_accumulated().to_vec()
                ),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(10);

            let update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![5; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: None,
                witness_update_info: Some(vec![1, 1, 0, 11, 8, 19]),
                created_at: 5,
                nonce: 2,
            };
            let sig = sign_update_accum(&author_kp, update_accum.clone());
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![5; 32],
                key_ref: (author.clone(), 1),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((5, 10, 2, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(
                    id.clone(),
                    accumulator.get_accumulated().to_vec()
                ),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(15);

            let mut rem_accum = RemoveAccumulator {
                id: id.clone(),
                created_at: 5,
                nonce: 2,
            };
            let sig = sign_remove_accum(&author_kp, rem_accum.clone());
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            rem_accum.nonce = 4;
            let sig = sign_remove_accum(&author_kp, rem_accum.clone());
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            rem_accum.created_at = 6;
            rem_accum.nonce = 3;
            let sig = sign_remove_accum(&author_kp, rem_accum.clone());
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::DifferentCreationBlockNo
            );

            rem_accum.created_at = 5;
            let sig = sign_remove_accum(&author_kp, rem_accum.clone());
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig).unwrap();
            assert_eq!(Accumulators::<Test>::get(&id), None);
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorRemoved(id.clone()),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));
        });
    }
}
