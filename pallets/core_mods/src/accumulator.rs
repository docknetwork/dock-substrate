use crate::did;
use crate::did::{Did, DidSignature};
use crate::types::CurveType;
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{Hash, One};
use sp_std::{borrow::Cow, vec::Vec};

pub type ParametersStorageKey = (Did, u32);
pub type PublicKeyStorageKey = (Did, u32);
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
pub struct RemoveAccumulatorParameters<T: frame_system::Config> {
    pub params_ref: ParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveAccumulatorPublicKey<T: frame_system::Config> {
    pub key_ref: PublicKeyStorageKey,
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
pub struct RemoveAccumulator<T: frame_system::Config> {
    pub id: AccumulatorId,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccumulatorUpdate<T: frame_system::Config> {
    pub id: AccumulatorId,
    pub new_accumulated: Vec<u8>,
    pub additions: Option<Vec<Vec<u8>>>,
    pub removals: Option<Vec<Vec<u8>>>,
    pub witness_update_info: Option<Vec<u8>>,
    /// Next valid nonce, i.e. 1 greater than currently stored
    pub nonce: T::BlockNumber,
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
    fn get_owner_did(&self) -> &Did {
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
    pub enum Error for Module<T: Config> where T: Debug {
        InvalidSig,
        LabelTooBig,
        ParamsTooBig,
        PublicKeyTooBig,
        ParamsDontExist,
        PublicKeyDoesntExist,
        AccumulatedTooBig,
        AccumulatorDoesntExist,
        AccumulatorAlreadyExists,
        NotOwner,
        IncorrectNonce,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as AccumulatorModule where T: Debug {
        pub DidCounters get(fn did_counters):
            map hasher(blake2_128_concat) did::Did => (u32, u32);

        pub AccumulatorParams get(fn get_params):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<(AccumulatorParameters, T::BlockNumber)>;

        /// Public key storage is kept separate from accumulator storage and a single key can be used to manage
        /// several accumulators. It is assumed that whoever (DID) owns the public key, owns the accumulator as
        /// well and only that DID can update accumulator.
        pub AccumulatorKeys get(fn get_key):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<(AccumulatorPublicKey, T::BlockNumber)>;

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
            map hasher(blake2_128_concat) AccumulatorId => Option<(T::BlockNumber, T::BlockNumber, T::BlockNumber, Accumulator)>;
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
            + params.bytes.len() as u64 * T::ParamsPerByteWeight::get()
            + params.label.as_ref().map_or_else(|| 0, |l| l.len()) as u64 * T::LabelPerByteWeight::get()
        ]
        pub fn add_params(
            origin,
            params: AccumulatorParameters,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_params_(params, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + {if public_key.params_ref.is_some() { 1 } else {0}} + signature.weight()
            + public_key.bytes.len() as u64 * T::PublicKeyPerByteWeight::get()
        ]
        pub fn add_public_key(
            origin,
            public_key: AccumulatorPublicKey,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_public_key_(public_key, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_params(
            origin,
            remove: RemoveAccumulatorParameters<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_params_(remove, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_public_key(
            origin,
            remove: RemoveAccumulatorPublicKey<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_public_key_(remove, signature)
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
            update: AccumulatorUpdate<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::update_accumulator_(update, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(1, 2)+ signature.weight()]
        pub fn remove_accumulator(
            origin,
            remove: RemoveAccumulator<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_accumulator_(remove, signature)
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn add_params_(params: AccumulatorParameters, signature: DidSignature) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or_else(|| 0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let payload =
            crate::StateChange::<T>::AddAccumulatorParams(Cow::Borrowed(&params)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        let param_index = Self::on_new_params(params, &signature.did);

        Self::deposit_event(Event::ParamsAdded(signature.did, param_index));
        Ok(())
    }

    fn add_public_key_(
        public_key: AccumulatorPublicKey,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= public_key.bytes.len(),
            Error::<T>::PublicKeyTooBig
        );
        match public_key.params_ref {
            Some(params_ref) => {
                ensure!(
                    AccumulatorParams::<T>::contains_key(&params_ref.0, &params_ref.1),
                    Error::<T>::ParamsDontExist
                );
            }
            None => (),
        }

        let payload =
            crate::StateChange::<T>::AddAccumulatorPublicKey(Cow::Borrowed(&public_key)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        let key_index = Self::on_new_key(public_key, &signature.did);

        Self::deposit_event(Event::KeyAdded(signature.did, key_index));
        Ok(())
    }

    fn remove_params_(
        remove: RemoveAccumulatorParameters<T>,
        signature: DidSignature,
    ) -> DispatchResult {
        let params_ref = &remove.params_ref;

        let (_, nonce) = AccumulatorParams::<T>::get(&params_ref.0, &params_ref.1)
            .ok_or_else(|| Error::<T>::ParamsDontExist)?;
        // Only the DID that added the param can remove it
        ensure!(params_ref.0 == signature.did, Error::<T>::NotOwner);
        // Nonce should be correct
        ensure!(
            remove.nonce == (nonce + T::BlockNumber::one()),
            Error::<T>::IncorrectNonce
        );
        let payload = crate::StateChange::RemoveAccumulatorParams(Cow::Borrowed(&remove)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        AccumulatorParams::<T>::remove(&params_ref.0, &params_ref.1);

        Self::deposit_event(Event::ParamsRemoved(params_ref.0, params_ref.1));
        Ok(())
    }

    fn remove_public_key_(
        remove: RemoveAccumulatorPublicKey<T>,
        signature: DidSignature,
    ) -> DispatchResult {
        let public_key_ref = &remove.key_ref;
        let (_, nonce) = AccumulatorKeys::<T>::get(&public_key_ref.0, &public_key_ref.1)
            .ok_or_else(|| Error::<T>::PublicKeyDoesntExist)?;
        // Only the DID that added the key can remove it
        ensure!(public_key_ref.0 == signature.did, Error::<T>::NotOwner);
        // Nonce should be correct
        ensure!(
            remove.nonce == (nonce + T::BlockNumber::one()),
            Error::<T>::IncorrectNonce
        );

        let payload =
            crate::StateChange::RemoveAccumulatorPublicKey(Cow::Borrowed(&remove)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        AccumulatorKeys::<T>::remove(&public_key_ref.0, &public_key_ref.1);

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
            AccumulatorKeys::<T>::contains_key(&key_ref.0, &key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        let payload =
            crate::StateChange::<T>::AddAccumulator(Cow::Borrowed(&add_accumulator)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        let accumulated = add_accumulator.accumulator.get_accumulated().to_vec();

        let current_block_no = <system::Module<T>>::block_number();
        Accumulators::<T>::insert(
            add_accumulator.id,
            (
                current_block_no,
                current_block_no,
                current_block_no,
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

    fn update_accumulator_(
        update: AccumulatorUpdate<T>,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            T::AccumulatedMaxSize::get() as usize >= update.new_accumulated.len(),
            Error::<T>::AccumulatedTooBig
        );

        let accumulator = Accumulators::<T>::get(&update.id);
        ensure!(accumulator.is_some(), Error::<T>::AccumulatorDoesntExist);

        let (created_at, _, nonce, mut accumulator) = accumulator.unwrap();

        // Only the DID that added the accumulator can update it
        ensure!(
            *accumulator.get_owner_did() == signature.did,
            Error::<T>::NotOwner
        );
        ensure!(
            nonce + T::BlockNumber::one() == update.nonce,
            Error::<T>::IncorrectNonce
        );

        let payload = crate::StateChange::UpdateAccumulator(Cow::Borrowed(&update)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        accumulator.set_new_accumulated(update.new_accumulated.clone());
        let current_block_no = <system::Module<T>>::block_number();
        Accumulators::<T>::insert(
            &update.id,
            (created_at, current_block_no, update.nonce, accumulator),
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

    fn remove_accumulator_(
        remove: RemoveAccumulator<T>,
        signature: DidSignature,
    ) -> DispatchResult {
        let accumulator = Accumulators::<T>::get(&remove.id);
        ensure!(accumulator.is_some(), Error::<T>::AccumulatorDoesntExist);

        let (_, _, nonce, accumulator) = accumulator.unwrap();
        // Only the DID that added the accumulator can remove it
        ensure!(
            *accumulator.get_owner_did() == signature.did,
            Error::<T>::NotOwner
        );
        ensure!(
            nonce + T::BlockNumber::one() == remove.nonce,
            Error::<T>::IncorrectNonce
        );

        let payload = crate::StateChange::RemoveAccumulator(Cow::Borrowed(&remove)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

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
        AccumulatorKeys::<T>::get(&key_ref.0, &key_ref.1).map(|(pk, _)| {
            let params = match &pk.params_ref {
                Some(r) => AccumulatorParams::<T>::get(r.0, r.1).map(|(p, _)| p),
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
        AccumulatorParams::<T>::insert(
            &signer,
            new_param_count,
            (params, <system::Module<T>>::block_number()),
        );
        DidCounters::insert(&signer, (new_param_count, key_count));
        new_param_count
    }

    fn on_new_key(public_key: AccumulatorPublicKey, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_key_count = key_count + 1;
        AccumulatorKeys::<T>::insert(
            &signer,
            new_key_count,
            (public_key, <system::Module<T>>::block_number()),
        );
        DidCounters::insert(&signer, (params_count, new_key_count));
        new_key_count
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_common::*;
    use frame_support::assert_err;
    use sp_core::{sr25519, H256};

    fn sign_add_params(
        keypair: &sr25519::Pair,
        params: &AccumulatorParameters,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::<Test>::AddAccumulatorParams(Cow::Borrowed(params));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_remove_params<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulatorParameters<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulatorParams(Cow::Borrowed(remove));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_add_key(
        keypair: &sr25519::Pair,
        key: &AccumulatorPublicKey,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::<Test>::AddAccumulatorPublicKey(Cow::Borrowed(key));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_remove_key<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulatorPublicKey<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulatorPublicKey(Cow::Borrowed(remove));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_add_accum(
        keypair: &sr25519::Pair,
        accum: &AddAccumulator,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::<Test>::AddAccumulator(Cow::Borrowed(accum));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_remove_accum<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        remove: &RemoveAccumulator<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveAccumulator(Cow::Borrowed(remove));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_update_accum<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        update: &AccumulatorUpdate<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = crate::StateChange::UpdateAccumulator(Cow::Borrowed(update));
        did_sig(&payload, keypair, signer, key_id)
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

            run_to_block(11);

            let (author_1, author_1_kp) = newdid();

            run_to_block(20);

            let id: AccumulatorId = rand::random();
            let mut accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 300],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatedTooBig
            );

            run_to_block(30);

            accumulator.set_new_accumulated(vec![3; 100]);
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::PublicKeyDoesntExist
            );

            run_to_block(40);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let sig = sign_add_params(&author_kp, &params, author.clone(), 1);
            AccumMod::add_params(Origin::signed(1), params.clone(), sig).unwrap();

            run_to_block(50);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let sig = sign_add_key(&author_kp, &key, author.clone(), 1);
            AccumMod::add_public_key(Origin::signed(1), key.clone(), sig).unwrap();

            run_to_block(60);

            let id: AccumulatorId = rand::random();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig.clone()).unwrap();

            // Cannot add with same id again
            assert_err!(
                AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig),
                Error::<Test>::AccumulatorAlreadyExists
            );

            run_to_block(70);

            let mut update_accum = AccumulatorUpdate {
                id: rand::random(),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                nonce: 60 + 1,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::AccumulatorDoesntExist
            );

            update_accum.id = id.clone();
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(80);

            let mut update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![5; 300],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 1, 2, 3]),
                nonce: 61 + 1,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
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
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(90);

            update_accum.nonce = 90;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.nonce = 62 + 1;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            run_to_block(100);

            update_accum.nonce = 63 + 1;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();

            // Only accumulator owner can update it
            update_accum.nonce = 64 + 1;
            let sig = sign_update_accum(&author_1_kp, &update_accum, author_1.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::NotOwner
            );
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum, sig).unwrap();

            // Only accumulator owner can remove it
            let rem_accum = RemoveAccumulator {
                id: id.clone(),
                nonce: 65 + 1,
            };
            let sig = sign_remove_accum(&author_1_kp, &rem_accum, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::NotOwner
            );
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum, sig).unwrap();

            // Only key owner can remove it
            let rem = RemoveAccumulatorPublicKey {
                key_ref: (author.clone(), 1),
                nonce: 50 + 1,
            };

            let sig = sign_remove_key(&author_1_kp, &rem, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_public_key(Origin::signed(1), rem.clone(), sig),
                Error::<Test>::NotOwner
            );
            let sig = sign_remove_key(&author_kp, &rem, author.clone(), 1);
            AccumMod::remove_public_key(Origin::signed(1), rem, sig).unwrap();

            // Only params owner can remove it
            let rem = RemoveAccumulatorParameters {
                params_ref: (author.clone(), 1),
                nonce: 40 + 1,
            };

            let sig = sign_remove_params(&author_1_kp, &rem, author_1.clone(), 1);
            assert_err!(
                AccumMod::remove_params(Origin::signed(1), rem.clone(), sig),
                Error::<Test>::NotOwner
            );
            let sig = sign_remove_params(&author_kp, &rem, author.clone(), 1);
            AccumMod::remove_params(Origin::signed(1), rem, sig).unwrap();
        });
    }

    #[test]
    fn add_remove_accumulator() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();

            run_to_block(20);

            let params = AccumulatorParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 100],
            };
            let sig = sign_add_params(&author_kp, &params, author.clone(), 1);
            AccumMod::add_params(Origin::signed(1), params.clone(), sig).unwrap();
            assert_eq!(
                AccumulatorParams::<Test>::get(&author, 1),
                Some((params.clone(), 20))
            );
            assert!(accumulator_events().contains(&(super::Event::ParamsAdded(author, 1), vec![])));

            run_to_block(30);

            let key = AccumulatorPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 100],
            };
            let sig = sign_add_key(&author_kp, &key, author.clone(), 1);
            AccumMod::add_public_key(Origin::signed(1), key.clone(), sig).unwrap();
            assert_eq!(
                AccumulatorKeys::<Test>::get(&author, 1),
                Some((key.clone(), 30))
            );
            assert!(accumulator_events().contains(&(super::Event::KeyAdded(author, 1), vec![])));

            run_to_block(40);

            let id: AccumulatorId = rand::random();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![3; 32],
                key_ref: (author.clone(), 1),
            });
            let add_accum = AddAccumulator {
                id: id.clone(),
                accumulator: accumulator.clone(),
            };
            let sig = sign_add_accum(&author_kp, &add_accum, author.clone(), 1);
            AccumMod::add_accumulator(Origin::signed(1), add_accum.clone(), sig).unwrap();
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((40, 40, 40, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorAdded(id.clone(), accumulator.get_accumulated().to_vec()),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(50);

            let mut update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![4; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: Some(vec![vec![9, 4]]),
                witness_update_info: Some(vec![1, 2, 3, 4]),
                nonce: 50,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.nonce = 40;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            assert_err!(
                AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            update_accum.nonce = 40 + 1;
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![4; 32],
                key_ref: (author.clone(), 1),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((40, 50, 41, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(
                    id.clone(),
                    accumulator.get_accumulated().to_vec()
                ),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(60);

            let update_accum = AccumulatorUpdate {
                id: id.clone(),
                new_accumulated: vec![5; 32],
                additions: Some(vec![vec![0, 1, 2], vec![3, 5, 4]]),
                removals: None,
                witness_update_info: Some(vec![1, 1, 0, 11, 8, 19]),
                nonce: 41 + 1,
            };
            let sig = sign_update_accum(&author_kp, &update_accum, author.clone(), 1);
            AccumMod::update_accumulator(Origin::signed(1), update_accum.clone(), sig).unwrap();
            let accumulator = Accumulator::Positive(AccumulatorCommon {
                accumulated: vec![5; 32],
                key_ref: (author.clone(), 1),
            });
            assert_eq!(
                Accumulators::<Test>::get(&id),
                Some((40, 60, 42, accumulator.clone()))
            );
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorUpdated(
                    id.clone(),
                    accumulator.get_accumulated().to_vec()
                ),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));

            run_to_block(70);

            let mut rem_accum = RemoveAccumulator {
                id: id.clone(),
                nonce: 70,
            };
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            rem_accum.nonce = 60;
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            assert_err!(
                AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig),
                Error::<Test>::IncorrectNonce
            );

            rem_accum.nonce = 42 + 1;
            let sig = sign_remove_accum(&author_kp, &rem_accum, author.clone(), 1);
            AccumMod::remove_accumulator(Origin::signed(1), rem_accum.clone(), sig).unwrap();
            assert_eq!(Accumulators::<Test>::get(&id), None);
            assert!(accumulator_events().contains(&(
                super::Event::AccumulatorRemoved(id.clone()),
                vec![<Test as system::Config>::Hashing::hash(&id)]
            )));
        });
    }
}
