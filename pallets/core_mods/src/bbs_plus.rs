//! Module to store BBS+ keys and parameters.
//! This module might become irrelevant if signature params become part of a standard so they become universal
//! and BBS+ keys are moved to the DID module. Not making this change as it will be a disruption for the client
//! library. This decision must be revisited if the signature params become irrelevant.

use crate::did;
use crate::did::{Did, DidDetail, DidSignature};
use crate::types::CurveType;
use crate::{Action, StateChange};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::One;
use sp_std::{borrow::Cow, collections::btree_map::BTreeMap, vec::Vec};

pub type ParametersStorageKey = (Did, u32);
pub type PublicKeyStorageKey = (Did, u32);
pub type PublicKeyWithParams = (BbsPlusPublicKey, Option<BbsPlusParameters>);

/// Signature params in G1 for BBS+ signatures
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BbsPlusParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Vec<u8>>,
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

/// Public key in G2 for BBS+ signatures
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BbsPlusPublicKey {
    /// The public key should be for the same curve as the parameters but a public key might not have
    /// parameters on chain
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
    /// The params used to generate the public key (`g2` comes from params)
    pub params_ref: Option<ParametersStorageKey>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddBBSPlusPublicKey<T: frame_system::Config> {
    pub key: BbsPlusPublicKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveBBSPlusParams<T: frame_system::Config> {
    pub params_ref: ParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveBBSPlusPublicKey<T: frame_system::Config> {
    pub key_ref: PublicKeyStorageKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

impl_action!(Did, did, AddBBSPlusPublicKey);
impl_action!(Did, did, RemoveBBSPlusPublicKey);

/// The module's configuration trait.
pub trait Config: system::Config + did::Trait {
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
        ParamsAdded(did::Did, u32),
        ParamsRemoved(did::Did, u32),
        KeyAdded(did::Did, u32),
        KeyRemoved(did::Did, u32),
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
            map hasher(blake2_128_concat) did::Did => u32;

        /// Parameters are stored as key value (did, counter) -> params
        pub BbsPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<(BbsPlusParameters, T::BlockNumber)>;

        /// Public keys are stored as key value (did, counter) -> public key
        /// Its assumed that the public keys are always members of G2. It does impact any logic on the
        /// chain but makes up for one less storage value
        pub BbsPlusKeys get(fn get_key):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<BbsPlusPublicKey>;
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

        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + signature.weight()
            + params.bytes.len() as u64 * T::ParamsPerByteWeight::get()
            + params.label.as_ref().map_or_else(|| 0, |l| l.len()) as u64 * T::LabelPerByteWeight::get()
        ]
        pub fn add_params(
            origin,
            params: BbsPlusParameters,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_params_(params, signature)
        }

        /// Add a BBS+ public key. Only the DID controller can add key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module but only by calling `remove_public_key` of this module.
        #[weight = T::DbWeight::get().reads_writes(2, 2)
            + {if public_key.key.params_ref.is_some() { 1 } else {0}} + signature.weight()
            + public_key.key.bytes.len() as u64 * T::PublicKeyPerByteWeight::get()
        ]
        pub fn add_public_key(
            origin,
            public_key: AddBBSPlusPublicKey<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_public_key_(public_key, signature)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_params(
            origin,
            remove: RemoveBBSPlusParams<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_params_(remove, signature)
        }

        /// Remove BBS+ public key. Only the DID controller can remove key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module.
        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_public_key(
            origin,
            remove: RemoveBBSPlusPublicKey<T>,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_public_key_(remove, signature)
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn add_params_(params: BbsPlusParameters, signature: DidSignature) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or_else(|| 0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let payload = StateChange::<T>::AddBBSPlusParams(Cow::Borrowed(&params)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        let param_index = Self::on_new_params(params, &signature.did);

        Self::deposit_event(Event::ParamsAdded(signature.did, param_index));
        Ok(())
    }

    fn add_public_key_(pk: AddBBSPlusPublicKey<T>, signature: DidSignature) -> DispatchResult {
        let public_key = &pk.key;
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= public_key.bytes.len(),
            Error::<T>::PublicKeyTooBig
        );
        match public_key.params_ref {
            Some(params_ref) => {
                ensure!(
                    BbsPlusParams::<T>::contains_key(&params_ref.0, &params_ref.1),
                    Error::<T>::ParamsDontExist
                );

                // Note: Once we have more than 1 curve type, it should check that params and key
                // both have same curve type
            }
            None => (),
        }

        // Only controller can add a key
        ensure!(
            did::Module::<T>::verify_sig_from_controller(&pk, &signature)?,
            Error::<T>::InvalidSig
        );

        let did_detail = did::Module::<T>::get_on_chain_did_detail(&pk.did)?;

        ensure!(
            pk.nonce == did_detail.next_nonce(),
            Error::<T>::IncorrectNonce
        );

        let owner = pk.did;
        let new_key_count = Self::on_new_key(pk, did_detail);
        Self::deposit_event(Event::KeyAdded(owner, new_key_count));
        Ok(())
    }

    fn remove_params_(remove: RemoveBBSPlusParams<T>, signature: DidSignature) -> DispatchResult {
        let (_, nonce) = BbsPlusParams::<T>::get(&remove.params_ref.0, &remove.params_ref.1)
            .ok_or_else(|| Error::<T>::ParamsDontExist)?;
        // Only the DID that added the param can remove it
        ensure!(remove.params_ref.0 == signature.did, Error::<T>::NotOwner);
        // Nonce should be correct
        ensure!(
            remove.nonce == (nonce + T::BlockNumber::one()),
            Error::<T>::IncorrectNonce
        );
        let payload = StateChange::RemoveBBSPlusParams(Cow::Borrowed(&remove)).encode();
        ensure!(
            did::Module::<T>::verify_sig_from_auth_or_control_key(&payload, &signature)?,
            Error::<T>::InvalidSig
        );

        BbsPlusParams::<T>::remove(&remove.params_ref.0, &remove.params_ref.1);

        Self::deposit_event(Event::ParamsRemoved(
            remove.params_ref.0,
            remove.params_ref.1,
        ));
        Ok(())
    }

    fn remove_public_key_(
        remove: RemoveBBSPlusPublicKey<T>,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            BbsPlusKeys::contains_key(&remove.key_ref.0, &remove.key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        // Only controller can add a key
        ensure!(
            did::Module::<T>::verify_sig_from_controller(&remove, &signature)?,
            Error::<T>::InvalidSig
        );

        let mut did_detail = did::Module::<T>::get_on_chain_did_detail(&remove.did)?;

        ensure!(
            remove.nonce == did_detail.next_nonce(),
            Error::<T>::IncorrectNonce
        );

        let key_ref = &remove.key_ref;
        did_detail.nonce = remove.nonce;
        BbsPlusKeys::remove(&key_ref.0, &key_ref.1);
        did::Module::<T>::insert_did_detail(remove.did, did_detail);

        Self::deposit_event(Event::KeyRemoved(key_ref.0, key_ref.1));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &PublicKeyStorageKey,
    ) -> Option<PublicKeyWithParams> {
        BbsPlusKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = match &pk.params_ref {
                Some(r) => BbsPlusParams::<T>::get(r.0, r.1).map(|t| t.0),
                _ => None,
            };
            (pk, params)
        })
    }

    pub fn get_params_by_did(id: &Did) -> BTreeMap<u32, BbsPlusParameters> {
        let mut params = BTreeMap::new();
        for (idx, (val, _)) in BbsPlusParams::<T>::iter_prefix(id) {
            params.insert(idx, val);
        }
        params
    }

    pub fn get_public_key_by_did(id: &Did) -> BTreeMap<u32, PublicKeyWithParams> {
        let mut keys = BTreeMap::new();
        for (idx, pk) in BbsPlusKeys::iter_prefix(id) {
            let params = match &pk.params_ref {
                Some(r) => BbsPlusParams::<T>::get(r.0, r.1).map(|t| t.0),
                _ => None,
            };
            keys.insert(idx, (pk, params));
        }
        keys
    }

    /// When new params are added. 1 read and 2 writes
    fn on_new_params(params: BbsPlusParameters, signer: &Did) -> u32 {
        let params_count = Self::params_counter(&signer);
        let new_param_count = params_count + 1;
        BbsPlusParams::<T>::insert(
            &signer,
            new_param_count,
            (params, <system::Module<T>>::block_number()),
        );
        ParamsCounter::insert(&signer, new_param_count);
        new_param_count
    }

    fn on_new_key(pk: AddBBSPlusPublicKey<T>, mut did_detail: DidDetail<T>) -> u32 {
        did_detail.increment_last_key_id();
        did_detail.nonce = pk.nonce;
        let new_key_count = did_detail.last_key_id.as_number();
        BbsPlusKeys::insert(pk.did, new_key_count, pk.key);
        did::Module::<T>::insert_did_detail(pk.did, did_detail);
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
        params: &BbsPlusParameters,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = StateChange::<Test>::AddBBSPlusParams(Cow::Borrowed(params));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_remove_params<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        rp: &RemoveBBSPlusParams<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = StateChange::RemoveBBSPlusParams(Cow::Borrowed(rp));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_add_key<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        ak: &AddBBSPlusPublicKey<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = StateChange::AddBBSPlusPublicKey(Cow::Borrowed(ak));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn sign_remove_key<T: frame_system::Config>(
        keypair: &sr25519::Pair,
        rk: &RemoveBBSPlusPublicKey<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature {
        let payload = StateChange::RemoveBBSPlusPublicKey(Cow::Borrowed(rk));
        did_sig(&payload, keypair, signer, key_id)
    }

    fn bbs_plus_events() -> Vec<super::Event> {
        System::events()
            .iter()
            .filter_map(|event_record| {
                let system::EventRecord::<TestEvent, H256> {
                    phase: _p,
                    event,
                    topics: _t,
                } = event_record;
                match event {
                    TestEvent::BBSPlus(e) => Some(e.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    #[test]
    fn add_remove_params() {
        ext().execute_with(|| {
            run_to_block(5);

            let (author, author_kp) = newdid();

            run_to_block(6);

            let (author_1, author_1_kp) = newdid();

            run_to_block(10);

            let params_bytes = vec![1u8; 600];
            let mut params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: params_bytes,
            };
            let sig = sign_add_params(&author_kp, &params, author.clone(), 1);

            assert_eq!(ParamsCounter::get(&author), 0);
            assert_err!(
                BBSPlusMod::add_params(Origin::signed(1), params.clone(), sig.clone()),
                Error::<Test>::ParamsTooBig
            );
            assert_eq!(ParamsCounter::get(&author), 0);
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            run_to_block(15);

            params.bytes = vec![1u8; 500];

            assert_err!(
                BBSPlusMod::add_params(Origin::signed(1), params.clone(), sig.clone()),
                Error::<Test>::InvalidSig
            );
            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(BbsPlusParams::<Test>::get(&author, 1), None);
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            run_to_block(20);

            let sig = sign_add_params(&author_kp, &params, author.clone(), 1);
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 1);
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 20))
            );

            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            run_to_block(21);

            assert_eq!(BbsPlusParams::<Test>::get(&author, 2), None);
            let params_1 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let sig = sign_add_params(&author_kp, &params_1, author.clone(), 1);
            BBSPlusMod::add_params(Origin::signed(1), params_1.clone(), sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 2);
            assert_eq!(BbsPlusParams::<Test>::get(&author, 2), Some((params_1, 21)));
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 2)));

            run_to_block(25);

            let params_2 = BbsPlusParameters {
                label: Some(vec![0, 9, 1]),
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let sig = sign_add_params(&author_1_kp, &params_2, author_1.clone(), 1);
            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(BbsPlusParams::<Test>::get(&author_1, 1), None);
            BBSPlusMod::add_params(Origin::signed(1), params_2.clone(), sig).unwrap();
            assert_eq!(ParamsCounter::get(&author_1), 1);
            assert_eq!(
                BbsPlusParams::<Test>::get(&author_1, 1),
                Some((params_2.clone(), 25))
            );
            assert_eq!(ParamsCounter::get(&author), 2);
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author_1, 1)));

            run_to_block(30);

            assert_eq!(BbsPlusParams::<Test>::get(&author, 3), None);
            let params_3 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let sig = sign_add_params(&author_kp, &params_3, author.clone(), 1);
            BBSPlusMod::add_params(Origin::signed(1), params_3.clone(), sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 3);
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 3),
                Some((params_3.clone(), 30))
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 3)));

            let rf = (author.clone(), 5);
            let nonce = 25;
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author.clone(), 2);
            let nonce = 21 + 1;
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce,
            };

            let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rp.clone(), sig.clone()),
                Error::<Test>::NotOwner
            );

            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 3);
            // Entry gone from storage
            assert_eq!(BbsPlusParams::<Test>::get(&author, 2), None);
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 3),
                Some((params_3.clone(), 30))
            );
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 20))
            );
            assert_eq!(
                BbsPlusParams::<Test>::get(&author_1, 1),
                Some((params_2.clone(), 25))
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 2)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(
                    Origin::signed(1),
                    RemoveBBSPlusParams {
                        params_ref: rf,
                        nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author_1.clone(), 1);
            let nonce = 25 + 1;
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce,
            };
            let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author_1), 1);
            // Entry gone from storage
            assert_eq!(BbsPlusParams::<Test>::get(&author_1, 1), None);
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 3),
                Some((params_3.clone(), 30))
            );
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 20))
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author_1, 1)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(
                    Origin::signed(1),
                    RemoveBBSPlusParams {
                        params_ref: rf,
                        nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author.clone(), 3);
            let nonce = 30 + 1;
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 3);
            // Entry gone from storage
            assert_eq!(BbsPlusParams::<Test>::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 20))
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 3)));

            let rf = (author.clone(), 1);
            let nonce = 20 + 1;
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 3);
            // Entry gone from storage
            assert_eq!(BbsPlusParams::<Test>::get(&author, 1), None);
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 1)));
        });
    }

    #[test]
    fn add_remove_public_key() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();

            run_to_block(15);

            let mut key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 200],
            };
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: 11,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);

            assert_eq!(ParamsCounter::get(&author), 0);
            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::PublicKeyTooBig
            );
            assert_eq!(ParamsCounter::get(&author), 0);
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2)));

            run_to_block(30);

            key.bytes = vec![1u8; 100];
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: 11,
            };

            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak.clone(), sig.clone()),
                Error::<Test>::InvalidSig
            );
            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert_eq!(BbsPlusKeys::get(&author, 2), None);
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2)));

            run_to_block(35);

            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 2)));

            assert_eq!(BbsPlusKeys::get(&author, 3), None);
            let key_1 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: 12,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_1));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3)));

            run_to_block(45);

            let (author_1, author_kp_1) = newdid();

            run_to_block(50);

            let key_2 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author_1.clone(),
                nonce: 46,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(BbsPlusKeys::get(&author_1, 1), None);
            assert_eq!(BbsPlusKeys::get(&author_1, 2), None);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key_2.clone()));
            assert_eq!(ParamsCounter::get(&author), 0);
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 2)));

            run_to_block(55);

            assert_eq!(BbsPlusParams::<Test>::get(&author, 3), None);
            let key_3 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_3.clone(),
                did: author.clone(),
                nonce: 13,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(BbsPlusKeys::get(&author, 4), Some(key_3.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3)));

            run_to_block(60);

            let rf = (author.clone(), 5);
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: 14,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            let rf = (author.clone(), 3);
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: 14,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 0);
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 4), Some(key_3.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key_2));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            run_to_block(70);

            let rf = (author_1.clone(), 2);
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: 47,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author_1), 0);
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author_1, 2), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 4), Some(key_3));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author_1, 2)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            let rf = (author.clone(), 4);
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: 15,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 0);
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 4), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key));
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 4)));

            let rf = (author.clone(), 2);
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: 16,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(ParamsCounter::get(&author), 0);
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 2), None);
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 2)));

            run_to_block(80);

            let params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![19; 100],
            };
            let sig = sign_add_params(&author_kp, &params, author.clone(), 1);
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), sig).unwrap();
            assert_eq!(ParamsCounter::get(&author), 1);
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 80))
            );

            // Add key with reference to non-existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((author.clone(), 4)),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author_1.clone(),
                nonce: 48,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::ParamsDontExist
            );
            assert_eq!(ParamsCounter::get(&author_1), 0);

            // Add key with reference to existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((author.clone(), 1)),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author_1.clone(),
                nonce: 48,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(BbsPlusKeys::get(&author_1, 3), Some(key_4.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 3)));

            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author.clone(),
                nonce: 17,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            assert_eq!(ParamsCounter::get(&author), 1);
            assert_eq!(BbsPlusKeys::get(&author, 5), Some(key_4));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 5)));
        });
    }

    #[test]
    fn on_new_params_keys() {
        ext().execute_with(|| {
            run_to_block(10);
            let (author, _) = newdid();

            run_to_block(20);
            let (author_1, _) = newdid();

            run_to_block(30);
            let (author_2, _) = newdid();

            let params = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![5; 100],
            };
            let params_1 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![6; 100],
            };

            let key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 80],
            };
            let key_1 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 80],
            };
            let key_2 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![3; 80],
            };

            assert_eq!(ParamsCounter::get(&author), 0);
            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(ParamsCounter::get(&author_2), 0);

            run_to_block(35);

            assert_eq!(BBSPlusMod::on_new_params(params.clone(), &author), 1);
            assert_eq!(ParamsCounter::get(&author), 1);
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 35))
            );

            run_to_block(40);

            let did_detail = DIDModule::get_on_chain_did_detail(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert_eq!(BBSPlusMod::on_new_key(ak, did_detail), 2);
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), None);

            run_to_block(50);

            let did_detail = DIDModule::get_on_chain_did_detail(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert_eq!(BBSPlusMod::on_new_key(ak, did_detail), 3);
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_1.clone()));

            run_to_block(60);

            let did_detail = DIDModule::get_on_chain_did_detail(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert_eq!(BBSPlusMod::on_new_key(ak, did_detail), 4);
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_1.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 4), Some(key_2.clone()));

            run_to_block(70);

            assert_eq!(BBSPlusMod::on_new_params(params_1.clone(), &author), 2);
            assert_eq!(ParamsCounter::get(&author), 2);
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_1.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 4), Some(key_2.clone()));
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 1),
                Some((params.clone(), 35))
            );
            assert_eq!(
                BbsPlusParams::<Test>::get(&author, 2),
                Some((params_1.clone(), 70))
            );

            assert_eq!(ParamsCounter::get(&author_1), 0);
            assert_eq!(ParamsCounter::get(&author_2), 0);

            run_to_block(80);

            let did_detail_1 = DIDModule::get_on_chain_did_detail(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert_eq!(BBSPlusMod::on_new_key(ak, did_detail_1), 2);
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key.clone()));

            run_to_block(90);

            assert_eq!(BBSPlusMod::on_new_params(params.clone(), &author_1), 1);
            assert_eq!(ParamsCounter::get(&author_1), 1);
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key.clone()));
            assert_eq!(
                BbsPlusParams::<Test>::get(&author_1, 1),
                Some((params.clone(), 90))
            );

            run_to_block(100);

            let did_detail_1 = DIDModule::get_on_chain_did_detail(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert_eq!(BBSPlusMod::on_new_key(ak, did_detail_1), 3);
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author_1, 3), Some(key_1.clone()));
        });
    }

    #[test]
    fn get_params_and_keys() {
        ext().execute_with(|| {
            let (author, _) = newdid();
            let (author_1, _) = newdid();

            let params = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![5; 100],
            };
            let params_1 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![6; 100],
            };
            let params_2 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![7; 100],
            };

            let key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1; 80],
            };
            let key_1 = BbsPlusPublicKey {
                params_ref: Some((author.clone(), 1)),
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 80],
            };
            let key_2 = BbsPlusPublicKey {
                params_ref: Some((author_1.clone(), 1)),
                curve_type: CurveType::Bls12381,
                bytes: vec![3; 80],
            };

            assert_eq!(BBSPlusMod::get_params_by_did(&author).len(), 0);
            assert_eq!(BBSPlusMod::get_params_by_did(&author_1).len(), 0);
            assert_eq!(BBSPlusMod::get_public_key_with_params(&(author, 0)), None);
            assert_eq!(BBSPlusMod::get_public_key_with_params(&(author_1, 0)), None);

            BBSPlusMod::on_new_params(params.clone(), &author);
            BBSPlusMod::on_new_params(params_1.clone(), &author_1);
            BBSPlusMod::on_new_params(params_2.clone(), &author_1);

            assert_eq!(BBSPlusMod::get_params_by_did(&author), {
                let mut m = BTreeMap::new();
                m.insert(1, params.clone());
                m
            });

            assert_eq!(BBSPlusMod::get_params_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(1, params_1.clone());
                m.insert(2, params_2.clone());
                m
            });

            let did_detail = DIDModule::get_on_chain_did_detail(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            BBSPlusMod::on_new_key(ak, did_detail);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 2)),
                Some((key.clone(), None))
            );

            let did_detail_1 = DIDModule::get_on_chain_did_detail(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            BBSPlusMod::on_new_key(ak, did_detail_1);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author_1, 2)),
                Some((key_1.clone(), Some(params.clone())))
            );

            let did_detail = DIDModule::get_on_chain_did_detail(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            BBSPlusMod::on_new_key(ak, did_detail);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 3)),
                Some((key_2.clone(), Some(params_1.clone())))
            );

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(2, (key_1.clone(), Some(params.clone())));
                m
            });

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author), {
                let mut m = BTreeMap::new();
                m.insert(2, (key.clone(), None));
                m.insert(3, (key_2.clone(), Some(params_1.clone())));
                m
            });

            BbsPlusParams::<Test>::remove(&author, &1);

            assert_eq!(BBSPlusMod::get_params_by_did(&author).len(), 0);

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(2, (key_1.clone(), None));
                m
            });
        });
    }
}
