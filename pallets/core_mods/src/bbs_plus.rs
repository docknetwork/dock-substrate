//! Module to store BBS+ keys and parameters

use crate::did;
use crate::did::DidSignature;
use crate::types::CurveType;
use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

pub type ParametersStorageKey = (did::Did, u32);
pub type PublicKeyStorageKey = (did::Did, u32);
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

/// The module's configuration trait.
pub trait Config: system::Config + did::Trait {
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
    pub enum Error for Module<T: Config> {
        InvalidSig,
        ParamsTooBig,
        PublicKeyTooBig,
        ParamsDontExist,
        PublicKeyDoesntExist,
    }
}

decl_storage! {
    trait Store for Module<T: Config> as BBSPlusModule {
        /// Pair of counters where each is used to assign unique id to parameters and public keys
        /// respectively. On adding new params or keys, corresponding counter is increased by 1 but
        /// the counters don't decrease on removal
        pub DidCounters get(fn did_counters):
            map hasher(blake2_128_concat) did::Did => (u32, u32);

        /// Parameters are stored as key value (did, counter) -> params
        pub BbsPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<BbsPlusParameters>;

        /// Public keys are stored as key value (did, counter) -> public key
        /// Its assumed that the public keys are always members of G2. It does impact any logic on the
        /// chain but makes up for one less storage value
        pub BbsPlusKeys get(fn get_key):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<BbsPlusPublicKey>;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        type Error = Error<T>;

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
        ]
        pub fn add_params(
            origin,
            params: BbsPlusParameters,
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
            public_key: BbsPlusPublicKey,
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
    }
}

impl<T: Config> Module<T> {
    fn add_params_(
        params: BbsPlusParameters,
        signer: did::Did,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let payload = crate::StateChange::AddBBSPlusParams(params.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &signer)?;
        ensure!(valid, Error::<T>::InvalidSig);

        let param_index = Self::on_new_params(params, &signer);

        Self::deposit_event(Event::ParamsAdded(signer, param_index));
        Ok(())
    }

    fn add_public_key_(
        public_key: BbsPlusPublicKey,
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
                    BbsPlusParams::contains_key(&params_ref.0, &params_ref.1),
                    Error::<T>::ParamsDontExist
                );

                // Note: Once we have more than 1 curve type, it should check that params and key
                // both have same curve type
            }
            None => (),
        }

        let payload = crate::StateChange::AddBBSPlusPublicKey(public_key.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &signer)?;
        ensure!(valid, Error::<T>::InvalidSig);

        let key_index = Self::on_new_key(public_key, &signer);

        Self::deposit_event(Event::KeyAdded(signer, key_index));
        Ok(())
    }

    fn remove_params_(params_ref: ParametersStorageKey, signature: DidSignature) -> DispatchResult {
        ensure!(
            BbsPlusParams::contains_key(&params_ref.0, &params_ref.1),
            Error::<T>::ParamsDontExist
        );

        let payload = crate::StateChange::RemoveBBSPlusParams(params_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &params_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        BbsPlusParams::remove(&params_ref.0, &params_ref.1);

        Self::deposit_event(Event::ParamsRemoved(params_ref.0, params_ref.1));
        Ok(())
    }

    fn remove_public_key_(
        public_key_ref: PublicKeyStorageKey,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            BbsPlusKeys::contains_key(&public_key_ref.0, &public_key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        let payload = crate::StateChange::RemoveBBSPlusPublicKey(public_key_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &public_key_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        BbsPlusKeys::remove(&public_key_ref.0, &public_key_ref.1);

        Self::deposit_event(Event::KeyRemoved(public_key_ref.0, public_key_ref.1));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &PublicKeyStorageKey,
    ) -> Option<PublicKeyWithParams> {
        BbsPlusKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = match &pk.params_ref {
                Some(r) => BbsPlusParams::get(r.0, r.1),
                _ => None,
            };
            (pk, params)
        })
    }

    pub fn get_params_by_did(id: &did::Did) -> BTreeMap<u32, BbsPlusParameters> {
        let mut params = BTreeMap::new();
        for (idx, val) in BbsPlusParams::iter_prefix(id) {
            params.insert(idx, val);
        }
        params
    }

    pub fn get_public_key_by_did(id: &did::Did) -> BTreeMap<u32, PublicKeyWithParams> {
        let mut keys = BTreeMap::new();
        for (idx, pk) in BbsPlusKeys::iter_prefix(id) {
            let params = match &pk.params_ref {
                Some(r) => BbsPlusParams::get(r.0, r.1),
                _ => None,
            };
            keys.insert(idx, (pk, params));
        }
        keys
    }

    /// When new params are added. 1 read and 2 writes
    fn on_new_params(params: BbsPlusParameters, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_param_count = params_count + 1;
        BbsPlusParams::insert(&signer, new_param_count, params);
        DidCounters::insert(&signer, (new_param_count, key_count));
        new_param_count
    }

    /// When new public key is added. 1 read and 2 writes
    fn on_new_key(public_key: BbsPlusPublicKey, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_key_count = key_count + 1;
        BbsPlusKeys::insert(&signer, new_key_count, public_key);
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

    fn sign_add_params(keypair: &sr25519::Pair, params: BbsPlusParameters) -> DidSignature {
        let payload = crate::StateChange::AddBBSPlusParams(params);
        sign(&payload, keypair)
    }

    fn sign_remove_params(
        keypair: &sr25519::Pair,
        params_ref: ParametersStorageKey,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveBBSPlusParams(params_ref);
        sign(&payload, keypair)
    }

    fn sign_add_key(keypair: &sr25519::Pair, key: BbsPlusPublicKey) -> DidSignature {
        let payload = crate::StateChange::AddBBSPlusPublicKey(key);
        sign(&payload, keypair)
    }

    fn sign_remove_key(keypair: &sr25519::Pair, key_ref: PublicKeyStorageKey) -> DidSignature {
        let payload = crate::StateChange::RemoveBBSPlusPublicKey(key_ref);
        sign(&payload, keypair)
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
            let (author, author_kp) = newdid();
            let params_bytes = vec![1u8; 600];
            let mut params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: params_bytes,
            };
            let sig = sign_add_params(&author_kp, params.clone());

            assert_eq!(DidCounters::get(&author), (0, 0));
            assert_err!(
                BBSPlusMod::add_params(
                    Origin::signed(1),
                    params.clone(),
                    author.clone(),
                    sig.clone()
                ),
                Error::<Test>::ParamsTooBig
            );
            assert_eq!(DidCounters::get(&author), (0, 0));
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            params.bytes = vec![1u8; 500];

            assert_err!(
                BBSPlusMod::add_params(
                    Origin::signed(1),
                    params.clone(),
                    author.clone(),
                    sig.clone()
                ),
                Error::<Test>::InvalidSig
            );
            assert_eq!(DidCounters::get(&author), (0, 0));
            assert_eq!(BbsPlusParams::get(&author, 1), None);
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            let sig = sign_add_params(&author_kp, params.clone());
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();
            assert_eq!(DidCounters::get(&author), (1, 0));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));

            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 1)));

            assert_eq!(BbsPlusParams::get(&author, 2), None);
            let params_1 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let sig = sign_add_params(&author_kp, params_1.clone());
            BBSPlusMod::add_params(Origin::signed(1), params_1.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (2, 0));
            assert_eq!(BbsPlusParams::get(&author, 2), Some(params_1));
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 2)));

            let (author_1, author_kp_1) = newdid();
            let params_2 = BbsPlusParameters {
                label: Some(vec![0, 9, 1]),
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let sig = sign_add_params(&author_kp_1, params_2.clone());
            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(BbsPlusParams::get(&author_1, 1), None);
            BBSPlusMod::add_params(Origin::signed(1), params_2.clone(), author_1.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author_1), (1, 0));
            assert_eq!(BbsPlusParams::get(&author_1, 1), Some(params_2.clone()));
            assert_eq!(DidCounters::get(&author), (2, 0));
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author_1, 1)));

            assert_eq!(BbsPlusParams::get(&author, 3), None);
            let params_3 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let sig = sign_add_params(&author_kp, params_3.clone());
            BBSPlusMod::add_params(Origin::signed(1), params_3.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (3, 0));
            assert_eq!(BbsPlusParams::get(&author, 3), Some(params_3.clone()));
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(author, 3)));

            let rf = (author.clone(), 5);
            let sig = sign_remove_params(&author_kp, rf.clone());
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author.clone(), 2);
            let sig = sign_remove_params(&author_kp, rf.clone());
            BBSPlusMod::remove_params(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (3, 0));
            // Entry gone from storage
            assert_eq!(BbsPlusParams::get(&author, 2), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusParams::get(&author, 3), Some(params_3.clone()));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author_1, 1), Some(params_2));
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 2)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author_1.clone(), 1);
            let sig = sign_remove_params(&author_kp_1, rf.clone());
            BBSPlusMod::remove_params(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author_1), (1, 0));
            // Entry gone from storage
            assert_eq!(BbsPlusParams::get(&author_1, 1), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusParams::get(&author, 3), Some(params_3));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author_1, 1)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::ParamsDontExist
            );

            let rf = (author.clone(), 3);
            let sig = sign_remove_params(&author_kp, rf.clone());
            BBSPlusMod::remove_params(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (3, 0));
            // Entry gone from storage
            assert_eq!(BbsPlusParams::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params));
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 3)));

            let rf = (author.clone(), 1);
            let sig = sign_remove_params(&author_kp, rf.clone());
            BBSPlusMod::remove_params(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (3, 0));
            // Entry gone from storage
            assert_eq!(BbsPlusParams::get(&author, 1), None);
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(author, 1)));
        });
    }

    #[test]
    fn add_remove_public_key() {
        ext().execute_with(|| {
            let (author, author_kp) = newdid();
            let mut key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 200],
            };
            let sig = sign_add_key(&author_kp, key.clone());

            assert_eq!(DidCounters::get(&author), (0, 0));
            assert_err!(
                BBSPlusMod::add_public_key(
                    Origin::signed(1),
                    key.clone(),
                    author.clone(),
                    sig.clone()
                ),
                Error::<Test>::PublicKeyTooBig
            );
            assert_eq!(DidCounters::get(&author), (0, 0));
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 1)));

            key.bytes = vec![1u8; 100];

            assert_err!(
                BBSPlusMod::add_public_key(
                    Origin::signed(1),
                    key.clone(),
                    author.clone(),
                    sig.clone()
                ),
                Error::<Test>::InvalidSig
            );
            assert_eq!(DidCounters::get(&author), (0, 0));
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 1)));

            let sig = sign_add_key(&author_kp, key.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 1));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 1)));

            assert_eq!(BbsPlusKeys::get(&author, 2), None);
            let key_1 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let sig = sign_add_key(&author_kp, key_1.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key_1.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 2));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key_1));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 2)));

            let (author_1, author_kp_1) = newdid();
            let key_2 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let sig = sign_add_key(&author_kp_1, key_2.clone());
            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), None);
            BBSPlusMod::add_public_key(Origin::signed(1), key_2.clone(), author_1.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author_1), (0, 1));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), Some(key_2.clone()));
            assert_eq!(DidCounters::get(&author), (0, 2));

            assert_eq!(BbsPlusParams::get(&author, 3), None);
            let key_3 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let sig = sign_add_key(&author_kp, key_3.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key_3.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 3));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_3.clone()));

            let rf = (author.clone(), 5);
            let sig = sign_remove_key(&author_kp, rf.clone());
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            let rf = (author.clone(), 2);
            let sig = sign_remove_key(&author_kp, rf.clone());
            BBSPlusMod::remove_public_key(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (0, 3));
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 2), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_3.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), Some(key_2));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            let rf = (author_1.clone(), 1);
            let sig = sign_remove_key(&author_kp_1, rf.clone());
            BBSPlusMod::remove_public_key(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author_1), (0, 1));
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author_1, 1), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_3));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author_1, 1)));

            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rf, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );

            let rf = (author.clone(), 3);
            let sig = sign_remove_key(&author_kp, rf.clone());
            BBSPlusMod::remove_public_key(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (0, 3));
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key));
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 3)));

            let rf = (author.clone(), 1);
            let sig = sign_remove_key(&author_kp, rf.clone());
            BBSPlusMod::remove_public_key(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (0, 3));
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 1)));

            let params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![19; 100],
            };
            let sig = sign_add_params(&author_kp, params.clone());
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();
            assert_eq!(DidCounters::get(&author), (1, 3));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));

            // Add key with reference to non-existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((author.clone(), 4)),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let sig = sign_add_key(&author_kp_1, key_4.clone());
            assert_err!(
                BBSPlusMod::add_public_key(
                    Origin::signed(1),
                    key_4.clone(),
                    author_1.clone(),
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );
            assert_eq!(DidCounters::get(&author_1), (0, 1));

            // Add key with reference to existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((author.clone(), 1)),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let sig = sign_add_key(&author_kp_1, key_4.clone());
            BBSPlusMod::add_public_key(
                Origin::signed(1),
                key_4.clone(),
                author_1.clone(),
                sig.clone(),
            )
            .unwrap();
            assert_eq!(DidCounters::get(&author_1), (0, 2));

            let sig = sign_add_key(&author_kp, key_4.clone());
            BBSPlusMod::add_public_key(
                Origin::signed(1),
                key_4.clone(),
                author.clone(),
                sig.clone(),
            )
            .unwrap();
            assert_eq!(DidCounters::get(&author), (1, 4));
        });
    }

    #[test]
    fn on_new_params_keys() {
        ext().execute_with(|| {
            let (author, _) = newdid();
            let (author_1, _) = newdid();
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

            assert_eq!(DidCounters::get(&author), (0, 0));
            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(DidCounters::get(&author_2), (0, 0));

            assert_eq!(BBSPlusMod::on_new_params(params.clone(), &author), 1);
            assert_eq!(DidCounters::get(&author), (1, 0));
            assert_eq!(BbsPlusKeys::get(&author, 1), None);
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));

            assert_eq!(BBSPlusMod::on_new_key(key.clone(), &author), 1);
            assert_eq!(DidCounters::get(&author), (1, 1));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author, 2), None);

            assert_eq!(BBSPlusMod::on_new_key(key_1.clone(), &author), 2);
            assert_eq!(DidCounters::get(&author), (1, 2));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author, 2), None);
            assert_eq!(BbsPlusParams::get(&author, 3), None);

            assert_eq!(BBSPlusMod::on_new_key(key_2.clone(), &author), 3);
            assert_eq!(DidCounters::get(&author), (1, 3));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_2.clone()));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author, 2), None);
            assert_eq!(BbsPlusParams::get(&author, 3), None);

            assert_eq!(BBSPlusMod::on_new_params(params_1.clone(), &author), 2);
            assert_eq!(DidCounters::get(&author), (2, 3));
            assert_eq!(BbsPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BbsPlusKeys::get(&author, 3), Some(key_2.clone()));
            assert_eq!(BbsPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author, 2), Some(params_1.clone()));

            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(DidCounters::get(&author_2), (0, 0));

            assert_eq!(BBSPlusMod::on_new_key(key.clone(), &author_1), 1);
            assert_eq!(DidCounters::get(&author_1), (0, 1));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BbsPlusParams::get(&author_1, 1), None);

            assert_eq!(BBSPlusMod::on_new_params(params.clone(), &author_1), 1);
            assert_eq!(DidCounters::get(&author_1), (1, 1));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BbsPlusParams::get(&author_1, 1), Some(params.clone()));

            assert_eq!(BBSPlusMod::on_new_key(key_1.clone(), &author_1), 2);
            assert_eq!(DidCounters::get(&author_1), (1, 2));
            assert_eq!(BbsPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BbsPlusKeys::get(&author_1, 2), Some(key_1.clone()));
            assert_eq!(BbsPlusParams::get(&author_1, 1), Some(params.clone()));
            assert_eq!(BbsPlusParams::get(&author_1, 2), None);

            assert_eq!(DidCounters::get(&author_2), (0, 0));
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

            BBSPlusMod::on_new_key(key.clone(), &author);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 1)),
                Some((key.clone(), None))
            );

            BBSPlusMod::on_new_key(key_1.clone(), &author_1);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author_1, 1)),
                Some((key_1.clone(), Some(params.clone())))
            );

            BBSPlusMod::on_new_key(key_2.clone(), &author);
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 2)),
                Some((key_2.clone(), Some(params_1.clone())))
            );

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(1, (key_1.clone(), Some(params.clone())));
                m
            });

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author), {
                let mut m = BTreeMap::new();
                m.insert(1, (key.clone(), None));
                m.insert(2, (key_2.clone(), Some(params_1.clone())));
                m
            });

            BbsPlusParams::remove(&author, &1);

            assert_eq!(BBSPlusMod::get_params_by_did(&author).len(), 0);

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(1, (key_1.clone(), None));
                m
            });
        });
    }
}
