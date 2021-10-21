//! Module to store BBS+ keys and parameters

use crate::did;
use crate::did::DidSignature;
use codec::{Decode, Encode};
use frame_support::dispatch::Weight;
use frame_support::traits::Get;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
};
use frame_system::{self as system, ensure_signed};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CurveType {
    /// BLS12-381
    Bls12381,
}

pub type ParametersStorageKey = (did::Did, u32);
pub type PublicKeyStorageKey = (did::Did, u32);
pub type PublicKeyWithParams = (BbsPlusPublicKey, Option<BBSPlusParameters>);

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BBSPlusParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Vec<u8>>,
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BbsPlusPublicKey {
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
    pub params_ref: Option<ParametersStorageKey>,
}

/// The module's configuration trait.
pub trait Config: system::Config + did::Trait {
    type ParamsMaxSize: Get<u32>;
    type ParamsPerByteWeight: Get<Weight>;
    type PublicKeyMaxSize: Get<u32>;
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
    /// Error for the DID module.
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
        pub DidCounters get(fn did_counters):
            map hasher(blake2_128_concat) did::Did => (u32, u32);

        pub BBSPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) did::Did, hasher(identity) u32 => Option<BBSPlusParameters>;

        pub BBSPlusKeys get(fn get_key):
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

        // TODO: Fix weight

        #[weight = 10_000]
        pub fn add_params(
            origin,
            params: BBSPlusParameters,
            signer: did::Did,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_params_(params, signer, signature)
        }

        #[weight = 10_000]
        pub fn add_public_key(
            origin,
            public_key: BbsPlusPublicKey,
            signer: did::Did,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::add_public_key_(public_key, signer, signature)
        }

        #[weight = 10_000]
        pub fn remove_params(
            origin,
            params_ref: ParametersStorageKey,
            signature: DidSignature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Module::<T>::remove_params_(params_ref, signature)
        }

        #[weight = 10_000]
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
        params: BBSPlusParameters,
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
                    BBSPlusParams::contains_key(&params_ref.0, &params_ref.1),
                    Error::<T>::ParamsDontExist
                );
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
            BBSPlusParams::contains_key(&params_ref.0, &params_ref.1),
            Error::<T>::ParamsDontExist
        );

        let payload = crate::StateChange::RemoveBBSPlusParams(params_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &params_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        BBSPlusParams::remove(&params_ref.0, &params_ref.1);

        Self::deposit_event(Event::ParamsRemoved(params_ref.0, params_ref.1));
        Ok(())
    }

    fn remove_public_key_(
        public_key_ref: PublicKeyStorageKey,
        signature: DidSignature,
    ) -> DispatchResult {
        ensure!(
            BBSPlusKeys::contains_key(&public_key_ref.0, &public_key_ref.1),
            Error::<T>::PublicKeyDoesntExist
        );

        let payload = crate::StateChange::RemoveBBSPlusPublicKey(public_key_ref.clone()).encode();
        let valid = did::Module::<T>::verify_sig_from_did(&signature, &payload, &public_key_ref.0)?;
        ensure!(valid, Error::<T>::InvalidSig);

        BBSPlusKeys::remove(&public_key_ref.0, &public_key_ref.1);

        Self::deposit_event(Event::KeyRemoved(public_key_ref.0, public_key_ref.1));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &PublicKeyStorageKey,
    ) -> Option<PublicKeyWithParams> {
        BBSPlusKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = match &pk.params_ref {
                Some(r) => BBSPlusParams::get(r.0, r.1),
                _ => None,
            };
            (pk, params)
        })
    }

    pub fn get_params_by_did(id: &did::Did) -> BTreeMap<u32, BBSPlusParameters> {
        let mut params = BTreeMap::new();
        for (idx, val) in BBSPlusParams::iter_prefix(id) {
            params.insert(idx, val);
        }
        params
    }

    pub fn get_public_key_by_did(id: &did::Did) -> BTreeMap<u32, PublicKeyWithParams> {
        let mut keys = BTreeMap::new();
        for (idx, pk) in BBSPlusKeys::iter_prefix(id) {
            let params = match &pk.params_ref {
                Some(r) => BBSPlusParams::get(r.0, r.1),
                _ => None,
            };
            keys.insert(idx, (pk, params));
        }
        keys
    }

    fn on_new_params(params: BBSPlusParameters, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_param_count = params_count + 1;
        BBSPlusParams::insert(&signer, new_param_count, params);
        DidCounters::insert(&signer, (new_param_count, key_count));
        new_param_count
    }

    fn on_new_key(public_key: BbsPlusPublicKey, signer: &did::Did) -> u32 {
        let (params_count, key_count) = Self::did_counters(&signer);
        let new_key_count = key_count + 1;
        BBSPlusKeys::insert(&signer, new_key_count, public_key);
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
    use sp_core::{sr25519, Pair};

    fn sign(keypair: &sr25519::Pair, payload: crate::StateChange) -> DidSignature {
        let sig_bytes = keypair.sign(&payload.encode()).0;
        return DidSignature::Sr25519(Bytes64 { value: sig_bytes });
    }

    fn sign_add_params(keypair: &sr25519::Pair, params: BBSPlusParameters) -> DidSignature {
        let payload = crate::StateChange::AddBBSPlusParams(params);
        sign(keypair, payload)
    }

    fn sign_remove_params(
        keypair: &sr25519::Pair,
        params_ref: ParametersStorageKey,
    ) -> DidSignature {
        let payload = crate::StateChange::RemoveBBSPlusParams(params_ref);
        sign(keypair, payload)
    }

    fn sign_add_key(keypair: &sr25519::Pair, key: BbsPlusPublicKey) -> DidSignature {
        let payload = crate::StateChange::AddBBSPlusPublicKey(key);
        sign(keypair, payload)
    }

    fn sign_remove_key(keypair: &sr25519::Pair, key_ref: PublicKeyStorageKey) -> DidSignature {
        let payload = crate::StateChange::RemoveBBSPlusPublicKey(key_ref);
        sign(keypair, payload)
    }

    #[test]
    fn add_remove_params() {
        ext().execute_with(|| {
            let (author, author_kp) = newdid();
            let params_bytes = vec![1u8; 600];
            let mut params = BBSPlusParameters {
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
            assert_eq!(BBSPlusParams::get(&author, 1), None);

            let sig = sign_add_params(&author_kp, params.clone());
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();
            assert_eq!(DidCounters::get(&author), (1, 0));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));

            assert_eq!(BBSPlusParams::get(&author, 2), None);
            let params_1 = BBSPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let sig = sign_add_params(&author_kp, params_1.clone());
            BBSPlusMod::add_params(Origin::signed(1), params_1.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (2, 0));
            assert_eq!(BBSPlusParams::get(&author, 2), Some(params_1));

            let (author_1, author_kp_1) = newdid();
            let params_2 = BBSPlusParameters {
                label: Some(vec![0, 9, 1]),
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let sig = sign_add_params(&author_kp_1, params_2.clone());
            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(BBSPlusParams::get(&author_1, 1), None);
            BBSPlusMod::add_params(Origin::signed(1), params_2.clone(), author_1.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author_1), (1, 0));
            assert_eq!(BBSPlusParams::get(&author_1, 1), Some(params_2.clone()));
            assert_eq!(DidCounters::get(&author), (2, 0));

            assert_eq!(BBSPlusParams::get(&author, 3), None);
            let params_3 = BBSPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let sig = sign_add_params(&author_kp, params_3.clone());
            BBSPlusMod::add_params(Origin::signed(1), params_3.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (3, 0));
            assert_eq!(BBSPlusParams::get(&author, 3), Some(params_3.clone()));

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
            assert_eq!(BBSPlusParams::get(&author, 2), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusParams::get(&author, 3), Some(params_3.clone()));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author_1, 1), Some(params_2));

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
            assert_eq!(BBSPlusParams::get(&author_1, 1), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusParams::get(&author, 3), Some(params_3));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));

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
            assert_eq!(BBSPlusParams::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params));

            let rf = (author.clone(), 1);
            let sig = sign_remove_params(&author_kp, rf.clone());
            BBSPlusMod::remove_params(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (3, 0));
            // Entry gone from storage
            assert_eq!(BBSPlusParams::get(&author, 1), None);
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
            assert_eq!(BBSPlusKeys::get(&author, 1), None);

            let sig = sign_add_key(&author_kp, key.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 1));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));

            assert_eq!(BBSPlusKeys::get(&author, 2), None);
            let key_1 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let sig = sign_add_key(&author_kp, key_1.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key_1.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 2));
            assert_eq!(BBSPlusKeys::get(&author, 2), Some(key_1));

            let (author_1, author_kp_1) = newdid();
            let key_2 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let sig = sign_add_key(&author_kp_1, key_2.clone());
            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), None);
            BBSPlusMod::add_public_key(Origin::signed(1), key_2.clone(), author_1.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author_1), (0, 1));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), Some(key_2.clone()));
            assert_eq!(DidCounters::get(&author), (0, 2));

            assert_eq!(BBSPlusParams::get(&author, 3), None);
            let key_3 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let sig = sign_add_key(&author_kp, key_3.clone());
            BBSPlusMod::add_public_key(Origin::signed(1), key_3.clone(), author.clone(), sig)
                .unwrap();
            assert_eq!(DidCounters::get(&author), (0, 3));
            assert_eq!(BBSPlusKeys::get(&author, 3), Some(key_3.clone()));

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
            assert_eq!(BBSPlusKeys::get(&author, 2), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusKeys::get(&author, 3), Some(key_3.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), Some(key_2));

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
            assert_eq!(BBSPlusKeys::get(&author_1, 1), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusKeys::get(&author, 3), Some(key_3));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));

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
            assert_eq!(BBSPlusKeys::get(&author, 3), None);
            // Other entries remain as it is
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key));

            let rf = (author.clone(), 1);
            let sig = sign_remove_key(&author_kp, rf.clone());
            BBSPlusMod::remove_public_key(Origin::signed(1), rf.clone(), sig.clone()).unwrap();
            // Counter doesn't go back
            assert_eq!(DidCounters::get(&author), (0, 3));
            // Entry gone from storage
            assert_eq!(BBSPlusKeys::get(&author, 1), None);

            let params = BBSPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![19; 100],
            };
            let sig = sign_add_params(&author_kp, params.clone());
            BBSPlusMod::add_params(Origin::signed(1), params.clone(), author.clone(), sig).unwrap();
            assert_eq!(DidCounters::get(&author), (1, 3));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));

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

            let params = BBSPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![5; 100],
            };
            let params_1 = BBSPlusParameters {
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
            assert_eq!(BBSPlusKeys::get(&author, 1), None);
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));

            assert_eq!(BBSPlusMod::on_new_key(key.clone(), &author), 1);
            assert_eq!(DidCounters::get(&author), (1, 1));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author, 2), None);

            assert_eq!(BBSPlusMod::on_new_key(key_1.clone(), &author), 2);
            assert_eq!(DidCounters::get(&author), (1, 2));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author, 2), None);
            assert_eq!(BBSPlusParams::get(&author, 3), None);

            assert_eq!(BBSPlusMod::on_new_key(key_2.clone(), &author), 3);
            assert_eq!(DidCounters::get(&author), (1, 3));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 3), Some(key_2.clone()));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author, 2), None);
            assert_eq!(BBSPlusParams::get(&author, 3), None);

            assert_eq!(BBSPlusMod::on_new_params(params_1.clone(), &author), 2);
            assert_eq!(DidCounters::get(&author), (2, 3));
            assert_eq!(BBSPlusKeys::get(&author, 1), Some(key.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 2), Some(key_1.clone()));
            assert_eq!(BBSPlusKeys::get(&author, 3), Some(key_2.clone()));
            assert_eq!(BBSPlusParams::get(&author, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author, 2), Some(params_1.clone()));

            assert_eq!(DidCounters::get(&author_1), (0, 0));
            assert_eq!(DidCounters::get(&author_2), (0, 0));

            assert_eq!(BBSPlusMod::on_new_key(key.clone(), &author_1), 1);
            assert_eq!(DidCounters::get(&author_1), (0, 1));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BBSPlusParams::get(&author_1, 1), None);

            assert_eq!(BBSPlusMod::on_new_params(params.clone(), &author_1), 1);
            assert_eq!(DidCounters::get(&author_1), (1, 1));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BBSPlusParams::get(&author_1, 1), Some(params.clone()));

            assert_eq!(BBSPlusMod::on_new_key(key_1.clone(), &author_1), 2);
            assert_eq!(DidCounters::get(&author_1), (1, 2));
            assert_eq!(BBSPlusKeys::get(&author_1, 1), Some(key.clone()));
            assert_eq!(BBSPlusKeys::get(&author_1, 2), Some(key_1.clone()));
            assert_eq!(BBSPlusParams::get(&author_1, 1), Some(params.clone()));
            assert_eq!(BBSPlusParams::get(&author_1, 2), None);

            assert_eq!(DidCounters::get(&author_2), (0, 0));
        });
    }

    #[test]
    fn get_params_and_keys() {
        ext().execute_with(|| {
            let (author, _) = newdid();
            let (author_1, _) = newdid();

            let params = BBSPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![5; 100],
            };
            let params_1 = BBSPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![6; 100],
            };
            let params_2 = BBSPlusParameters {
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

            BBSPlusParams::remove(&author, &1);

            assert_eq!(BBSPlusMod::get_params_by_did(&author).len(), 0);

            assert_eq!(BBSPlusMod::get_public_key_by_did(&author_1), {
                let mut m = BTreeMap::new();
                m.insert(1, (key_1.clone(), None));
                m
            });
        });
    }
}
