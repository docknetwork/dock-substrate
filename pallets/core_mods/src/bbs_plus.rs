//! Module to store BBS+ keys and parameters.
//! This module might become irrelevant if signature params become part of a standard so they become universal
//! and BBS+ keys are moved to the DID module. Not making this change as it will be a disruption for the client
//! library. This decision must be revisited if the signature params become irrelevant.

use crate::did::{Controller, Did, DidSignature, OnChainDidDetails};
use crate::types::CurveType;
use crate::util::IncId;
use crate::{did, StorageVersion};
use codec::{Decode, Encode};
use core::fmt::Debug;

use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchResult, Weight},
    ensure,
    traits::Get,
};
use frame_system::{self as system, ensure_signed};
use sp_std::{collections::btree_map::BTreeMap, vec::Vec};

pub type BBSPlusParametersStorageKey = (BBSPlusParamsOwner, IncId);
pub type BBSPlusPublicKeyStorageKey = (Did, IncId);
pub type BBSPlusPublicKeyWithParams = (BbsPlusPublicKey, Option<BbsPlusParameters>);

/// DID owner of the BBSPlus parameters.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BBSPlusParamsOwner(pub Did);

crate::impl_wrapper!(BBSPlusParamsOwner, Did, for rand use Did(rand::random()), with tests as bbs_plus_params_owner_tests);

/// Signature params in G1 for BBS+ signatures
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BbsPlusParameters {
    /// The label (generating string) used to generate the params
    pub label: Option<Vec<u8>>,
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddBBSPlusParams<T: frame_system::Config> {
    pub params: BbsPlusParameters,
    pub nonce: T::BlockNumber,
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
    pub params_ref: Option<BBSPlusParametersStorageKey>,
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
    pub params_ref: BBSPlusParametersStorageKey,
    pub nonce: T::BlockNumber,
}

#[derive(Encode, Decode, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveBBSPlusPublicKey<T: frame_system::Config> {
    pub key_ref: BBSPlusPublicKeyStorageKey,
    pub did: Did,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce!(
    for Did:
        AddBBSPlusPublicKey with { |_| 1 } as len, did as target,
        RemoveBBSPlusPublicKey with { |_| 1 } as len, did as target
);

crate::impl_action_with_nonce!(
    for ():
        AddBBSPlusParams with 1 as len, () as target,
        RemoveBBSPlusParams with 1 as len, () as target
);

/// The module's configuration trait.
pub trait Config: system::Config + did::Config {
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
        ParamsAdded(BBSPlusParamsOwner, IncId),
        ParamsRemoved(BBSPlusParamsOwner, IncId),
        KeyAdded(Did, IncId),
        KeyRemoved(Did, IncId),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> where T: Debug {
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
            map hasher(blake2_128_concat) BBSPlusParamsOwner => IncId;

        /// Parameters are stored as key value (did, counter) -> params
        pub BbsPlusParams get(fn get_params):
            double_map hasher(blake2_128_concat) BBSPlusParamsOwner, hasher(identity) IncId => Option<BbsPlusParameters>;

        /// Public keys are stored as key value (did, counter) -> public key
        /// Its assumed that the public keys are always members of G2. It does impact any logic on the
        /// chain but makes up for one less storage value
        pub BbsPlusKeys get(fn get_key):
            double_map hasher(blake2_128_concat) Did, hasher(identity) IncId => Option<BbsPlusPublicKey>;

        pub Version get(fn version): StorageVersion;
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
            + params.params.bytes.len() as u64 * T::ParamsPerByteWeight::get()
            + params.params.label.as_ref().map_or_else(|| 0, |l| l.len()) as u64 * T::LabelPerByteWeight::get()
        ]
        pub fn add_params(
            origin,
            params: AddBBSPlusParams<T>,
            signature: DidSignature<BBSPlusParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(params, signature, Self::add_params_)
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
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // Only controller can add a key

            <did::Module<T>>::try_exec_signed_action_from_onchain_did_over_onchain_did(public_key, signature, Self::add_public_key_)
        }

        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_params(
            origin,
            remove: RemoveBBSPlusParams<T>,
            signature: DidSignature<BBSPlusParamsOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            did::Module::<T>::try_exec_signed_action_from_onchain_did(remove, signature, Self::remove_params_)
        }

        /// Remove BBS+ public key. Only the DID controller can remove key and it should use the nonce from the DID module.
        /// This kind of key cannot be removed by calling `remove_keys` from the DID module.
        #[weight = T::DbWeight::get().reads_writes(2, 1) + signature.weight()]
        pub fn remove_public_key(
            origin,
            remove: RemoveBBSPlusPublicKey<T>,
            signature: DidSignature<Controller>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            <did::Module<T>>::try_exec_signed_action_from_onchain_did_over_onchain_did(remove, signature, Self::remove_public_key_)
        }

        fn on_runtime_upgrade() -> Weight {
            T::DbWeight::get().reads(1) + if Self::version() == StorageVersion::SingleKey {
                let weight = crate::migrations::bbs_plus::single_key::migrate_to_multi_key::<T>();
                Version::put(StorageVersion::MultiKey);

                T::DbWeight::get().writes(1) + weight
            } else {
                0
            }
        }
    }
}

impl<T: Config + Debug> Module<T> {
    fn add_params_(
        AddBBSPlusParams { params, .. }: AddBBSPlusParams<T>,
        signer: BBSPlusParamsOwner,
    ) -> DispatchResult {
        ensure!(
            T::LabelMaxSize::get() as usize >= params.label.as_ref().map_or_else(|| 0, |l| l.len()),
            Error::<T>::LabelTooBig
        );
        ensure!(
            T::ParamsMaxSize::get() as usize >= params.bytes.len(),
            Error::<T>::ParamsTooBig
        );

        let params_count = ParamsCounter::mutate(signer, |counter| *counter.inc());
        BbsPlusParams::insert(signer, params_count, params);

        Self::deposit_event(Event::ParamsAdded(signer, params_count));
        Ok(())
    }

    fn add_public_key_(
        AddBBSPlusPublicKey {
            did: owner, key, ..
        }: AddBBSPlusPublicKey<T>,
        OnChainDidDetails { key_counter, .. }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(
            T::PublicKeyMaxSize::get() as usize >= key.bytes.len(),
            Error::<T>::PublicKeyTooBig
        );
        if let Some((did, counter)) = key.params_ref {
            ensure!(
                BbsPlusParams::contains_key(&did, &counter),
                Error::<T>::ParamsDontExist
            );
            // Note: Once we have more than 1 curve type, it should check that params and key
            // both have same curve type
        };
        BbsPlusKeys::insert(owner, key_counter.inc(), key);

        Self::deposit_event(Event::KeyAdded(owner, *key_counter));
        Ok(())
    }

    fn remove_params_(
        RemoveBBSPlusParams {
            params_ref: (did, counter),
            ..
        }: RemoveBBSPlusParams<T>,
        owner: BBSPlusParamsOwner,
    ) -> DispatchResult {
        // Only the DID that added the param can it
        ensure!(did == owner, Error::<T>::NotOwner);

        ensure!(
            BbsPlusParams::contains_key(&did, &counter),
            Error::<T>::ParamsDontExist
        );

        BbsPlusParams::remove(&did, &counter);

        Self::deposit_event(Event::ParamsRemoved(did, counter));
        Ok(())
    }

    fn remove_public_key_(
        RemoveBBSPlusPublicKey {
            key_ref: (did, counter),
            ..
        }: RemoveBBSPlusPublicKey<T>,
        _: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(
            BbsPlusKeys::contains_key(&did, &counter),
            Error::<T>::PublicKeyDoesntExist
        );

        BbsPlusKeys::remove(&did, &counter);

        Self::deposit_event(Event::KeyRemoved(did, counter));
        Ok(())
    }

    pub fn get_public_key_with_params(
        key_ref: &BBSPlusPublicKeyStorageKey,
    ) -> Option<BBSPlusPublicKeyWithParams> {
        BbsPlusKeys::get(&key_ref.0, &key_ref.1).map(|pk| {
            let params = pk.params_ref.and_then(|r| BbsPlusParams::get(r.0, r.1));

            (pk, params)
        })
    }

    pub fn get_params_by_did(id: &BBSPlusParamsOwner) -> BTreeMap<IncId, BbsPlusParameters> {
        let mut params = BTreeMap::new();
        for (idx, val) in BbsPlusParams::iter_prefix(*id) {
            params.insert(idx, val);
        }
        params
    }

    pub fn get_public_key_by_did(id: &Did) -> BTreeMap<IncId, BBSPlusPublicKeyWithParams> {
        let mut keys = BTreeMap::new();
        for (idx, pk) in BbsPlusKeys::iter_prefix(id) {
            let params = pk.params_ref.and_then(|r| BbsPlusParams::get(r.0, r.1));

            keys.insert(idx, (pk, params));
        }
        keys
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::did::tests::check_did_detail;
    use crate::did::AddControllers;
    use crate::test_common::*;
    use frame_support::assert_err;
    use sp_core::{sr25519, H256};

    fn sign_add_params<T: Config>(
        keypair: &sr25519::Pair,
        ap: &AddBBSPlusParams<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature<BBSPlusParamsOwner> {
        did_sig::<T, _, _>(ap, keypair, BBSPlusParamsOwner(signer), key_id)
    }

    fn sign_remove_params<T: Config>(
        keypair: &sr25519::Pair,
        rp: &RemoveBBSPlusParams<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature<BBSPlusParamsOwner> {
        did_sig::<T, _, _>(rp, keypair, BBSPlusParamsOwner(signer), key_id)
    }

    fn sign_add_key<T: Config>(
        keypair: &sr25519::Pair,
        ak: &AddBBSPlusPublicKey<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature<Controller> {
        did_sig::<T, _, _>(ak, keypair, Controller(signer), key_id)
    }

    fn sign_remove_key<T: Config>(
        keypair: &sr25519::Pair,
        rk: &RemoveBBSPlusPublicKey<T>,
        signer: Did,
        key_id: u32,
    ) -> DidSignature<Controller> {
        did_sig::<T, _, _>(rk, keypair, Controller(signer), key_id)
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
            let mut next_nonce = 5 + 1;
            check_nonce(&author, next_nonce - 1);

            run_to_block(6);

            let (author_1, author_1_kp) = newdid();
            let mut next_nonce_1 = 6 + 1;
            check_nonce(&author_1, next_nonce_1 - 1);

            run_to_block(10);

            let params_bytes = vec![1u8; 600];
            let mut params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: params_bytes,
            };
            let ap = AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);

            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_err!(
                BBSPlusMod::add_params(
                    Origin::signed(1),
                    AddBBSPlusParams {
                        params: params.clone(),
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsTooBig
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author),
                1u8.into()
            )));
            check_nonce(&author, next_nonce - 1);

            run_to_block(15);

            params.bytes = vec![1u8; 500];

            assert_err!(
                BBSPlusMod::add_params(
                    Origin::signed(1),
                    AddBBSPlusParams {
                        params: params.clone(),
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                did::Error::<Test>::InvalidSignature
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                None
            );
            assert!(!bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author),
                1u8.into()
            )));
            check_nonce(&author, next_nonce - 1);

            run_to_block(20);

            let ap = AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );

            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author),
                1u8.into()
            )));

            run_to_block(21);

            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
                None
            );
            let params_1 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let ap = AddBBSPlusParams {
                params: params_1.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params_1.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(2u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
                Some(params_1)
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author),
                2u8.into()
            )));

            run_to_block(25);

            let params_2 = BbsPlusParameters {
                label: Some(vec![0, 9, 1]),
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let ap = AddBBSPlusParams {
                params: params_2.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_params::<Test>(&author_1_kp, &ap, author_1.clone(), 1);
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
                None
            );
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params_2.clone(),
                    nonce: next_nonce_1,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(1u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
                Some(params_2.clone())
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(2u8)
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author_1),
                1u8.into()
            )));

            run_to_block(30);

            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                None
            );
            let params_3 = BbsPlusParameters {
                label: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let ap = AddBBSPlusParams {
                params: params_3.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params_3.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(3u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsAdded(
                BBSPlusParamsOwner(author),
                3u8.into()
            )));

            let rf = (BBSPlusParamsOwner(author.clone()), 5u8.into());
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (BBSPlusParamsOwner(author.clone()), 2u8.into());
            let mut rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce: next_nonce_1,
            };

            let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_params(Origin::signed(1), rp.clone(), sig.clone()),
                Error::<Test>::NotOwner
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            rp.nonce = next_nonce;
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
                Some(params_2.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
                BBSPlusParamsOwner(author),
                2u8.into()
            )));

            let rp = RemoveBBSPlusParams::<Test> {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(
                    Origin::signed(1),
                    RemoveBBSPlusParams {
                        params_ref: rf,
                        nonce: next_nonce
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (BBSPlusParamsOwner(author_1.clone()), 1u8.into());
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce: next_nonce_1,
            };
            let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(1u8)
            );
            // Entry gone from storage
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                Some(params_3.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
                BBSPlusParamsOwner(author_1),
                1u8.into()
            )));

            let rp = RemoveBBSPlusParams::<Test> {
                params_ref: rf,
                nonce: next_nonce_1,
            };
            let sig = sign_remove_params(&author_1_kp, &rp, author_1.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_params(
                    Origin::signed(1),
                    RemoveBBSPlusParams {
                        params_ref: rf,
                        nonce: next_nonce_1
                    },
                    sig.clone()
                ),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rf = (BBSPlusParamsOwner(author.clone()), 3u8.into());
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                None
            );
            // Other entries remain as it is
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
                BBSPlusParamsOwner(author),
                3u8.into()
            )));

            let rf = (BBSPlusParamsOwner(author.clone()), 1u8.into());
            let rp = RemoveBBSPlusParams {
                params_ref: rf,
                nonce: next_nonce,
            };
            let sig = sign_remove_params(&author_kp, &rp, author.clone(), 1);
            BBSPlusMod::remove_params(Origin::signed(1), rp, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(3u8)
            );
            // Entry gone from storage
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                None
            );
            assert!(bbs_plus_events().contains(&super::Event::ParamsRemoved(
                BBSPlusParamsOwner(author),
                1u8.into()
            )));
        });
    }

    #[test]
    fn add_remove_public_key() {
        ext().execute_with(|| {
            run_to_block(10);

            let (author, author_kp) = newdid();
            let mut next_nonce = 10 + 1;
            check_nonce(&author, next_nonce - 1);

            run_to_block(15);

            let mut key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 200],
            };
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);

            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::PublicKeyTooBig
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));
            check_nonce(&author, next_nonce - 1);

            run_to_block(30);

            key.bytes = vec![1u8; 100];
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: next_nonce,
            };

            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak.clone(), sig.clone()),
                did::Error::<Test>::InvalidSignature
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), None);
            assert!(!bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));
            check_nonce(&author, next_nonce - 1);

            run_to_block(35);

            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 2u8.into())));

            assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);
            let key_1 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![1u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), Some(key_1));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3u8.into())));

            run_to_block(45);

            let (author_1, author_kp_1) = newdid();
            let mut next_nonce_1 = 45 + 1;

            run_to_block(50);

            let key_2 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![9u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(1u8)), None);
            assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), None);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(2u8)),
                Some(key_2.clone())
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 2u8.into())));

            run_to_block(55);

            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(3u8)),
                None
            );
            let key_3 = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_3.clone(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(4u8)),
                Some(key_3.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 3u8.into())));

            run_to_block(60);

            let rf = (author.clone(), 5u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            let rf = (author.clone(), 3u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;

            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);
            // Other entries remain as it is
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(4u8)),
                Some(key_3.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), Some(key_2));

            let rf = (author.clone(), 3u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author, next_nonce - 1);

            run_to_block(70);

            let rf = (author_1.clone(), 2u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            next_nonce_1 += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author_1, IncId::from(2u8)), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(4u8)), Some(key_3));
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author_1, 2u8.into())));

            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_remove_key(&author_kp_1, &rk, author_1.clone(), 1);
            // Cannot remove as already removed
            assert_err!(
                BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()),
                Error::<Test>::PublicKeyDoesntExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);

            let rf = (author.clone(), 4u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(4u8)), None);
            // Other entries remain as it is
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), Some(key));
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 4u8.into())));

            let rf = (author.clone(), 2u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&author_kp, &rk, author.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            // Counter doesn't go back
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            // Entry gone from storage
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(2u8)), None);
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(author, 2u8.into())));

            run_to_block(80);

            let params = BbsPlusParameters {
                label: Some(vec![0, 1, 2, 3]),
                curve_type: CurveType::Bls12381,
                bytes: vec![19; 100],
            };
            let ap = AddBBSPlusParams {
                params: params.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_params::<Test>(&author_kp, &ap, author.clone(), 1);
            BBSPlusMod::add_params(
                Origin::signed(1),
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: next_nonce,
                },
                sig,
            )
            .unwrap();
            check_nonce(&author, next_nonce);
            next_nonce += 1;
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );

            // Add key with reference to non-existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((BBSPlusParamsOwner(author.clone()), 4u8.into())),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            assert_err!(
                BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()),
                Error::<Test>::ParamsDontExist
            );
            check_nonce(&author_1, next_nonce_1 - 1);
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );

            // Add key with reference to existent params
            let key_4 = BbsPlusPublicKey {
                params_ref: Some((BBSPlusParamsOwner(author.clone()), 1u8.into())),
                curve_type: CurveType::Bls12381,
                bytes: vec![92u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author_1.clone(),
                nonce: next_nonce_1,
            };
            let sig = sign_add_key(&author_kp_1, &ak, author_1.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            check_nonce(&author_1, next_nonce_1);
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(3u8)),
                Some(key_4.clone())
            );
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author_1, 3u8.into())));

            let ak = AddBBSPlusPublicKey {
                key: key_4.clone(),
                did: author.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&author_kp, &ak, author.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig.clone()).unwrap();
            check_nonce(&author, next_nonce);
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(5u8)), Some(key_4));
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(author, 5u8.into())));
        });
    }

    #[test]
    fn add_remove_public_key_by_controller() {
        ext().execute_with(|| {
            run_to_block(10);

            let (did, did_kp) = newdid();
            let mut next_nonce = 10 + 1;
            check_did_detail(&did, 1, 1, 1, next_nonce - 1);

            run_to_block(20);

            let (did_1, did_1_kp) = newdid();
            let mut next_nonce_1 = 20 + 1;
            check_nonce(&did_1, next_nonce_1 - 1);
            check_did_detail(&did_1, 1, 1, 1, next_nonce_1 - 1);

            // Make `did` controller of `did`
            let add_controllers = AddControllers {
                did: did_1.clone(),
                controllers: vec![did].into_iter().map(Controller).collect(),
                nonce: next_nonce_1,
            };
            let sig = did_sig::<_, _, _>(&add_controllers, &did_1_kp, Controller(did_1.clone()), 1);
            DIDModule::add_controllers(Origin::signed(1), add_controllers, sig).unwrap();
            assert!(DIDModule::is_controller(&did_1, &Controller(did.clone())));
            check_did_detail(&did_1, 1, 1, 2, next_nonce_1);
            check_did_detail(&did, 1, 1, 1, next_nonce - 1);
            next_nonce_1 += 1;

            let key = BbsPlusPublicKey {
                params_ref: None,
                curve_type: CurveType::Bls12381,
                bytes: vec![8u8; 100],
            };
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: did_1.clone(),
                nonce: next_nonce,
            };
            let sig = sign_add_key(&did_kp, &ak, did.clone(), 1);
            BBSPlusMod::add_public_key(Origin::signed(1), ak, sig).unwrap();

            check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
            check_did_detail(&did, 1, 1, 1, next_nonce);

            next_nonce += 1;

            assert_eq!(
                BbsPlusKeys::get(&did_1, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(BbsPlusKeys::get(&did, IncId::from(2u8)), None);
            assert!(bbs_plus_events().contains(&super::Event::KeyAdded(did_1, 2u8.into())));

            let rf = (did_1.clone(), 2u8.into());
            let rk = RemoveBBSPlusPublicKey {
                key_ref: rf,
                did: did_1.clone(),
                nonce: next_nonce,
            };
            let sig = sign_remove_key(&did_kp, &rk, did.clone(), 1);
            BBSPlusMod::remove_public_key(Origin::signed(1), rk.clone(), sig.clone()).unwrap();

            check_did_detail(&did_1, 2, 1, 2, next_nonce_1 - 1);
            check_did_detail(&did, 1, 1, 1, next_nonce);

            assert_eq!(BbsPlusKeys::get(&did_1, IncId::from(2u8)), None);
            assert!(bbs_plus_events().contains(&super::Event::KeyRemoved(did_1, 2u8.into())));
        })
    }

    #[test]
    fn add_params_keys() {
        ext().execute_with(|| {
            run_to_block(10);
            let (author, _) = newdid();
            let next_nonce = 10 + 1;

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

            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_2)),
                IncId::from(0u8)
            );

            run_to_block(35);

            assert!(BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: next_nonce
                },
                BBSPlusParamsOwner(author)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(1u8)
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(1u8)), None);
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );

            run_to_block(40);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(BbsPlusKeys::get(&author, IncId::from(3u8)), None);

            run_to_block(50);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone())
            );

            run_to_block(60);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert_eq!(did_detail.nonce + 1, ak.nonce);
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(4u8)),
                Some(key_2.clone())
            );

            run_to_block(70);

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            assert!(BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params_1.clone(),
                    nonce: did_detail.next_nonce()
                },
                BBSPlusParamsOwner(author)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author)),
                IncId::from(2u8)
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(3u8)),
                Some(key_1.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author, IncId::from(4u8)),
                Some(key_2.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(1u8)),
                Some(params.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author), IncId::from(2u8)),
                Some(params_1.clone())
            );

            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(0u8)
            );
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_2)),
                IncId::from(0u8)
            );

            run_to_block(80);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone())
            );

            run_to_block(90);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            assert!(BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: did_detail_1.next_nonce()
                },
                BBSPlusParamsOwner(author_1)
            )
            .is_ok());
            assert_eq!(
                ParamsCounter::get(&BBSPlusParamsOwner(author_1)),
                IncId::from(1u8)
            );
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(
                BbsPlusParams::get(&BBSPlusParamsOwner(author_1), IncId::from(1u8)),
                Some(params.clone())
            );

            run_to_block(100);

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            assert_eq!(did_detail_1.nonce + 1, ak.nonce);
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(2u8)),
                Some(key.clone())
            );
            assert_eq!(
                BbsPlusKeys::get(&author_1, IncId::from(3u8)),
                Some(key_1.clone())
            );
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
                params_ref: Some((BBSPlusParamsOwner(author.clone()), 1u8.into())),
                curve_type: CurveType::Bls12381,
                bytes: vec![2; 80],
            };
            let key_2 = BbsPlusPublicKey {
                params_ref: Some((BBSPlusParamsOwner(author_1.clone()), 1u8.into())),
                curve_type: CurveType::Bls12381,
                bytes: vec![3; 80],
            };

            assert_eq!(
                BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)).len(),
                0
            );
            assert_eq!(
                BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author_1)).len(),
                0
            );
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 0u8.into())),
                None
            );
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author_1, 0u8.into())),
                None
            );

            BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params.clone(),
                    nonce: 0, // Doesn't matter
                },
                BBSPlusParamsOwner(author),
            )
            .unwrap();
            BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params_1.clone(),
                    nonce: 0, // Doesn't matter
                },
                BBSPlusParamsOwner(author_1),
            )
            .unwrap();
            BBSPlusMod::add_params_(
                AddBBSPlusParams {
                    params: params_2.clone(),
                    nonce: 0, // Doesn't matter
                },
                BBSPlusParamsOwner(author_1),
            )
            .unwrap();

            assert_eq!(
                BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params.clone());
                    m
                }
            );

            assert_eq!(
                BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author_1)),
                {
                    let mut m = BTreeMap::new();
                    m.insert(1u8.into(), params_1.clone());
                    m.insert(2u8.into(), params_2.clone());
                    m
                }
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 2u8.into())),
                Some((key.clone(), None))
            );

            let did_detail_1 = DIDModule::onchain_did_details(&author_1).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_1.clone(),
                did: author_1.clone(),
                nonce: did_detail_1.next_nonce(),
            };
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author_1, 2u8.into())),
                Some((key_1.clone(), Some(params.clone())))
            );

            let did_detail = DIDModule::onchain_did_details(&author).unwrap();
            let ak = AddBBSPlusPublicKey {
                key: key_2.clone(),
                did: author.clone(),
                nonce: did_detail.next_nonce(),
            };
            assert!(<did::Module<Test>>::try_exec_action_over_onchain_did(
                ak,
                BBSPlusMod::add_public_key_
            )
            .is_ok());
            assert_eq!(
                BBSPlusMod::get_public_key_with_params(&(author, 3u8.into())),
                Some((key_2.clone(), Some(params_1.clone())))
            );

            assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author_1)), {
                let mut m = BTreeMap::new();
                m.insert(2u8.into(), (key_1.clone(), Some(params.clone())));
                m
            });

            assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author)), {
                let mut m = BTreeMap::new();
                m.insert(2u8.into(), (key.clone(), None));
                m.insert(3u8.into(), (key_2.clone(), Some(params_1.clone())));
                m
            });

            BbsPlusParams::remove(&BBSPlusParamsOwner(author), IncId::from(1u8));

            assert_eq!(
                BBSPlusMod::get_params_by_did(&BBSPlusParamsOwner(author)).len(),
                0
            );

            assert_eq!(BBSPlusMod::get_public_key_by_did(&Controller(author_1)), {
                let mut m = BTreeMap::new();
                m.insert(2u8.into(), (key_1.clone(), None));
                m
            });
        });
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks {
    use super::*;
    use crate::did::{Did, DidKey, DidSignature};
    use crate::keys_and_sigs::*;
    use crate::util::IncId;
    use crate::ToStateChange;
    use alloc::collections::BTreeSet;
    use core::iter::repeat;
    use frame_benchmarking::{benchmarks, whitelisted_caller};
    use sp_application_crypto::Pair;
    use sp_core::U256;
    use sp_core::{ecdsa, ed25519, sr25519};
    use sp_std::prelude::*;
    use system::RawOrigin;

    const MAX_PARAMS: u32 = 512;
    const MAX_LABEL: u32 = 128;
    const MAX_ACC: u32 = 128;
    const MAX_KEY: u32 = 256;

    crate::bench_with_all_pairs! {
        with_pairs:
        add_params_sr25519 for sr25519, add_params_ed25519 for ed25519, add_params_secp256k1 for secp256k1 {
            {
                let b in 0 .. MAX_PARAMS => ();
                let l in 1 .. MAX_LABEL => ();
            }
            let pair as Pair;
            let caller = whitelisted_caller();
            let did = Did([1; Did::BYTE_SIZE]);
            let public = pair.public();

            crate::did::Module::<T>::new_onchain_(
                did,
                vec![DidKey::new_with_all_relationships(public)],
                Default::default(),
            ).unwrap();

            let params = BbsPlusParameters {
                curve_type: CurveType::Bls12381,
                bytes: vec![0; b as usize],
                label: Some(vec![0; l as usize])
            };
            let new_params = AddBBSPlusParams {
                params: params.clone(),
                nonce: 1u8.into()
            };

            let sig = pair.sign(&new_params.to_state_change().encode());
            let signature = DidSignature::new(did, 1u32, sig);
        }: add_params(RawOrigin::Signed(caller), new_params, signature)
        verify {
            assert_eq!(BbsPlusParams::get(BBSPlusParamsOwner(did), IncId::from(1u8)).unwrap(), params.clone());
        }

        remove_params_sr25519 for sr25519, remove_params_ed25519 for ed25519, remove_params_secp256k1 for secp256k1 {
            {
                let b in 0 .. MAX_PARAMS;
            }
            let pair as Pair;
            let caller = whitelisted_caller();
            let did = Did([1; Did::BYTE_SIZE]);
            let public = pair.public();

            crate::did::Module::<T>::new_onchain_(
                did,
                vec![DidKey::new_with_all_relationships(public)],
                Default::default(),
            ).unwrap();

            Module::<T>::add_params_(
                AddBBSPlusParams {
                    params: BbsPlusParameters {
                        curve_type: CurveType::Bls12381,
                        bytes: vec![0; b as usize],
                        label: Some(vec![1; MAX_LABEL as usize])
                    },
                    nonce: 1u8.into()
                },
                BBSPlusParamsOwner(did)
            ).unwrap();

            let rem_params = RemoveBBSPlusParams {
                params_ref: (BBSPlusParamsOwner(did), 1u8.into()),
                nonce: 1u8.into()
            };

            let sig = pair.sign(&rem_params.to_state_change().encode());
            let signature = DidSignature::new(did, 1u32, sig);

        }: remove_params(RawOrigin::Signed(caller), rem_params, signature)
        verify {
            assert!(BbsPlusParams::get(BBSPlusParamsOwner(did), IncId::from(1u8)).is_none());
        }

        add_public_sr25519 for sr25519, add_public_ed25519 for ed25519, add_public_secp256k1 for secp256k1 {
            {
                let b in 0 .. MAX_KEY;
            }
            let pair as Pair;
            let caller = whitelisted_caller();
            let did = Did([1; Did::BYTE_SIZE]);
            let public = pair.public();

            crate::did::Module::<T>::new_onchain_(
                did,
                vec![DidKey::new_with_all_relationships(public)],
                Default::default(),
            ).unwrap();

            Module::<T>::add_params_(
                AddBBSPlusParams {
                    params: BbsPlusParameters {
                        curve_type: CurveType::Bls12381,
                        bytes: vec![0; MAX_PARAMS as usize],
                        label: Some(vec![1; MAX_LABEL as usize])
                    },
                    nonce: 1u8.into()
                },
                BBSPlusParamsOwner(did)
            ).unwrap();

            let key = BbsPlusPublicKey {
                curve_type: CurveType::Bls12381,
                bytes: vec![0; b as usize],
                /// The params used to generate the public key (`P_tilde` comes from params)
                params_ref: Some((BBSPlusParamsOwner(did), IncId::from(1u8)))
            };
            let add_key = AddBBSPlusPublicKey {
                did: Controller(did),
                key: key.clone(),
                nonce: 1u8.into()
            };

            let sig = pair.sign(&add_key.to_state_change().encode());
            let signature = DidSignature::new(did, 1u32, sig);

        }: add_public_key(RawOrigin::Signed(caller), add_key, signature)
        verify {
            assert_eq!(BbsPlusKeys::get(Controller(did), IncId::from(2u8)).unwrap(), key);
        }

        remove_public_sr25519 for sr25519, remove_public_ed25519 for ed25519, remove_public_secp256k1 for secp256k1 {
            {
                let b in 0 .. MAX_KEY;
            }
            let pair as Pair;
            let caller = whitelisted_caller();
            let did = Did([1; Did::BYTE_SIZE]);
            let public = pair.public();

            crate::did::Module::<T>::new_onchain_(
                did,
                vec![DidKey::new_with_all_relationships(public)],
                Default::default(),
            ).unwrap();

            Module::<T>::add_params_(
                AddBBSPlusParams {
                    params: BbsPlusParameters {
                        curve_type: CurveType::Bls12381,
                        bytes: vec![0; MAX_PARAMS as usize],
                        label: Some(vec![1; MAX_LABEL as usize])
                    },
                    nonce: 1u8.into()
                },
                BBSPlusParamsOwner(did)
            ).unwrap();

            Module::<T>::add_public_key_(
                AddBBSPlusPublicKey {
                    did: Controller(did),
                    key: BbsPlusPublicKey {
                        curve_type: CurveType::Bls12381,
                        bytes: vec![0; b as usize],
                        /// The params used to generate the public key (`P_tilde` comes from params)
                        params_ref: Some((BBSPlusParamsOwner(did), IncId::from(1u8)))
                    },
                    nonce: 2u8.into()
                },
                &mut Default::default()
            ).unwrap();

            let rem_key = RemoveBBSPlusPublicKey {
                //did: Controller(did),
                key_ref: (Controller(did), 1u8.into()),
                nonce: 1u8.into()
            };

            let sig = pair.sign(&rem_key.to_state_change().encode());
            let signature = DidSignature::new(did, 1u32, sig);


        }: remove_public_key(RawOrigin::Signed(caller), rem_key, signature)
        verify {
            assert!(BbsPlusKeys::get(Controller(did), IncId::from(2u8)).is_none());
        }
    }
}
