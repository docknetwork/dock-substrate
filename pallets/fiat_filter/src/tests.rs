// TODO rm
mod old {
    // use crate::*;
    // use codec::{Decode, Encode};
    // use core_mods::{anchor, did};
    // use frame_support::dispatch::{DispatchInfo, Dispatchable};
    // use frame_support::traits::{Filter, IsSubType};
    // use frame_support::weights::DispatchClass;
    // use frame_support::{impl_outer_dispatch, impl_outer_origin, parameter_types};
    // use frame_system as system;
    // use rand::random;
    // use sp_core::H256;
    // use sp_core::{sr25519, Pair};
    // use sp_runtime::{
    //     testing::Header,
    //     traits::{BlakeTwo256, IdentityLookup},
    // };

    // // impl_outer_dispatch! {
    // //     pub enum Call for TestRt where origin: Origin {
    // //         did::DIDMod,
    // //         anchor::AnchorMod,
    // //         blob::BlobMod,
    // //         revoke::RevokeMod,
    // //         attest::AttestMod,
    // //         system::SystemMod,
    // //         balance::BalanceMod,
    // //     }
    // // }
    // #[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
    // pub enum TestCall {
    //     System(system::Call<TestRt>),
    //     Balance(pallet_balances::Call<TestRt>),
    //     Did(did::Call<TestRt>),
    //     Anchor(anchor::Call<TestRt>),
    //     Blob(blob::Call<TestRt>),
    //     Revoke(revoke::Call<TestRt>),
    //     Attest(attest::Call<TestRt>),
    // }
    // impl Dispatchable for TestCall {
    //     type Origin = Origin;
    //     type Config = ();
    //     type Info = ();
    //     type PostInfo = PostDispatchInfo;
    //     fn dispatch(self, origin: Self::Origin) -> sp_runtime::DispatchResultWithInfo<Self::PostInfo> {
    //         match self {
    //             TestCall::System(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Balance(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Did(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Anchor(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Blob(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Revoke(c) => c.dispatch_bypass_filter(origin),
    //             TestCall::Attest(c) => c.dispatch_bypass_filter(origin),
    //         }
    //     }
    // }
    // impl UnfilteredDispatchable for TestCall {
    //     type Origin = Origin;

    //     fn dispatch_bypass_filter(self, origin: Self::Origin) -> DispatchResultWithPostInfo {
    //         self.dispatch(origin)
    //     }
    // }
    // impl GetDispatchInfo for TestCall {
    //     fn get_dispatch_info(&self) -> DispatchInfo {
    //         DispatchInfo {
    //             weight: 101u64,
    //             class: DispatchClass::Normal,
    //             pays_fee: Pays::Yes,
    //         }
    //     }
    // }
    // impl IsSubType<did::Call<TestRt>> for TestCall {
    //     fn is_sub_type(&self) -> Option<&did::Call<TestRt>> {
    //         match self {
    //             Self::Did(ref r) => Some(r),
    //             _ => None,
    //         }
    //     }
    // }
    // impl IsSubType<anchor::Call<TestRt>> for TestCall {
    //     fn is_sub_type(&self) -> Option<&anchor::Call<TestRt>> {
    //         match self {
    //             Self::Anchor(ref r) => Some(r),
    //             _ => None,
    //         }
    //     }
    // }
    // impl IsSubType<blob::Call<TestRt>> for TestCall {
    //     fn is_sub_type(&self) -> Option<&blob::Call<TestRt>> {
    //         match self {
    //             Self::Blob(ref r) => Some(r),
    //             _ => None,
    //         }
    //     }
    // }
    // impl IsSubType<revoke::Call<TestRt>> for TestCall {
    //     fn is_sub_type(&self) -> Option<&revoke::Call<TestRt>> {
    //         match self {
    //             Self::Revoke(ref r) => Some(r),
    //             _ => None,
    //         }
    //     }
    // }
    // impl IsSubType<attest::Call<TestRt>> for TestCall {
    //     fn is_sub_type(&self) -> Option<&attest::Call<TestRt>> {
    //         match self {
    //             Self::Attest(ref r) => Some(r),
    //             _ => None,
    //         }
    //     }
    // }

    // // pub struct BaseFilter;
    // // impl Filter<TestCall> for BaseFilter {
    // //     fn filter(call: &TestCall) -> bool {
    // //         match call {
    // //             // filter out core_mods TestCalls so they're only done through fiat_filter
    // //             TestCall::AnchorMod(_) => false,
    // //             TestCall::BlobMod(_) => false,
    // //             TestCall::DIDMod(_) => false,
    // //             TestCall::RevokeMod(_) => false,
    // //             TestCall::AttestMod(_) => false,
    // //             _ => true,
    // //         }
    // //     }
    // // }

    // type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<TestRt>;
    // type Block = frame_system::mocking::MockBlock<TestRt>;
    // frame_support::construct_runtime!(
    //     pub enum TestRt where
    //         Block = Block,
    //         NodeBlock = Block,
    //         UncheckedExtrinsic = UncheckedExtrinsic,
    //     {
    //         System: frame_system::{Module, Call, Config, Storage, Event<T>},
    //         // Balances: pallet_balances::{Module, Call, Storage, Config<T>, Event<T>},
    //         Balances: balances::{Module, Call, Storage},
    //         DIDMod: did::{Module, Call, Storage, Event, Config},
    //         RevokeMod: revoke::{Module, Call, Storage},
    //         BlobMod: blob::{Module, Call, Storage},
    //         AnchorMod: anchor::{Module, Call, Storage, Event<T>},
    //         AttestMod: attest::{Module, Call, Storage},
    //     }
    // );

    // impl Config for TestRt {
    //     type PriceProvider = TestPriceProvider;
    //     type Call = TestCall;
    //     type Currency = pallet_balances::Module<Self>;
    // }

    // parameter_types! {
    //     pub const BlockHashCount: u64 = 250;
    // }
    // impl system::Config for TestRt {
    //     type BaseCallFilter = (); // not needed since we use bypass_filter in our impl of Dispatchable for TestCall
    //     type Origin = Origin;
    //     type Call = TestCall;
    //     type Index = u64;
    //     type BlockNumber = u64;
    //     type Hash = H256;
    //     type Hashing = BlakeTwo256;
    //     type AccountId = u64;
    //     type Lookup = IdentityLookup<Self::AccountId>;
    //     type Header = Header;
    //     type Event = ();
    //     type BlockHashCount = BlockHashCount;
    //     type DbWeight = ();
    //     type BlockWeights = ();
    //     type BlockLength = ();
    //     type Version = ();
    //     type PalletInfo = PalletInfo;
    //     type AccountData = pallet_balances::AccountData<u64>;
    //     type OnNewAccount = ();
    //     type OnKilledAccount = ();
    //     type SystemWeightInfo = ();
    //     type SS58Prefix = ();
    // }

    // // impl_outer_origin! {
    // //     pub enum Origin for TestRt where system = frame_system {}
    // // }
    // // type SystemMod = frame_system::Module<TestRt>;
    // // type DidMod = did::Module<TestRt>;
    // // type AnchorMod = anchor::Module<TestRt>;
    // // type BlobMod = blob::Module<TestRt>;
    // // type RevokeMod = revoke::Module<TestRt>;
    // // type AttestMod = attest::Module<TestRt>;
    // // type BalanceMod = pallet_balances::Module<TestRt>;

    // // Configure a mock runtime to test the pallet.
    // // #[derive(Clone, Eq, PartialEq)]
    // // pub struct TestRt {}
    // // parameter_types! {
    // //     pub const BlockHashCount: u64 = 250;
    // // }

    // // impl system::Config for TestRt {
    // //     type BaseCallFilter = BaseFilter;
    // //     type Origin = Origin;
    // //     type Call = TestCall;
    // //     type Index = u64;
    // //     type BlockNumber = u64;
    // //     type Hash = H256;
    // //     type Hashing = BlakeTwo256;
    // //     type AccountId = u64;
    // //     type Lookup = IdentityLookup<Self::AccountId>;
    // //     type Header = Header;
    // //     type Event = ();
    // //     type BlockHashCount = BlockHashCount;
    // //     type DbWeight = ();
    // //     type Version = ();
    // //     type PalletInfo = PalletInfo;
    // //     type AccountData = pallet_balances::AccountData<u64>;
    // //     type OnNewAccount = ();
    // //     type OnKilledAccount = ();
    // //     type SystemWeightInfo = ();
    // //     type BlockWeights = ();
    // //     type BlockLength = ();
    // //     type SS58Prefix = ();
    // // }

    // parameter_types! {
    //     pub const ExistentialDeposit: u64 = 1;
    // }
    // impl pallet_balances::Config for TestRt {
    //     type MaxLocks = ();
    //     type Balance = u64;
    //     type Event = ();
    //     type DustRemoval = ();
    //     type ExistentialDeposit = ExistentialDeposit;
    //     type AccountStore = System;
    //     type WeightInfo = ();
    // }
    // impl anchor::Trait for TestRt {
    //     type Event = ();
    // }
    // impl did::Trait for TestRt {
    //     type Event = ();
    // }
    // impl revoke::Trait for TestRt {}

    // parameter_types! {
    //     pub const MaxBlobSize: u32 = 1024;
    //     pub const StorageWeight: Weight = 1100;
    // }
    // impl blob::Trait for TestRt {
    //     type MaxBlobSize = MaxBlobSize;
    //     type StorageWeight = StorageWeight;
    // }

    // impl attest::Trait for TestRt {
    //     type StorageWeight = StorageWeight;
    // }

    // pub struct TestPriceProvider;
    // impl common::PriceProvider for TestPriceProvider {
    //     fn get_dock_usd_price() -> Option<(u32, u64)> {
    //         Some((RATE_DOCK_USD, 0))
    //     }
    //     fn optimized_get_dock_usd_price() -> Option<(u32, u64)> {
    //         Some((RATE_DOCK_USD, 0))
    //     }
    // }

    // pub type FiatFilterModule = Module<TestRt>;

    // const ALICE: u64 = 100;
    // const BOB: u64 = 200;
    // // Build genesis storage according to the mock runtime.
    // pub fn ext() -> sp_io::TestExternalities {
    //     let mut ret: sp_io::TestExternalities = system::GenesisConfig::default()
    //         .build_storage::<TestRt>()
    //         .unwrap()
    //         .into();
    //     ret.execute_with(|| {
    //         let _ = <TestRt as Config>::Currency::deposit_creating(&ALICE, 100_000_000_000);
    //     });
    //     ret
    // }
    // pub fn new_test_ext() -> sp_io::TestExternalities {
    //     let mut t = system::GenesisConfig::default()
    //         .build_storage::<TestRt>()
    //         .unwrap();
    //     // pallet_balances::GenesisConfig::<TestRt> {
    //     //     balances: vec![(1, 10), (2, 20), (3, 30), (4, 40), (5, 50), (6, 60)],
    //     // }
    //     // .assimilate_storage(&mut t)
    //     // .unwrap();

    //     let mut ext = sp_io::TestExternalities::new(t);
    //     ext.execute_with(|| System::set_block_number(1));
    //     ext
    // }
    // // pub fn ext_price2() -> sp_io::TestExternalities {
    // //     let mut ret: sp_io::TestExternalities = system::GenesisConfig::default()
    // //         .build_storage::<testrt_price2::TestRt>()
    // //         .unwrap()
    // //         .into();
    // //     ret.execute_with(|| {
    // //         let _ = <TestRt as Config>::Currency::deposit_creating(&ALICE, 100_000_000_000);
    // //     });
    // //     ret
    // // }

    // /// generate a random keypair
    // pub fn gen_kp() -> sr25519::Pair {
    //     sr25519::Pair::generate_with_phrase(None).0
    // }
    // /// get the latest block number
    // pub fn block_no() -> u64 {
    //     system::Module::<TestRt>::block_number()
    // }
    // // Create did for `did`. Return the randomly generated signing key.
    // // The did public key is controlled by some non-existent account (normally a security
    // // concern), but that doesn't matter for our purposes.
    // pub fn create_did(origin: u64, did: did::Did) -> sr25519::Pair {
    //     let kp = gen_kp();
    //     let pubkey_bytes = did::Bytes32 {
    //         value: kp.public().0,
    //     };
    //     let didpubkey = did::PublicKey::Sr25519(pubkey_bytes);
    //     let key_detail = did::KeyDetail::new(did, didpubkey);
    //     did::Module::<TestRt>::new(Origin::signed(origin), did, key_detail).unwrap();
    //     kp
    // }
    // /// create a did with a random id and random signing key
    // pub fn newdid(origin: u64) -> (did::Did, sr25519::Pair) {
    //     let d: did::Did = rand::random();
    //     (d, create_did(origin, d))
    // }

    // pub fn sign(payload: &StateChange, keypair: &sr25519::Pair) -> did::DidSignature {
    //     did::DidSignature::Sr25519(did::Bytes64 {
    //         value: keypair.sign(&payload.encode()).0,
    //     })
    // }

    // /// create a random byte array with set len
    // pub fn random_bytes(len: usize) -> Vec<u8> {
    //     let ret: Vec<u8> = (0..len).map(|_| rand::random()).collect();
    //     assert_eq!(ret.len(), len);
    //     ret
    // }

    // fn measure_fees(call: TestCall) -> (u64, DispatchResultWithPostInfo) {
    //     let balance_pre = <TestRt as Config>::Currency::free_balance(ALICE);
    //     let executed = FiatFilterModule::execute_call(Origin::signed(ALICE), Box::new(call.clone()));
    //     let balance_post = <TestRt as Config>::Currency::free_balance(ALICE);
    //     let fee_microdock = balance_pre - balance_post;
    //     return (fee_microdock, executed);
    // }
    // fn exec_assert_fees(call: TestCall, expected_fees: u64) -> (u64, DispatchResultWithPostInfo) {
    //     let (fee_microdock, executed) = measure_fees(call);
    //     assert_ok!(executed);

    //     let pdi = executed.unwrap();
    //     assert!(pdi.pays_fee == Pays::No);
    //     assert_eq!(fee_microdock, expected_fees);
    //     return (fee_microdock, executed);
    // }
}

use crate::test_mock::*;
use crate::{
    PRICE_ANCHOR_OP_PER_BYTE, PRICE_ATTEST_PER_IRI_BYTE, PRICE_BLOB_OP_PER_BYTE, PRICE_DID_OP,
    PRICE_REVOKE_OP_CONST_FACTOR, PRICE_REVOKE_PER_REVOCATION, PRICE_REVOKE_REGISTRY_OP,
};
use codec::Encode;
use core_mods::StateChange;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::traits::Currency;
use frame_support::weights::Pays;
use frame_support::{assert_noop, assert_ok, assert_err};
use frame_system::RawOrigin;
use rand::random;
use sp_core::{sr25519, Pair};

// type SystemMod = frame_system::Module<TestRt>;
// type AnchorMod = anchor::Module<TestRt>;
// type BlobMod = blob::Module<TestRt>;
// type RevokeMod = revoke::Module<TestRt>;
// type AttestMod = attest::Module<TestRt>;
// type BalanceMod = pallet_balances::Module<TestRt>;

mod tests_did_calls {
    use super::*;
    use did::{
        Bytes32, Bytes64, DidRemoval, DidSignature, KeyDetail, KeyUpdate, PublicKey, DID_BYTE_SIZE,
    };

    type DidMod = did::Module<TestRt>;

    #[test]
    fn call_did_new() {
        ext().execute_with(|| {
            let d: did::Did = rand::random();
            let kp = gen_kp();
            let key_detail = did::KeyDetail::new(
                d,
                did::PublicKey::Sr25519(did::Bytes32 {
                    value: kp.public().0,
                }),
            );

            let call = Call::DIDMod(did::Call::<TestRt>::new(d.clone(), key_detail));
            let expected_fees: u64 = PRICE_DID_OP / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
    #[test]
    fn call_did_update_key__OK() {
        ext().execute_with(|| {
            let did_alice = [1; DID_BYTE_SIZE];
            let (pair_1, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_1 = pair_1.public().0;
            let detail = KeyDetail::new(
                did_alice.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_1 }),
            );

            // Add a DID
            let new_res = DidMod::new(Origin::signed(ALICE), did_alice.clone(), detail.clone());
            assert_ok!(new_res);

            let (_current_detail, modified_in_block) = DidMod::get_key_detail(&did_alice).unwrap();

            // Correctly update DID's key.
            // Prepare a key update
            let (pair_2, _, _) = sr25519::Pair::generate_with_phrase(None);
            let pk_2 = pair_2.public().0;
            let key_update = KeyUpdate::new(
                did_alice.clone(),
                PublicKey::Sr25519(Bytes32 { value: pk_2 }),
                None,
                modified_in_block as u32,
            );
            let sig_value = pair_1
                .sign(&StateChange::KeyUpdate(key_update.clone()).encode())
                .0;
            let sig = DidSignature::Sr25519(did::Bytes64 { value: sig_value });

            // Signing with the current key (`pair_1`) to update to the new key (`pair_2`)
            let call = Call::DIDMod(did::Call::<TestRt>::update_key(key_update, sig));
            let expected_fees: u64 = PRICE_DID_OP / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
    #[test]
    fn call_did_remove() {
        ext().execute_with(|| {
            let (did_alice, kp) = newdid(ALICE);
            let blockno = block_no() as u32;

            let to_remove = DidRemoval::new(did_alice.clone(), blockno);
            let sig = DidSignature::Sr25519(Bytes64 {
                value: kp
                    .sign(&StateChange::DIDRemoval(to_remove.clone()).encode())
                    .0,
            });

            let call = Call::DIDMod(did::Call::<TestRt>::remove(to_remove, sig));
            let expected_fees: u64 = PRICE_DID_OP / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
}

#[test]
fn call_anchor_deploy() {
    use anchor;

    ext().execute_with(|| {
        let dat = (0..32).map(|_| rand::random()).collect();

        let call = Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat));
        let expected_fees: u64 = 32 * PRICE_ANCHOR_OP_PER_BYTE / RATE_DOCK_USD as u64;
        let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
    });
}

mod test_attest_calls {
    use super::*;

    #[test]
    fn call_attest__iri_none() {
        use attest::Attestation;

        ext().execute_with(|| {
            let (attester, kp) = newdid(ALICE);
            let att = Attestation {
                priority: 1,
                iri: None,
            };
            let size_attested: u64 = att.iri.clone().unwrap_or([1].to_vec()).len() as u64;
            assert_eq!(size_attested, 1);
            let sig = sign(&StateChange::Attestation((attester, att.clone())), &kp);

            let call = Call::AttestMod(attest::Call::<TestRt>::set_claim(attester, att, sig));
            let expected_fees: u64 =
                size_attested * PRICE_ATTEST_PER_IRI_BYTE / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }

    #[test]
    fn call_attest__iri_some() {
        use attest::Attestation;

        ext().execute_with(|| {
            let (attester, kp) = newdid(ALICE);
            let att = Attestation {
                priority: 1,
                iri: Some("http://hello.world".as_bytes().to_vec()),
            };
            let size_attested: u64 = att.iri.clone().unwrap_or([1].to_vec()).len() as u64;
            assert_eq!(size_attested, 18);
            let sig = sign(&StateChange::Attestation((attester, att.clone())), &kp);

            let call = Call::AttestMod(attest::Call::<TestRt>::set_claim(attester, att, sig));
            let expected_fees: u64 =
                size_attested * PRICE_ATTEST_PER_IRI_BYTE / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
        });
    }
}

#[test]
fn call_blob_new() {
    use blob::{Blob, BlobId};
    ext().execute_with(|| {
        let id: BlobId = rand::random();
        let noise = random_bytes(999);
        let (author, author_kp) = newdid(ALICE);
        let blob = Blob {
            id,
            blob: noise.clone(),
            author,
        };
        let sig = sign(&StateChange::Blob(blob.clone()), &author_kp);

        let call = Call::BlobMod(blob::Call::<TestRt>::new(blob, sig));

        let expected_fees: u64 = 999 * PRICE_BLOB_OP_PER_BYTE / RATE_DOCK_USD as u64;
        let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);
    });
}

mod tests_revoke_calls {
    use super::*;
    use did::Did;
    use revoke::{Policy, Registry, RegistryId, RemoveRegistry, Revoke, RevokeId, UnRevoke};

    pub const REV_ID: RevokeId = [7u8; 32];

    pub fn policy_oneof(dids: &[Did]) -> Policy {
        Policy::OneOf(dids.iter().cloned().collect())
    }
    pub fn new_reg(did: Did) -> (RegistryId, Registry) {
        pub const REG_ID: RegistryId = [3u8; 32];
        let reg = Registry {
            policy: policy_oneof(&[did]),
            add_only: false,
        };
        let created = RevokeMod::new_registry(Origin::signed(ALICE), REG_ID, reg.clone());
        assert_ok!(created);
        (REG_ID, reg)
    }

    #[test]
    fn call_revoke_revoke() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);

            let cases: &[&[RevokeId]] = &[
                &[],
                &[random()],
                &[random(), random()],
                &[random(), random(), random()],
                &[REV_ID], // Test idempotence, step 1
                &[REV_ID], // Test idempotence, step 2
            ];
            for ids in cases {
                let revoke = Revoke {
                    registry_id: reg_id,
                    revoke_ids: ids.iter().cloned().collect(),
                    last_modified: block_no() as u32,
                };
                let revocation_size: u64 = ids.len() as u64;
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::Revoke(revoke.clone()), &kp_alice),
                ))
                .collect();

                let call = Call::RevokeMod(revoke::Call::<TestRt>::revoke(revoke, proof));
                let expected_fees_nusd: u64 =
                    PRICE_REVOKE_OP_CONST_FACTOR + revocation_size * PRICE_REVOKE_PER_REVOCATION;
                let expected_fees: u64 = expected_fees_nusd / RATE_DOCK_USD as u64;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                // assert ids in registry
                for rev_id in ids.iter() {
                    let rev_status = RevokeMod::get_revocation_status(reg_id, rev_id);
                    assert!(rev_status.is_some())
                }
            }
        });
    }

    #[test]
    fn call_revoke_unrevoke() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);
            let last_modified = block_no() as u32;

            let cases: &[&[RevokeId]] = &[
                &[],
                &[random()],
                &[random(), random()],
                &[random(), random(), random()],
                &[REV_ID], // Test idempotence, step 1
                &[REV_ID], // Test idempotence, step 2
            ];
            for ids in cases {
                for id in ids.iter() {
                    // assert not revoked
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, None);
                }

                // 1. revoke
                let revoke = Revoke {
                    registry_id: reg_id,
                    revoke_ids: ids.iter().cloned().collect(),
                    last_modified,
                };
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::Revoke(revoke.clone()), &kp_alice),
                ))
                .collect();
                let revoke_res = RevokeMod::revoke(Origin::signed(ALICE), revoke.clone(), proof);
                assert_ok!(revoke_res);
                // assert revoked
                for id in ids.iter() {
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, Some(()));
                }

                // 2. unrevoke
                let unrevoke = UnRevoke {
                    registry_id: reg_id,
                    revoke_ids: revoke.revoke_ids.clone(),
                    last_modified,
                };
                let unrevoke_size: u64 = unrevoke.revoke_ids.len() as u64;
                let proof = std::iter::once((
                    did_alice,
                    sign(&StateChange::UnRevoke(unrevoke.clone()), &kp_alice),
                ))
                .collect();

                let call = Call::RevokeMod(revoke::Call::<TestRt>::unrevoke(unrevoke, proof));
                let expected_fees_nusd: u64 =
                    PRICE_REVOKE_OP_CONST_FACTOR + unrevoke_size * PRICE_REVOKE_PER_REVOCATION;
                let expected_fees: u64 = expected_fees_nusd / RATE_DOCK_USD as u64;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                // assert unrevoked
                for id in ids.iter() {
                    let revoke_status = RevokeMod::get_revocation_status(reg_id, id);
                    assert_eq!(revoke_status, None);
                }
            }
        });
    }

    #[test]
    fn call_revoke_new_registry() {
        ext().execute_with(|| {
            let (did_alice, _) = newdid(ALICE);
            let (did_bob, _) = newdid(BOB);

            let cases: &[(Policy, bool)] = &[
                (policy_oneof(&[did_alice]), false),
                (policy_oneof(&[did_alice, did_bob]), false),
                (policy_oneof(&[did_alice]), true),
                (policy_oneof(&[did_alice, did_bob]), true),
            ];
            for (policy, add_only) in cases.iter().cloned() {
                let reg_id = random();
                let reg = Registry { policy, add_only };

                let got_reg = <revoke::Module<TestRt>>::get_revocation_registry(reg_id);
                assert!(got_reg.is_none());

                let call =
                    Call::RevokeMod(revoke::Call::<TestRt>::new_registry(reg_id, reg.clone()));

                let expected_fees: u64 = PRICE_REVOKE_REGISTRY_OP / RATE_DOCK_USD as u64;
                let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

                let got_reg = <revoke::Module<TestRt>>::get_revocation_registry(reg_id);
                assert!(got_reg.is_some());
                let (created_reg, created_bloc) = got_reg.unwrap();
                assert_eq!(created_reg, reg);
                assert_eq!(created_bloc, block_no());
            }
        });
    }
    #[test]
    fn call_revoke_remove_registry() {
        ext().execute_with(|| {
            let (did_alice, kp_alice) = newdid(ALICE);
            let (reg_id, _reg) = new_reg(did_alice);
            let last_modified = block_no() as u32;

            // destroy reg
            let rem = RemoveRegistry {
                registry_id: reg_id,
                last_modified,
            };
            let proof = std::iter::once((
                did_alice,
                sign(&StateChange::RemoveRegistry(rem.clone()), &kp_alice),
            ))
            .collect();

            let call = Call::RevokeMod(revoke::Call::<TestRt>::remove_registry(rem, proof));

            let expected_fees: u64 = PRICE_REVOKE_REGISTRY_OP / RATE_DOCK_USD as u64;
            let (_fee_microdock, _executed) = exec_assert_fees(call, expected_fees);

            // assert registry removed
            let got_reg = RevokeMod::get_revocation_registry(reg_id);
            assert_eq!(got_reg, None);
        });
    }
}

mod tests_fail_modes {
    use super::*;
    use crate::Config;
    use frame_support::dispatch::DispatchError;

    #[test]
    fn anchor_new__Err_no_balance() {
        ext().execute_with(|| {
            // empty alice's balance
            let _ = <TestRt as Config>::Currency::make_free_balance_be(&ALICE, 0);
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();
            // execute call
            let (_fee_microdock, executed) =
                measure_fees(Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat)));
            assert_noop!(
                executed,
                DispatchError::Module {
                    index: 1,
                    error: 3,
                    message: Some("InsufficientBalance")
                },
            );
        });
    }

    #[test]
    fn anchor_new__Err_insufficient_balance() {
        ext().execute_with(|| {
            // reduce alice's balance to just under the required fee
            let _ = <TestRt as Config>::Currency::make_free_balance_be(&ALICE, 20);
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();
            // execute call
            let (_fee_microdock, executed) =
                measure_fees(Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat)));
            assert_noop!(
                executed,
                DispatchError::Module {
                    index: 1,
                    error: 3,
                    message: Some("InsufficientBalance")
                },
            );
        });
    }

    #[test]
    fn anchor_new__Err_unsigned() {
        ext().execute_with(|| {
            // prepare data
            let dat = (0..32).map(|_| rand::random()).collect();

            // execute call
            let balance_pre = <TestRt as Config>::Currency::free_balance(ALICE);
            let call = Call::AnchorMod(anchor::Call::<TestRt>::deploy(dat));
            let executed =
                FiatFilterModule::execute_call(RawOrigin::None.into(), Box::new(call.clone()));
            let balance_post = <TestRt as Config>::Currency::free_balance(ALICE);
            let fee_microdock = balance_pre - balance_post;

            assert_noop!(executed, DispatchError::BadOrigin);

            // the call signature isn't valid, we can't charge the account any fees
            assert_eq!(fee_microdock, 0);
        });
    }

    #[test]
    fn balance_transfer__Err_unexpectedCall() {
        ext().execute_with(|| {
            // prepare data
            let call = Call::Balances(pallet_balances::Call::<TestRt>::transfer(BOB, 200));

            // // execute call
            let (fee_microdock, executed) = measure_fees(call);

            let pdi = executed.unwrap_err();
            // Comparing error with assert_noop will be brittle as that would contain weight which can change over time
            assert_eq!(pdi.error, DispatchError::from(Error::<TestRt>::UnexpectedCall));
            assert_eq!(pdi.post_info.pays_fee, Pays::Yes);
            assert!(pdi.post_info.actual_weight.is_some());

            // the call signature isn't valid, we can't charge the account any fees
            assert_eq!(fee_microdock, 0);
        });
    }
}

// mod tests_dock_fiat_rate {
//     use crate::*;
//     use frame_support::assert_ok;

//     #[test]
//     fn call_anchor_deploy__OK_different_rate() {
//         super::ext_price2().execute_with(|| {
//             use super::testrt_price2::TestRt as TestRtPrice2;
//             use super::testrt_price2::*;
//             use super::{ALICE, RATE_DOCK_USD_2};

//             let dat = (0..32).map(|_| rand::random()).collect();
//             let call = TestCall::AnchorMod(anchor::Call::<TestRt>::deploy(dat));

//             let expected_fees: u64 = 32 * PRICE_ANCHOR_OP_PER_BYTE / RATE_DOCK_USD_2 as u64;

//             let balance_pre = <TestRtPrice2 as Config>::Currency::free_balance(ALICE);
//             let executed =
//                 FiatFilterModule::execute_call(Origin::signed(ALICE), Box::new(call.clone()));
//             let balance_post = <TestRtPrice2 as Config>::Currency::free_balance(ALICE);
//             let fee_microdock = balance_pre - balance_post;

//             assert_ok!(executed);
//             let pdi = executed.unwrap();
//             assert!(pdi.pays_fee == Pays::No);
//             assert_eq!(fee_microdock, expected_fees);
//         });
//     }
// }
