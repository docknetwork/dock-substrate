use crate as fiat_filter;
pub use crate::{Config, Error, Module};
use codec::Encode;
use core_mods::StateChange;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::assert_ok;
use frame_support::dispatch::DispatchResultWithPostInfo;
use frame_support::parameter_types;
use frame_support::traits::{Currency, Filter};
use frame_support::weights::{Pays, Weight};
use frame_system as system;
use sp_core::H256;
use sp_core::{sr25519, Pair};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
use std::cell::RefCell;

pub struct BaseFilter;
impl Filter<Call> for BaseFilter {
    fn filter(call: &Call) -> bool {
        match call {
            _ => true,
        }
    }
}

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<TestRt>;
type Block = frame_system::mocking::MockBlock<TestRt>;
frame_support::construct_runtime!(
    pub enum TestRt where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Module, Call, Storage},
        DIDMod: did::{Module, Call, Storage, Event, Config},
        RevokeMod: revoke::{Module, Call, Storage},
        BlobMod: blob::{Module, Call, Storage},
        AnchorMod: anchor::{Module, Call, Storage, Event<T>},
        AttestMod: attest::{Module, Call, Storage},
        FiatFilterModule: fiat_filter::{Module, Call},
    }
);

impl Config for TestRt {
    type PriceProvider = TestPriceProvider;
    type Call = Call;
    type Currency = Balances;
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
}
impl system::Config for TestRt {
    type BaseCallFilter = BaseFilter;
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type DbWeight = ();
    type BlockWeights = ();
    type BlockLength = ();
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}
impl pallet_balances::Config for TestRt {
    type MaxLocks = ();
    type Balance = u64;
    type Event = ();
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
}
impl anchor::Trait for TestRt {
    type Event = ();
}
impl did::Trait for TestRt {
    type Event = ();
}
impl revoke::Trait for TestRt {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const StorageWeight: Weight = 1100;
}
impl blob::Trait for TestRt {
    type MaxBlobSize = MaxBlobSize;
    type StorageWeight = StorageWeight;
}

impl attest::Trait for TestRt {
    type StorageWeight = StorageWeight;
}

// the DOCK/USD rate in the price_feed pallet is the price of 1DOCK,
// expressed in USD_1000th/DOCK (as u32) (== USD/1000DOCK)
// the rate is ~0.072224 USD/DOCK in 2021-03
thread_local! {
    pub static RATE_DOCK_USD: RefCell<Option<u32>> = RefCell::new(Some(72));
}

pub struct TestPriceProvider;

impl TestPriceProvider {
    pub fn get() -> Option<u32> {
        RATE_DOCK_USD.with(|v| *v.borrow())
    }
}
impl common::traits::PriceProvider for TestPriceProvider {
    fn get_dock_usd_price() -> Option<(u32, u64)> {
        if let Some(p) = Self::get() {
            return Some((p, 0));
        }
        None
    }
    fn optimized_get_dock_usd_price() -> Option<(u32, u64)> {
        Self::get_dock_usd_price()
    }
}

pub const ALICE: u64 = 100;
pub const BOB: u64 = 200;
// Build genesis storage according to the mock runtime.
pub fn ext() -> sp_io::TestExternalities {
    let t = system::GenesisConfig::default()
        .build_storage::<TestRt>()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);

    ext.execute_with(|| {
        let _ = <TestRt as Config>::Currency::deposit_creating(&ALICE, 100_000_000_000);
    });
    ext
}

/// generate a random keypair
pub fn gen_kp() -> sr25519::Pair {
    sr25519::Pair::generate_with_phrase(None).0
}
/// get the latest block number
pub fn block_no() -> u64 {
    system::Module::<TestRt>::block_number()
}
// Create did for `did`. Return the randomly generated signing key.
// The did public key is controlled by some non-existent account (normally a security
// concern), but that doesn't matter for our purposes.
pub fn create_did(origin: u64, did: did::Did) -> sr25519::Pair {
    let kp = gen_kp();
    let pubkey_bytes = did::Bytes32 {
        value: kp.public().0,
    };
    let didpubkey = did::PublicKey::Sr25519(pubkey_bytes);
    let key_detail = did::KeyDetail::new(did, didpubkey);
    did::Module::<TestRt>::new(Origin::signed(origin), did, key_detail).unwrap();
    kp
}
/// create a did with a random id and random signing key
pub fn newdid(origin: u64) -> (did::Did, sr25519::Pair) {
    let d: did::Did = rand::random();
    (d, create_did(origin, d))
}

pub fn sign(payload: &StateChange, keypair: &sr25519::Pair) -> did::DidSignature {
    did::DidSignature::Sr25519(did::Bytes64 {
        value: keypair.sign(&payload.encode()).0,
    })
}

/// create a random byte array with set len
pub fn random_bytes(len: usize) -> Vec<u8> {
    let ret: Vec<u8> = (0..len).map(|_| rand::random()).collect();
    assert_eq!(ret.len(), len);
    ret
}

pub fn measure_fees(call: Call) -> (u32, DispatchResultWithPostInfo) {
    let balance_pre = <TestRt as Config>::Currency::free_balance(ALICE);
    let executed = FiatFilterModule::execute_call(Origin::signed(ALICE), Box::new(call.clone()));
    let balance_post = <TestRt as Config>::Currency::free_balance(ALICE);
    let fee_microdock = (balance_pre - balance_post) as u32;
    return (fee_microdock, executed);
}
pub fn exec_assert_fees(call: Call, expected_fees: u32) -> (u32, DispatchResultWithPostInfo) {
    let (fee_microdock, executed) = measure_fees(call);
    assert_ok!(executed);

    let pdi = executed.unwrap();
    assert!(pdi.pays_fee == Pays::No);
    assert_eq!(fee_microdock, expected_fees);
    return (fee_microdock, executed);
}
