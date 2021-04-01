use crate as fiat_filter;
pub use crate::{Config, Error, Module};
use codec::{Decode, Encode};
use core_mods::StateChange;
use core_mods::{anchor, attest, blob, did, revoke};
use frame_support::assert_ok;
use frame_support::dispatch::{
    DispatchInfo, DispatchResultWithPostInfo, Dispatchable, PostDispatchInfo,
    UnfilteredDispatchable,
};
use frame_support::parameter_types;
use frame_support::traits::{Currency, Filter, IsSubType};
use frame_support::weights::{DispatchClass, GetDispatchInfo, Pays, Weight};
use frame_system as system;
use sp_core::H256;
use sp_core::{sr25519, Pair};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};

/*#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq)]
pub enum TestCall {
    System(system::Call<TestRt>),
    Balance(pallet_balances::Call<TestRt>),
    Did(did::Call<TestRt>),
    Anchor(anchor::Call<TestRt>),
    Blob(blob::Call<TestRt>),
    Revoke(revoke::Call<TestRt>),
    Attest(attest::Call<TestRt>),
}
impl Dispatchable for TestCall {
    type Origin = Origin;
    type Config = ();
    type Info = ();
    type PostInfo = PostDispatchInfo;
    fn dispatch(self, origin: Self::Origin) -> sp_runtime::DispatchResultWithInfo<Self::PostInfo> {
        match self {
            // TestCall::System(c) => Dispatchable::dispatch(c, origin),
            TestCall::System(c) => c.dispatch_bypass_filter(origin),
            TestCall::Balance(c) => c.dispatch_bypass_filter(origin),
            TestCall::Did(c) => c.dispatch_bypass_filter(origin),
            TestCall::Anchor(c) => c.dispatch_bypass_filter(origin),
            TestCall::Blob(c) => c.dispatch_bypass_filter(origin),
            TestCall::Revoke(c) => c.dispatch_bypass_filter(origin),
            TestCall::Attest(c) => c.dispatch_bypass_filter(origin),
        }
    }
}
impl UnfilteredDispatchable for TestCall {
    type Origin = Origin;
    fn dispatch_bypass_filter(self, origin: Self::Origin) -> DispatchResultWithPostInfo {
        match self {
            TestCall::System(c) => c.dispatch_bypass_filter(origin),
            TestCall::Balance(c) => c.dispatch_bypass_filter(origin),
            TestCall::Did(c) => c.dispatch_bypass_filter(origin),
            TestCall::Anchor(c) => c.dispatch_bypass_filter(origin),
            TestCall::Blob(c) => c.dispatch_bypass_filter(origin),
            TestCall::Revoke(c) => c.dispatch_bypass_filter(origin),
            TestCall::Attest(c) => c.dispatch_bypass_filter(origin),
        }
    }
}
impl GetDispatchInfo for TestCall {
    fn get_dispatch_info(&self) -> DispatchInfo {
        DispatchInfo {
            weight: 101u64,
            class: DispatchClass::Normal,
            pays_fee: Pays::Yes,
        }
    }
}
impl IsSubType<did::Call<TestRt>> for TestCall {
    fn is_sub_type(&self) -> Option<&did::Call<TestRt>> {
        match self {
            Self::Did(ref r) => Some(r),
            _ => None,
        }
    }
}
impl IsSubType<anchor::Call<TestRt>> for TestCall {
    fn is_sub_type(&self) -> Option<&anchor::Call<TestRt>> {
        match self {
            Self::Anchor(ref r) => Some(r),
            _ => None,
        }
    }
}
impl IsSubType<blob::Call<TestRt>> for TestCall {
    fn is_sub_type(&self) -> Option<&blob::Call<TestRt>> {
        match self {
            Self::Blob(ref r) => Some(r),
            _ => None,
        }
    }
}
impl IsSubType<revoke::Call<TestRt>> for TestCall {
    fn is_sub_type(&self) -> Option<&revoke::Call<TestRt>> {
        match self {
            Self::Revoke(ref r) => Some(r),
            _ => None,
        }
    }
}
impl IsSubType<attest::Call<TestRt>> for TestCall {
    fn is_sub_type(&self) -> Option<&attest::Call<TestRt>> {
        match self {
            Self::Attest(ref r) => Some(r),
            _ => None,
        }
    }
}
pub struct BaseFilter;
impl Filter<TestCall> for BaseFilter {
    fn filter(call: &TestCall) -> bool {
        match call {
            // filter out core_mods TestCalls so they're only done through fiat_filter
            TestCall::Anchor(_) => false,
            TestCall::Blob(_) => false,
            TestCall::Did(_) => false,
            TestCall::Revoke(_) => false,
            TestCall::Attest(_) => false,
            _ => true,
        }
    }
}*/
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
pub const RATE_DOCK_USD: u32 = 72;
// pub const RATE_DOCK_USD_2: u32 = 999;

pub struct TestPriceProvider;
impl common::PriceProvider for TestPriceProvider {
    fn get_dock_usd_price() -> Option<(u32, u64)> {
        Some((RATE_DOCK_USD, 0))
    }
    fn optimized_get_dock_usd_price() -> Option<(u32, u64)> {
        Some((RATE_DOCK_USD, 0))
    }
}

// pub type FiatFilterModule = Module<TestRt>;

pub const ALICE: u64 = 100;
pub const BOB: u64 = 200;
// Build genesis storage according to the mock runtime.
pub fn ext() -> sp_io::TestExternalities {
    let t = system::GenesisConfig::default()
        .build_storage::<TestRt>()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);

    ext.execute_with(|| {
        // System::set_block_number(1);
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

pub fn measure_fees(call: Call) -> (u64, DispatchResultWithPostInfo) {
    let balance_pre = <TestRt as Config>::Currency::free_balance(ALICE);
    let executed = FiatFilterModule::execute_call(Origin::signed(ALICE), Box::new(call.clone()));
    let balance_post = <TestRt as Config>::Currency::free_balance(ALICE);
    let fee_microdock = balance_pre - balance_post;
    return (fee_microdock, executed);
}
pub fn exec_assert_fees(call: Call, expected_fees: u64) -> (u64, DispatchResultWithPostInfo) {
    let (fee_microdock, executed) = measure_fees(call);
    assert_ok!(executed);

    let pdi = executed.unwrap();
    assert!(pdi.pays_fee == Pays::No);
    assert_eq!(fee_microdock, expected_fees);
    return (fee_microdock, executed);
}

// mod testrt_price2 {
//     use crate::*;
//     use core_mods::{anchor, did};
//     use frame_support::traits::Filter;
//     use frame_support::weights::Weight;
//     use frame_support::{impl_outer_dispatch, impl_outer_origin, parameter_types};
//     use frame_system as system;
//     use sp_core::H256;
//     use sp_runtime::{
//         testing::Header,
//         traits::{BlakeTwo256, IdentityLookup},
//     };

//     impl_outer_origin! {
//         pub enum Origin for TestRt where system = frame_system {}
//     }
//     type SystemMod = frame_system::Module<TestRt>;
//     type DidMod = did::Module<TestRt>;
//     type AnchorMod = anchor::Module<TestRt>;
//     type BlobMod = blob::Module<TestRt>;
//     type RevokeMod = revoke::Module<TestRt>;
//     type AttestMod = attest::Module<TestRt>;
//     type BalanceMod = pallet_balances::Module<TestRt>;
//     impl_outer_dispatch! {
//         pub enum TestCall for TestRt where origin: Origin {
//             did::DidMod,
//             anchor::AnchorMod,
//             blob::BlobMod,
//             revoke::RevokeMod,
//             attest::AttestMod,
//             system::SystemMod,
//             balance::BalanceMod,
//         }
//     }

//     // Configure a mock runtime to test the pallet.
//     #[derive(Clone, Eq, PartialEq)]
//     pub struct TestRt;
//     parameter_types! {
//         pub const BlockHashCount: u64 = 250;
//     }
//     pub struct BaseFilter;
//     impl Filter<TestCall> for BaseFilter {
//         fn filter(call: &TestCall) -> bool {
//             match call {
//                 // filter out core_mods TestCalls so they're only done through fiat_filter
//                 TestCall::AnchorMod(_) => false,
//                 TestCall::BlobMod(_) => false,
//                 TestCall::DidMod(_) => false,
//                 TestCall::RevokeMod(_) => false,
//                 TestCall::AttestMod(_) => false,
//                 _ => true,
//             }
//         }
//     }
//     impl system::Config for TestRt {
//         type BaseCallFilter = BaseFilter;
//         type Origin = Origin;
//         type Call = TestCall;
//         type Index = u64;
//         type BlockNumber = u64;
//         type Hash = H256;
//         type Hashing = BlakeTwo256;
//         type AccountId = u64;
//         type Lookup = IdentityLookup<Self::AccountId>;
//         type Header = Header;
//         type Event = ();
//         type BlockHashCount = BlockHashCount;
//         type DbWeight = ();
//         type Version = ();
//         type PalletInfo = PalletInfo;
//         type AccountData = pallet_balances::AccountData<u64>;
//         type OnNewAccount = ();
//         type OnKilledAccount = ();
//         type SystemWeightInfo = ();
//         type BlockWeights = ();
//         type BlockLength = ();
//         type SS58Prefix = ();
//     }

//     impl Config for TestRt {
//         type PriceProvider = TestPriceProvider2;
//         type Call = TestCall;
//         type Currency = pallet_balances::Module<Self>;
//     }

//     parameter_types! {
//         pub const ExistentialDeposit: u64 = 1;
//     }
//     impl pallet_balances::Config for TestRt {
//         type MaxLocks = ();
//         type Balance = u64;
//         type Event = ();
//         type DustRemoval = ();
//         type ExistentialDeposit = ExistentialDeposit;
//         type AccountStore = SystemMod;
//         type WeightInfo = ();
//     }
//     impl anchor::Trait for TestRt {
//         type Event = ();
//     }
//     impl did::Trait for TestRt {
//         type Event = ();
//     }
//     impl revoke::Trait for TestRt {}

//     parameter_types! {
//         pub const MaxBlobSize: u32 = 1024;
//         pub const StorageWeight: Weight = 1100;
//     }
//     impl blob::Trait for TestRt {
//         type MaxBlobSize = MaxBlobSize;
//         type StorageWeight = StorageWeight;
//     }

//     impl attest::Trait for TestRt {
//         type StorageWeight = StorageWeight;
//     }

//     pub struct TestPriceProvider2;
//     impl common::PriceProvider for TestPriceProvider2 {
//         fn get_dock_usd_price() -> Option<(u32, u64)> {
//             Some((super::RATE_DOCK_USD_2, 0))
//         }
//         fn optimized_get_dock_usd_price() -> Option<(u32, u64)> {
//             Some((super::RATE_DOCK_USD_2, 0))
//         }
//     }

//     pub type FiatFilterModule = Module<TestRt>;
// }
