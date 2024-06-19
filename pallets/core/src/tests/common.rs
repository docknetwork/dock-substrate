//! Boilerplate for runtime module unit tests

use crate::{
    accumulator, anchor, attest, blob,
    common::{self, StateChange, ToStateChange, Types},
    did::{
        self, Did, DidDetailsOrDidMethodKeyDetails, DidKey, DidMethodKeySignature,
        DidOrDidMethodKey, DidOrDidMethodKeySignature, DidSignature,
    },
    master, offchain_signatures, revoke, status_list_credential, trust_registry,
    util::{ActionWrapper, WithNonce},
};
use sp_runtime::DispatchError;

use crate::{
    common::SigValue,
    revoke::{RevocationRegistryId, RevokeId},
};
use codec::{Decode, Encode};
use frame_support::{
    parameter_types,
    traits::{Contains, OnFinalize, OnInitialize},
    weights::Weight,
};
use frame_system::RawOrigin;
use pallet_evm::EnsureAddressOrigin;
pub use rand::random;
use sp_core::{sr25519, Pair, H160, H256};
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, ConstU32, IdentityLookup},
};
pub use std::iter::once;

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
        DIDModule: did::{Pallet, Call, Storage, Event<T>, Config<T>},
        RevoMod: revoke::{Pallet, Call, Storage, Event},
        BlobMod: blob::{Pallet, Call, Storage},
        MasterMod: master::{Pallet, Call, Storage, Event<T>, Config<T>},
        AnchorMod: anchor::{Pallet, Call, Storage, Event<T>},
        AttestMod: attest::{Pallet, Call, Storage},
        SignatureMod: offchain_signatures::{Pallet, Call, Storage, Event},
        AccumMod: accumulator::{Pallet, Call, Storage, Event},
        StatusListCredentialMod: status_list_credential::{Pallet, Call, Storage, Event},
        TrustRegistryMod: trust_registry::{Pallet, Call, Storage, Event},
        EVM: pallet_evm::{Pallet, Config, Call, Storage, Event<T>},
    }
);

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Clone, PartialEq, Debug, Eq)]
pub enum TestEvent {
    Did(crate::did::Event<Test>),
    Revoke(crate::revoke::Event),
    Master(crate::master::Event<Test>),
    Anchor(crate::anchor::Event<Test>),
    Unknown,
    OffchainSignature(offchain_signatures::Event),
    Accum(accumulator::Event),
    StatusListCredential(status_list_credential::Event),
    TrustRegistry(trust_registry::Event),
}

impl From<frame_system::Event<Test>> for TestEvent {
    fn from(_: frame_system::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<pallet_balances::Event<Test>> for TestEvent {
    fn from(_: pallet_balances::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<pallet_evm::Event<Test>> for TestEvent {
    fn from(_: pallet_evm::Event<Test>) -> Self {
        unimplemented!()
    }
}

impl From<()> for TestEvent {
    fn from((): ()) -> Self {
        Self::Unknown
    }
}

impl From<crate::did::Event<Test>> for TestEvent {
    fn from(other: crate::did::Event<Test>) -> Self {
        Self::Did(other)
    }
}

impl From<crate::revoke::Event> for TestEvent {
    fn from(other: crate::revoke::Event) -> Self {
        Self::Revoke(other)
    }
}

impl From<crate::anchor::Event<Test>> for TestEvent {
    fn from(other: crate::anchor::Event<Test>) -> Self {
        Self::Anchor(other)
    }
}

impl From<crate::master::Event<Test>> for TestEvent {
    fn from(other: crate::master::Event<Test>) -> Self {
        Self::Master(other)
    }
}

impl From<crate::status_list_credential::Event> for TestEvent {
    fn from(other: crate::status_list_credential::Event) -> Self {
        Self::StatusListCredential(other)
    }
}

impl From<crate::trust_registry::Event> for TestEvent {
    fn from(other: crate::trust_registry::Event) -> Self {
        Self::TrustRegistry(other)
    }
}

impl From<offchain_signatures::Event> for TestEvent {
    fn from(other: offchain_signatures::Event) -> Self {
        Self::OffchainSignature(other)
    }
}

impl From<accumulator::Event> for TestEvent {
    fn from(other: accumulator::Event) -> Self {
        Self::Accum(other)
    }
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const ByteReadWeight: Weight = Weight::from_ref_time(10);
}

pub struct BaseFilter;
impl Contains<Call> for BaseFilter {
    fn contains(_call: &Call) -> bool {
        true
    }
}

impl frame_system::Config for Test {
    type OnSetCode = ();
    type MaxConsumers = ConstU32<10>;
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
    type Event = TestEvent;
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

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ();
    type WeightInfo = ();
}

pub struct DummyCallOrigin;
impl<OuterOrigin> EnsureAddressOrigin<OuterOrigin> for DummyCallOrigin
where
    OuterOrigin: Into<Result<RawOrigin<u64>, OuterOrigin>> + From<RawOrigin<u64>>,
{
    type Success = u64;

    fn try_address_origin(_: &H160, _: OuterOrigin) -> Result<u64, OuterOrigin> {
        unimplemented!()
    }
}

/// Identity address mapping.
pub struct DummyAddressMapping;
impl pallet_evm::AddressMapping<u64> for DummyAddressMapping {
    fn into_account_id(_: H160) -> u64 {
        unimplemented!()
    }
}

impl pallet_evm::Config for Test {
    type FeeCalculator = ();
    type GasWeightMapping = ();
    type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
    type CallOrigin = DummyCallOrigin;
    type WithdrawOrigin = DummyCallOrigin;
    type AddressMapping = DummyAddressMapping;
    type Currency = Balances;
    type Event = TestEvent;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type ByteReadWeight = ByteReadWeight;
    type PrecompilesType = ();
    type PrecompilesValue = ();
    type ChainId = ();
    type BlockGasLimit = ();
    type OnChargeTransaction = ();
    type FindAuthor = ();
}

impl pallet_balances::Config for Test {
    type ReserveIdentifier = ();
    type MaxReserves = ();
    type MaxLocks = ();
    type Balance = u64;
    type Event = TestEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
}

impl crate::common::Limits for Test {
    type MaxDidDocRefSize = ConstU32<128>;
    type MaxDidServiceEndpointIdSize = ConstU32<256>;
    type MaxDidServiceEndpointOrigins = ConstU32<20>;
    type MaxDidServiceEndpointOriginSize = ConstU32<256>;

    type MaxAccumulatorLabelSize = ConstU32<512>;
    type MaxAccumulatorParamsSize = ConstU32<512>;
    type MaxAccumulatorPublicKeySize = ConstU32<128>;
    type MaxAccumulatorAccumulatedSize = ConstU32<256>;

    type MinStatusListCredentialSize = ConstU32<10>;
    type MaxStatusListCredentialSize = ConstU32<1_000>;

    type MaxIriSize = ConstU32<1024>;
    type MaxBlobSize = ConstU32<1024>;

    type MaxOffchainParamsLabelSize = ConstU32<512>;
    type MaxOffchainParamsBytesSize = ConstU32<512>;
    type MaxBBSPublicKeySize = ConstU32<128>;
    type MaxBBSPlusPublicKeySize = ConstU32<128>;
    type MaxPSPublicKeySize = ConstU32<128>;

    type MaxMasterMembers = ConstU32<100>;
    type MaxPolicyControllers = ConstU32<15>;

    type MaxIssuerPriceCurrencySymbolSize = ConstU32<10>;
    type MaxIssuersPerSchema = ConstU32<20>;
    type MaxVerifiersPerSchema = ConstU32<20>;
    type MaxIssuerPriceCurrencies = ConstU32<20>;
    type MaxTrustRegistryNameSize = ConstU32<100>;
    type MaxConvenerRegistries = ConstU32<5>;
    type MaxDelegatedIssuers = ConstU32<20>;
    type MaxSchemasPerIssuer = ConstU32<100>;
    type MaxSchemasPerVerifier = ConstU32<100>;
    type MaxRegistriesPerIssuer = ConstU32<250>;
    type MaxRegistriesPerVerifier = ConstU32<250>;
    type MaxSchemasPerRegistry = ConstU32<1_000>;
    type MaxTrustRegistryGovFrameworkSize = ConstU32<1_000>;
    type MaxParticipantsPerRegistry = ConstU32<10_000>;
    type MaxRegistryParticipantOrgNameSize = ConstU32<100>;
    type MaxRegistryParticipantLogoSize = ConstU32<500>;
    type MaxRegistryParticipantDescriptionSize = ConstU32<500>;
}

impl crate::did::Config for Test {
    type Event = TestEvent;
    type OnDidRemoval = SignatureMod;
}

impl crate::revoke::Config for Test {
    type Event = TestEvent;
}
impl crate::status_list_credential::Config for Test {
    type Event = TestEvent;
}
impl crate::trust_registry::Config for Test {
    type Event = TestEvent;
}
impl crate::blob::Config for Test {}
impl crate::attest::Config for Test {}

impl crate::anchor::Config for Test {
    type Event = TestEvent;
}

impl crate::master::Config for Test {
    type Event = TestEvent;
    type Call = Call;
}

impl offchain_signatures::Config for Test {
    type Event = TestEvent;
}

impl accumulator::Config for Test {
    type Event = TestEvent;
}

pub const ABBA: u64 = 0;
pub const DIDA: Did = Did([0u8; 32]);
pub const DIDB: Did = Did([1u8; 32]);
pub const DIDC: Did = Did([2u8; 32]);
pub const RGA: RevocationRegistryId = RevocationRegistryId([0u8; 32]);
pub const RA: RevokeId = RevokeId([0u8; 32]);
pub const RB: RevokeId = RevokeId([1u8; 32]);
pub const RC: RevokeId = RevokeId([2u8; 32]);

/// check whether test externalities are available
pub fn in_ext() -> bool {
    std::panic::catch_unwind(|| sp_io::storage::exists(&[])).is_ok()
}

#[test]
pub fn meta_in_ext() {
    assert!(!in_ext());
    ext().execute_with(|| assert!(in_ext()));
}

pub fn ext() -> sp_io::TestExternalities {
    let mut ret: sp_io::TestExternalities = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into();
    ret.execute_with(|| {
        frame_system::Pallet::<Test>::initialize(
            &1, // system module will not store events if block_number == 0
            &[0u8; 32].into(),
            &Default::default(),
        );
    });
    ret
}

/// generate a random keypair
pub fn gen_kp() -> sr25519::Pair {
    sr25519::Pair::generate_with_phrase(None).0
}

// Create did for `did`. Return the randomly generated signing key.
// The did public key is controlled by some non-existent account (normally a security
// concern), but that doesn't matter for our purposes.
pub fn create_did(did: did::Did) -> sr25519::Pair {
    let kp = gen_kp();
    let did_pk = DidKey::new_with_all_relationships(kp.public());
    println!("did pk: {:?}", did_pk.public_key());

    did::Pallet::<Test>::new_onchain(
        Origin::signed(ABBA),
        did,
        vec![did_pk.into()],
        Default::default(),
    )
    .unwrap();

    kp
}

/// create a did with a random id and random signing key
pub fn newdid() -> (Did, sr25519::Pair) {
    let d: Did = Did(rand::random());
    (d, create_did(d))
}

pub fn sign<T: crate::did::Config, P>(payload: &StateChange<T>, keypair: &P) -> SigValue
where
    P: Pair,
    P::Signature: Into<SigValue>,
{
    keypair.sign(&payload.encode()).into()
}

#[macro_export]
macro_rules! did_or_did_method_key {
    ($newdid: ident => $($tt: tt)+) => {
        mod onchain_did {
            use super::*;
            use $crate::did::Did;

            /// create a did with a random id and random signing key
            pub fn $newdid() -> (Did, sp_core::sr25519::Pair) {
                let d: Did = Did(rand::random());
                (d, create_did(d))
            }

            $($tt)+
        }

        mod did_method_key {
            use super::*;
            use $crate::did::DidMethodKey;

            /// create a did with a random id and random signing key
            pub fn $newdid() -> (DidMethodKey, sp_core::ed25519::Pair) {
                use sp_core::Pair;

                let kp = sp_core::ed25519::Pair::generate_with_phrase(None).0;
                let did_method_key = kp.public().into();

                did::Pallet::<Test>::new_did_method_key_(
                    did_method_key,
                )
                .unwrap();

                (did_method_key, kp)
            }

            $($tt)+
        }
    }
}

pub fn did_nonce<T: crate::did::Config, D: Into<DidOrDidMethodKey>>(
    did: D,
) -> Result<<T as Types>::BlockNumber, DispatchError> {
    use crate::util::Action;
    use core::marker::PhantomData;

    struct DummyAction<T>(PhantomData<T>);
    crate::impl_action!(for (): DummyAction with 1 as len, () as target no_state_change);

    ActionWrapper::new(did.into(), DummyAction(PhantomData::<T>)).view(
        |_, details: WithNonce<T, DidDetailsOrDidMethodKeyDetails<T>>| {
            Ok::<_, DispatchError>(details.next_nonce().unwrap())
        },
    )
}

pub fn did_sig<T: crate::did::Config, A: ToStateChange<T>, D: Into<DidOrDidMethodKey>, P: Pair>(
    change: &A,
    keypair: &P,
    did: impl Into<DidOrDidMethodKey>,
    key_id: u32,
) -> DidOrDidMethodKeySignature<D>
where
    P::Signature: Into<SigValue>,
{
    let did = did.into();

    match did {
        DidOrDidMethodKey::Did(did) => DidSignature {
            did,
            key_id: key_id.into(),
            sig: sign(&change.to_state_change(), keypair),
        }
        .into(),
        DidOrDidMethodKey::DidMethodKey(did_method_key) => DidMethodKeySignature {
            did_method_key,
            sig: match sign(&change.to_state_change(), keypair) {
                SigValue::Ed25519(sig) => common::DidMethodKeySigValue::Ed25519(sig),
                _ => panic!(),
            },
        }
        .into(),
    }
}

pub fn did_sig_on_bytes<D: Into<Did>>(
    msg_bytes: &[u8],
    keypair: &sr25519::Pair,
    did: D,
    key_id: u32,
) -> DidSignature<D> {
    DidSignature {
        did,
        key_id: key_id.into(),
        sig: SigValue::Sr25519(keypair.sign(msg_bytes).0.into()),
    }
}

/// create a random byte array with set len
pub fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random()).collect()
}

/// Changes the block number. Calls `on_finalize` and `on_initialize`
pub fn run_to_block(n: u64) {
    while System::block_number() < n {
        if System::block_number() > 1 {
            System::on_finalize(System::block_number());
        }
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
    }
}

pub fn check_nonce(d: &(impl Into<DidOrDidMethodKey> + Clone), nonce: u64) {
    match d.clone().into() {
        DidOrDidMethodKey::Did(did) => {
            let did_detail = DIDModule::onchain_did_details(&did).unwrap();
            assert_eq!(did_detail.nonce, nonce);
        }
        DidOrDidMethodKey::DidMethodKey(did_method_key) => {
            let did_detail: crate::util::WithNonce<Test, ()> =
                DIDModule::did_method_key(did_method_key).unwrap();
            assert_eq!(did_detail.nonce, nonce);
        }
    }
}

pub fn inc_nonce(d: &Did) {
    let mut did_detail = DIDModule::onchain_did_details(d).unwrap();
    did_detail.nonce = did_detail.next_nonce().unwrap();
    DIDModule::insert_did_details(*d, did_detail);
}
