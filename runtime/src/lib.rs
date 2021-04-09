//! Dock testnet runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM_BINARY available, but hide WASM_BINARY_BLOATY.
#[cfg(feature = "std")]
mod wasm {
    include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
    // The following assignment is to silence compiler warning for unused variable while not
    // exposing `WASM_BINARY_BLOATY` as public
    #[allow(dead_code)]
    const _: Option<&[u8]> = WASM_BINARY_BLOATY;
}
#[cfg(feature = "std")]
pub use wasm::WASM_BINARY;

extern crate alloc;

#[macro_use]
extern crate static_assertions;

pub use core_mods::anchor;
pub use core_mods::attest;
pub use core_mods::blob;
pub use core_mods::did;
pub use core_mods::master;
pub use core_mods::revoke;
pub mod weight_to_fee;

pub use poa;
pub use price_feed;
pub use simple_democracy;
pub use token_migration;

use codec::{Decode, Encode};
use frame_support::{
    construct_runtime, parameter_types,
    traits::{CurrencyToVote, Filter, FindAuthor, KeyOwnerProofSystem, Randomness},
    weights::{
        constants::{
            BlockExecutionWeight as DefaultBlockExecutionWeight, ExtrinsicBaseWeight,
            RocksDbWeight, WEIGHT_PER_SECOND,
        },
        DispatchClass, Weight,
    },
    ConsensusEngineId,
};
use frame_system as system;
use frame_system::{
    limits::{BlockLength, BlockWeights},
    EnsureOneOf, EnsureRoot,
};
use grandpa::fg_primitives;
use grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_session::historical as pallet_session_historical;
use pallet_sudo as sudo;
use sp_api::impl_runtime_apis;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_core::u32_trait::{_1, _2, _3, _4};
use sp_core::{
    crypto::{KeyTypeId, Public},
    OpaqueMetadata, H160, H256, U256,
};
use sp_runtime::traits::{
    AccountIdLookup, BlakeTwo256, Block as BlockT, ConvertInto, Extrinsic, IdentifyAccount,
    NumberFor, OpaqueKeys, StaticLookup, Verify,
};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    transaction_validity::{TransactionPriority, TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, MultiSignature, Perbill, SaturatedConversion,
};
use transaction_payment::CurrencyAdapter;

use evm::Config as EvmConfig;
use fp_rpc::TransactionStatus;
use pallet_evm::{
    Account as EVMAccount, EVMCurrencyAdapter, EnsureAddressTruncated, FeeCalculator,
    HashedAddressMapping, Runner,
};

use crate::weight_to_fee::TxnFee;
use sp_std::{convert::TryFrom, marker::PhantomData, prelude::*};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

#[cfg(feature = "std")]
pub use pallet_staking::StakerStatus;

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = u64;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = H256;

/// Type used for expressing timestamp.
pub type Moment = u64;

/// The token has 6 decimal places
pub const DOCK: Balance = 1_000_000;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core datastructures.
pub mod opaque {
    use super::*;

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        pub babe: Babe,
        pub grandpa: Grandpa,
        pub im_online: ImOnline,
        pub authority_discovery: AuthorityDiscovery,
    }
}

pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);

/// The BABE epoch configuration at genesis.
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
    sp_consensus_babe::BabeEpochConfiguration {
        c: PRIMARY_PROBABILITY,
        allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
    };

/// This runtime version.
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("dock-main-runtime"),
    impl_name: create_runtime_str!("dock-main-runtime"),
    authoring_version: 1,
    spec_version: 21,
    impl_version: 1,
    transaction_version: 1,
    apis: RUNTIME_API_VERSIONS,
};

pub const MILLISECS_PER_BLOCK: u64 = 3000;

const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// TODO: Configure epoch duration
pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 10 * MINUTES;
pub const EPOCH_DURATION_IN_SLOTS: u64 = EPOCH_DURATION_IN_BLOCKS as u64;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// We assume that an on-initialize consumes 10% of the weight on average, hence a single extrinsic
/// will not be allowed to consume more than `AvailableBlockRatio - 10%`.
pub const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(10);
/// We allow `Normal` extrinsics to fill up the block up to 75%, the rest can be used
/// by  Operational  extrinsics.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 1 second of compute with a 3 second average block time.
pub const MAXIMUM_BLOCK_WEIGHT: Weight = WEIGHT_PER_SECOND;

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    /// We allow for 1 seconds of compute with a 3 second average block time.
    pub const MaximumBlockWeight: Weight = WEIGHT_PER_SECOND;
    pub RuntimeBlockLength: BlockLength =
        BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
    pub const Version: RuntimeVersion = VERSION;
    /// After each block we
    /// - update stats, which is 1 read and 1 write
    /// - check if there is any fees in storage item `TxnFees`, which is 1 read
    /// - credit fees to block author's account which is 1 read and 1 write
    /// - reset the storage item `TxnFees`, 1 write
    /// Thus in the worst case, we do 3 reads and 3 writes
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(DefaultBlockExecutionWeight::get()  +
        <Runtime as system::Config>::DbWeight::get().reads_writes(3, 3))
        .for_class(DispatchClass::all(), |weights| {
            weights.base_extrinsic = ExtrinsicBaseWeight::get();
        })
        .for_class(DispatchClass::Normal, |weights| {
            weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
        })
        .for_class(DispatchClass::Operational, |weights| {
            weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
            // Operational transactions have some extra reserved space, so that they
            // are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
            weights.reserved = Some(
                MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
            );
        })
        .avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
        .build_or_panic();
    pub const SS58Prefix: u8 = 42;
}

impl system::Config for Runtime {
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = BaseFilter;
    /// The ubiquitous origin type.
    type Origin = Origin;
    /// The aggregated dispatch type that is available for extrinsics.
    type Call = Call;
    /// The index type for storing how many extrinsics an account has signed.
    type Index = Index;
    /// The index type for blocks.
    type BlockNumber = BlockNumber;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// The hashing algorithm used.
    type Hashing = BlakeTwo256;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = AccountIdLookup<AccountId, ()>;
    /// The header type.
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// The ubiquitous event type.
    type Event = Event;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = RuntimeBlockWeights;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    type BlockLength = RuntimeBlockLength;
    /// Version of the runtime.
    type Version = Version;
    /// Provides information about the pallet setup in the runtime.
    ///
    /// Expects the `PalletInfo` type that is being generated by `construct_runtime!` in the
    /// runtime.
    ///
    /// For tests it is okay to use `()` as type, however it will provide "useless" data.
    type PalletInfo = PalletInfo;
    /// The data to be stored in an account.
    type AccountData = balances::AccountData<Balance>;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
}

parameter_types! {
    pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
    /// We prioritize im-online heartbeats over election solution submission.
    pub const StakingUnsignedPriority: TransactionPriority = TransactionPriority::max_value() / 2;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
    Call: From<LocalCall>,
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: Call,
        public: <Signature as Verify>::Signer,
        account: AccountId,
        nonce: Index,
    ) -> Option<(Call, <UncheckedExtrinsic as Extrinsic>::SignaturePayload)> {
        let tip = 0;
        // take the biggest period possible.
        let period = BlockHashCount::get()
            .checked_next_power_of_two()
            .map(|c| c / 2)
            .unwrap_or(2) as u64;
        let current_block = System::block_number()
            .saturated_into::<u64>()
            // The `System::block_number` is initialized with `n+1`,
            // so the actual block number is `n`.
            .saturating_sub(1);
        let era = generic::Era::mortal(period, current_block);
        let extra = (
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(era),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
            token_migration::OnlyMigrator::<Runtime>::new(),
        );
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = <Runtime as system::Config>::Lookup::unlookup(account);
        let (call, extra, _) = raw_payload.deconstruct();
        Some((call, (address, signature.into(), extra)))
    }
}

impl frame_system::offchain::SigningTypes for Runtime {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    Call: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = Call;
}

impl pallet_im_online::Config for Runtime {
    type AuthorityId = ImOnlineId;
    type Event = Event;
    type NextSessionRotation = Babe;
    type ValidatorSet = Historical;
    type ReportUnresponsiveness = Offences;
    type UnsignedPriority = ImOnlineUnsignedPriority;
    type WeightInfo = pallet_im_online::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const EpochDuration: u64 = EPOCH_DURATION_IN_SLOTS;
    pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
    pub const ReportLongevity: u64 =
        BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
}

impl pallet_babe::Config for Runtime {
    type EpochDuration = EpochDuration;
    type ExpectedBlockTime = ExpectedBlockTime;
    type EpochChangeTrigger = pallet_babe::ExternalTrigger;

    type KeyOwnerProofSystem = Historical;

    type KeyOwnerProof = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        pallet_babe::AuthorityId,
    )>>::Proof;

    type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        pallet_babe::AuthorityId,
    )>>::IdentificationTuple;

    type HandleEquivocation =
        pallet_babe::EquivocationHandler<Self::KeyOwnerIdentification, Offences, ReportLongevity>;

    type WeightInfo = ();
}

parameter_types! {
    // TODO: Revisit these
    pub const SessionsPerEra: sp_staking::SessionIndex = 6;
    pub const BondingDuration: pallet_staking::EraIndex = 24 * 28;
    pub const SlashDeferDuration: pallet_staking::EraIndex = 24 * 7; // 1/4 the bonding duration.
    pub const MaxNominatorRewardedPerValidator: u32 = 256;
    pub const ElectionLookahead: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const MaxIterations: u32 = 10;
    // 0.05%. The higher the value, the more strict solution acceptance becomes.
    pub MinSolutionScoreBump: Perbill = Perbill::from_rational(5u32, 10_000);
    pub OffchainSolutionWeightLimit: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(DefaultBlockExecutionWeight::get());
}

pub struct U64CurrencyToVote;

impl CurrencyToVote<u64> for U64CurrencyToVote {
    fn to_vote(value: u64, _issuance: u64) -> u64 {
        value
    }

    fn to_currency(value: u128, _issuance: u64) -> u64 {
        value.saturated_into()
    }
}

impl pallet_staking::Config for Runtime {
    type Currency = Balances;
    type UnixTime = Timestamp;
    // Our balance type is u64
    type CurrencyToVote = U64CurrencyToVote;
    // TODO: Set to treasury once integrated
    type RewardRemainder = ();
    type Event = Event;
    // TODO: Set to treasury once integrated
    type Slash = (); // send the slashed funds to the treasury.
    type Reward = (); // rewards are minted from the void
    type SessionsPerEra = SessionsPerEra;
    type BondingDuration = BondingDuration;
    type SlashDeferDuration = SlashDeferDuration;
    /// A super-majority of the council can cancel the slash.
    type SlashCancelOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<_3, _4, AccountId, CouncilCollective>,
    >;
    type SessionInterface = Self;
    // TODO: Set a reward curve
    type EraPayout = ();
    type NextNewSession = Session;
    type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
    type ElectionLookahead = ElectionLookahead;
    type Call = Call;
    type MaxIterations = MaxIterations;
    type MinSolutionScoreBump = MinSolutionScoreBump;
    type UnsignedPriority = StakingUnsignedPriority;
    // The unsigned solution weight targeted by the OCW. We set it to the maximum possible value of
    // a single extrinsic.
    type OffchainSolutionWeightLimit = OffchainSolutionWeightLimit;
    type ElectionProvider = ElectionProviderMultiPhase;
    type WeightInfo = pallet_staking::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    // phase durations. 1/4 of the last session for each.
    pub const SignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const UnsignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;

    // fallback: no need to do on-chain phragmen initially.
    pub const Fallback: pallet_election_provider_multi_phase::FallbackStrategy =
        pallet_election_provider_multi_phase::FallbackStrategy::Nothing;

    pub SolutionImprovementThreshold: Perbill = Perbill::from_rational(1u32, 10_000);

    // miner configs
    pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
    pub const MinerMaxIterations: u32 = 10;
    pub MinerMaxWeight: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(DefaultBlockExecutionWeight::get());
}

impl pallet_election_provider_multi_phase::Config for Runtime {
    type Event = Event;
    type Currency = Balances;
    type SignedPhase = SignedPhase;
    type UnsignedPhase = UnsignedPhase;
    type SolutionImprovementThreshold = MinSolutionScoreBump;
    type MinerMaxIterations = MinerMaxIterations;
    type MinerMaxWeight = MinerMaxWeight;
    type MinerTxPriority = MultiPhaseUnsignedPriority;
    type DataProvider = Staking;
    type OnChainAccuracy = Perbill;
    type CompactSolution = pallet_staking::CompactAssignments;
    type Fallback = Fallback;
    type WeightInfo = pallet_election_provider_multi_phase::weights::SubstrateWeight<Runtime>;
    type BenchmarkingConfig = ();
}

impl pallet_authority_discovery::Config for Runtime {}

impl grandpa::Config for Runtime {
    type Event = Event;

    type Call = Call;

    type KeyOwnerProof =
        <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;

    type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        GrandpaId,
    )>>::IdentificationTuple;

    type KeyOwnerProofSystem = Historical;

    type HandleEquivocation =
        grandpa::EquivocationHandler<Self::KeyOwnerIdentification, Offences, ReportLongevity>;

    type WeightInfo = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = Babe;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 500;
    pub const MaxLocks: u32 = 50;
}

impl balances::Config for Runtime {
    /// The type for recording an account's balance.
    type Balance = Balance;
    type DustRemoval = ();
    /// The ubiquitous event type.
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = MaxLocks;
}

parameter_types! {
    /// .01 token
    pub const TransactionByteFee: Balance = DOCK / 100;
}

impl transaction_payment::Config for Runtime {
    /// Transaction fees is handled by PoA module
    type OnChargeTransaction = CurrencyAdapter<Balances, PoAModule>;
    type TransactionByteFee = TransactionByteFee;
    type WeightToFee = TxnFee<Balance>;
    type FeeMultiplierUpdate = ();
}

impl did::Trait for Runtime {
    type Event = Event;
}

impl revoke::Trait for Runtime {}

parameter_types! {
    pub const MaxBlobSize: u32 = 1024;
    pub const StorageWeight: Weight = 1100;
}

impl blob::Trait for Runtime {
    type MaxBlobSize = MaxBlobSize;
    type StorageWeight = StorageWeight;
}

parameter_types! {
    pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(17);
}

impl pallet_session::Config for Runtime {
    type Event = Event;
    type ValidatorId = <Self as system::Config>::AccountId;
    type ValidatorIdOf = pallet_staking::StashOf<Self>;
    type ShouldEndSession = Babe;
    type NextSessionRotation = Babe;
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = SessionKeys;
    type DisabledValidatorsThreshold = DisabledValidatorsThreshold;
    type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

impl pallet_session::historical::Config for Runtime {
    type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
    type FullIdentificationOf = pallet_staking::ExposureOf<Runtime>;
}

parameter_types! {
    pub OffencesWeightSoftLimit: Weight = Perbill::from_percent(60) *
        RuntimeBlockWeights::get().max_block;
}

impl pallet_offences::Config for Runtime {
    type Event = Event;
    type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
    type OnOffenceHandler = Staking;
    type WeightSoftLimit = OffencesWeightSoftLimit;
}

impl poa::Trait for Runtime {
    type Event = Event;
    type Currency = balances::Module<Runtime>;
}

parameter_types! {
    /// Number of vesting milestones
    pub const VestingMilestones: u8 = 3;
    /// Vesting duration in number of blocks. Duration is 183 days and block time is 3 sec. (183 * 24 * 3600) / 3 = 5270400
    pub const VestingDuration: u32 = 5270400;
}

// `VestingMilestones` and `VestingDuration` must be > 0
const_assert!(VestingMilestones::get() > 0);
const_assert!(VestingDuration::get() > 0);

impl token_migration::Trait for Runtime {
    type Event = Event;
    type Currency = balances::Module<Runtime>;
    type BlockNumberToBalance = ConvertInto;
    type VestingMilestones = VestingMilestones;
    type VestingDuration = VestingDuration;
}

parameter_types! {
    pub const UncleGenerations: u32 = 5;
}

impl pallet_authorship::Config for Runtime {
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = ();
    type EventHandler = (Staking, ImOnline);
}

/// Utility pallet is needed to send extrinsics in a batch
impl pallet_utility::Config for Runtime {
    type Event = Event;
    type Call = Call;
    type WeightInfo = ();
}

impl master::Trait for Runtime {
    type Event = Event;
    type Call = Call;
}

impl sudo::Config for Runtime {
    type Event = Event;
    type Call = Call;
}

impl anchor::Trait for Runtime {
    type Event = Event;
}

impl attest::Trait for Runtime {
    type StorageWeight = StorageWeight;
}

/// This origin indicates that either >50% (simple majority) of Council members approved some dispatch (through a proposal)
/// or the dispatch was done as `Root` (by sudo or master)
type RootOrMoreThanHalfCouncil = EnsureOneOf<
    AccountId,
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionMoreThan<_1, _2, AccountId, CouncilCollective>,
>;

type CouncilMember = pallet_collective::EnsureMember<AccountId, CouncilCollective>;

parameter_types! {
    pub const CouncilMotionDuration: BlockNumber = 7 * DAYS;
    pub const CouncilMaxProposals: u32 = 100;
    pub const CouncilMaxMembers: u32 = 30;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Runtime {
    type Origin = Origin;
    type Proposal = Call;
    type Event = Event;
    type MotionDuration = CouncilMotionDuration;
    type MaxProposals = CouncilMaxProposals;
    type MaxMembers = CouncilMaxMembers;
    type DefaultVote = pallet_collective::MoreThanMajorityThenPrimeDefaultVote;
    type WeightInfo = ();
}

/// This instance of the membership pallet corresponds to Council.
/// Adding, removing, swapping, reseting members requires an approval of simple majority of the Council
/// or `Root` origin
impl pallet_membership::Config<pallet_membership::Instance1> for Runtime {
    type Event = Event;
    type AddOrigin = RootOrMoreThanHalfCouncil;
    type RemoveOrigin = RootOrMoreThanHalfCouncil;
    type SwapOrigin = RootOrMoreThanHalfCouncil;
    type ResetOrigin = RootOrMoreThanHalfCouncil;
    type PrimeOrigin = RootOrMoreThanHalfCouncil;
    type MembershipInitialized = Council;
    type MembershipChanged = Council;
}

parameter_types! {
    pub const TechnicalMotionDuration: BlockNumber = 7 * DAYS;
    pub const TechnicalMaxProposals: u32 = 100;
    pub const TechnicalMaxMembers: u32 = 50;
}

type TechnicalCollective = pallet_collective::Instance2;
impl pallet_collective::Config<TechnicalCollective> for Runtime {
    type Origin = Origin;
    type Proposal = Call;
    type Event = Event;
    type MotionDuration = TechnicalMotionDuration;
    type MaxProposals = TechnicalMaxProposals;
    type MaxMembers = TechnicalMaxMembers;
    type DefaultVote = pallet_collective::MoreThanMajorityThenPrimeDefaultVote;
    type WeightInfo = ();
}

/// This instance of the membership pallet corresponds to the Technical committee which can fast track proposals.
/// Adding, removing, swapping, resetting members requires an approval of simple majority of the Council
/// or `Root` origin, the technical committee itself cannot change its membership
impl pallet_membership::Config<pallet_membership::Instance2> for Runtime {
    type Event = Event;
    type AddOrigin = RootOrMoreThanHalfCouncil;
    type RemoveOrigin = RootOrMoreThanHalfCouncil;
    type SwapOrigin = RootOrMoreThanHalfCouncil;
    type ResetOrigin = RootOrMoreThanHalfCouncil;
    type PrimeOrigin = RootOrMoreThanHalfCouncil;
    type MembershipInitialized = TechnicalCommittee;
    type MembershipChanged = TechnicalCommittee;
}

parameter_types! {
    pub const MaxScheduledPerBlock: u32 = 50;
}

impl pallet_scheduler::Config for Runtime {
    type Event = Event;
    type Origin = Origin;
    type PalletsOrigin = OriginCaller;
    type Call = Call;
    type MaximumWeight = MaximumBlockWeight;
    type ScheduleOrigin = EnsureRoot<AccountId>;
    type MaxScheduledPerBlock = MaxScheduledPerBlock;
    type WeightInfo = ();
}

parameter_types! {
    pub const EnactmentPeriod: BlockNumber = 2 * DAYS;
    pub const LaunchPeriod: BlockNumber = 20 * DAYS;
    pub const VotingPeriod: BlockNumber = 15 * DAYS;
    pub const FastTrackVotingPeriod: BlockNumber = 3 * HOURS;
    /// 1000 tokens
    pub const MinimumDeposit: Balance = 1_000 * DOCK;
    /// 0.1 token
    pub const PreimageByteDeposit: Balance = DOCK / 10;
    pub const MaxVotes: u32 = 100;
    pub const MaxProposals: u32 = 100;
    pub const InstantAllowed: bool = true;
}

impl simple_democracy::Trait for Runtime {
    type Event = Event;
    /// Only council members can vote
    type VoterOrigin = CouncilMember;
}

impl pallet_democracy::Trait for Runtime {
    type Proposal = Call;
    type Event = Event;
    type Currency = Balances;
    type EnactmentPeriod = EnactmentPeriod;
    type LaunchPeriod = LaunchPeriod;
    type VotingPeriod = VotingPeriod;
    type CooloffPeriod = ();
    type MinimumDeposit = MinimumDeposit;
    /// Only specified to compile, not used however.
    type ExternalOrigin = CouncilMember;
    type ExternalMajorityOrigin = CouncilMember;
    /// Only specified to compile, not used however.
    type ExternalDefaultOrigin = RootOrMoreThanHalfCouncil;
    /// Two thirds of the technical committee can have an ExternalMajority/ExternalDefault vote
    /// be tabled immediately and with a shorter voting/enactment period.
    type FastTrackOrigin = EnsureOneOf<
        AccountId,
        pallet_collective::EnsureProportionAtLeast<_2, _3, AccountId, TechnicalCollective>,
        EnsureRoot<AccountId>,
    >;
    /// Root or the Council unanimously agreeing can make a Council proposal a referendum instantly.
    type InstantOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<_1, _1, AccountId, CouncilCollective>,
    >;
    type InstantAllowed = InstantAllowed;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    type CancellationOrigin = RootOrMoreThanHalfCouncil;
    /// Any council member can cancel a public proposal
    type CancelProposalOrigin = CouncilMember;
    type PreimageByteDeposit = PreimageByteDeposit;
    /// Slashes are handled by Democracy
    type Slash = SimpleDemocracy;
    type OperationalPreimageOrigin = CouncilMember;
    type VetoOrigin = pallet_collective::EnsureMember<AccountId, TechnicalCollective>;
    type Scheduler = Scheduler;
    type PalletsOrigin = OriginCaller;
    type MaxVotes = MaxVotes;
    type MaxProposals = MaxProposals;
    type WeightInfo = ();
}

pub struct EthereumFindAuthor<F>(PhantomData<F>);
impl<F: FindAuthor<u32>> FindAuthor<H160> for EthereumFindAuthor<F> {
    fn find_author<'a, I>(digests: I) -> Option<H160>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        if let Some(author_index) = F::find_author(digests) {
            // TODO: Check if AuthorityDiscovery::current_authorities is safe to use
            let authority_id = Babe::authorities()[author_index as usize].clone();
            return Some(H160::from_slice(&authority_id.0.to_raw_vec()[4..24]));
        }
        None
    }
}

impl pallet_ethereum::Config for Runtime {
    type Event = Event;
    type FindAuthor = EthereumFindAuthor<Babe>;
    type StateRoot = pallet_ethereum::IntermediateStateRoot;
}

parameter_types! {
    // Keeping 22 as its the ss58 prefix of mainnet
    pub const DockChainId: u64 = 22;
    pub BlockGasLimit: U256 = U256::from(u32::max_value());
}

/*
Considering the cost of following ops assuming 1 gas = 1 mirco-token.
ERC token deploy - 891,328 gas = 0.8 tokens
ERC token send - 28,500 gas = 0.0285 tokens
Link token deploy - 951,000 gas = 0.951 tokens
Link token send - 47,066 gas = 0.047 tokens
AccessControlledAggregator - 4,425,900 gas = 4.425 tokens
AggregatorProxy - 1,665,600 gas = 1.665 tokens
Aggregator submit - 209,500 gas = 0.209 tokens
Aggregator add access - 45,200 gas = 0.045 tokens
Add oracle - 135,600 gas = 0.135 tokens
EVM transfer DOCK token - 21,000 gas = 0.021 tokens

The above is much lower than we would like. At this price it seems better to use EVM for token transfers.
 */

/// Fixed gas price
pub struct GasPrice;
impl FeeCalculator for GasPrice {
    fn min_gas_price() -> U256 {
        // Gas price is always 50 mirco-token (0.00005 token) per gas.
        50.into()
    }
}

pub const WEIGHT_PER_GAS: u64 = 50;

pub struct GasWeightMap;
impl pallet_evm::GasWeightMapping for GasWeightMap {
    fn gas_to_weight(gas: u64) -> Weight {
        gas.saturating_mul(WEIGHT_PER_GAS)
    }
    fn weight_to_gas(weight: Weight) -> u64 {
        u64::try_from(weight.wrapping_div(WEIGHT_PER_GAS)).unwrap_or(u32::MAX as u64)
    }
}

impl pallet_evm::Config for Runtime {
    /// Minimum gas price is 50
    type FeeCalculator = GasPrice;
    /// 1:50 mapping of gas to weight
    type GasWeightMapping = GasWeightMap;
    type CallOrigin = EnsureAddressTruncated;
    type WithdrawOrigin = EnsureAddressTruncated;
    type AddressMapping = HashedAddressMapping<BlakeTwo256>;
    type Currency = Balances;
    type Event = Event;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type Precompiles = (
        pallet_evm_precompile_simple::ECRecover,
        pallet_evm_precompile_simple::Sha256,
        pallet_evm_precompile_simple::Ripemd160,
        pallet_evm_precompile_simple::Identity,
        pallet_evm_precompile_simple::ECRecoverPublicKey,
        pallet_evm_precompile_sha3fips::Sha3FIPS256,
        pallet_evm_precompile_sha3fips::Sha3FIPS512,
        pallet_evm_precompile_ed25519::Ed25519Verify,
        pallet_evm_precompile_modexp::Modexp,
        pallet_evm_precompile_bn128::Bn128Add,
        pallet_evm_precompile_bn128::Bn128Mul,
        pallet_evm_precompile_bn128::Bn128Pairing,
        pallet_evm_precompile_dispatch::Dispatch<Self>,
    );
    type ChainId = DockChainId;
    /// Deducted fee will be handled by the PoA module
    type OnChargeTransaction = EVMCurrencyAdapter<Balances, PoAModule>;

    type BlockGasLimit = BlockGasLimit;

    fn config() -> &'static EvmConfig {
        // EvmConfig::frontier() has `create_contract_limit` set to None but causes runtime panic
        static mut CFG: EvmConfig = EvmConfig::istanbul();
        unsafe {
            CFG.create_contract_limit = None;
            &CFG
        }
    }
}

impl price_feed::Config for Runtime {
    type Event = Event;
}

impl fiat_filter::Config for Runtime {
    type Call = Call;
    type PriceProvider = price_feed::Module<Runtime>;
    type Currency = balances::Module<Runtime>;
}

pub struct BaseFilter;
impl Filter<Call> for BaseFilter {
    fn filter(call: &Call) -> bool {
        match call {
            Call::Democracy(_) => false,
            // filter out core_mods calls so they're only done through fiat_filter
            Call::Anchor(_) => false,
            Call::BlobStore(_) => false,
            Call::DIDModule(_) => false,
            Call::Revoke(_) => false,
            Call::Attest(_) => false,
            _ => true,
        }
    }
}

// Balances pallet has to be put before Session in construct_runtime otherwise there is a runtime panic.

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: system::{Module, Call, Config, Storage, Event<T>},
        RandomnessCollectiveFlip: randomness_collective_flip::{Module, Call, Storage},
        Timestamp: timestamp::{Module, Call, Storage, Inherent},
        Balances: balances::{Module, Call, Storage, Config<T>, Event<T>},
        Session: pallet_session::{Module, Call, Storage, Event, Config<T>},
        PoAModule: poa::{Module, Call, Storage, Event<T>, Config<T>},
        Grandpa: grandpa::{Module, Call, Storage, Config, Event},
        Authorship: pallet_authorship::{Module, Call, Storage},
        TransactionPayment: transaction_payment::{Module, Storage},
        Utility: pallet_utility::{Module, Call, Event},
        DIDModule: did::{Module, Call, Storage, Event, Config},
        Revoke: revoke::{Module, Call, Storage},
        BlobStore: blob::{Module, Call, Storage},
        Master: master::{Module, Call, Storage, Event<T>, Config},
        Sudo: sudo::{Module, Call, Storage, Event<T>, Config<T>},
        MigrationModule: token_migration::{Module, Call, Storage, Event<T>},
        Anchor: anchor::{Module, Call, Storage, Event<T>},
        SimpleDemocracy: simple_democracy::{Module, Call, Event},
        Democracy: pallet_democracy::{Module, Call, Storage, Event<T>},
        Council: pallet_collective::<Instance1>::{Module, Call, Storage, Origin<T>, Event<T>, Config<T>},
        CouncilMembership: pallet_membership::<Instance1>::{Module, Call, Storage, Event<T>, Config<T>},
        TechnicalCommittee: pallet_collective::<Instance2>::{Module, Call, Storage, Origin<T>, Event<T>, Config<T>},
        TechnicalCommitteeMembership: pallet_membership::<Instance2>::{Module, Call, Storage, Event<T>, Config<T>},
        Scheduler: pallet_scheduler::{Module, Call, Storage, Event<T>},
        Attest: attest::{Module, Call, Storage},
        Ethereum: pallet_ethereum::{Module, Call, Storage, Event, Config, ValidateUnsigned},
        EVM: pallet_evm::{Module, Config, Call, Storage, Event<T>},
        PriceFeedModule: price_feed::{Module, Call, Storage, Event, Config},
        FiatFilterModule: fiat_filter::{Module, Call},
        AuthorityDiscovery: pallet_authority_discovery::{Module, Call, Config},
        Historical: pallet_session_historical::{Module},
        ImOnline: pallet_im_online::{Module, Call, Storage, Event<T>, ValidateUnsigned, Config<T>},
        Babe: pallet_babe::{Module, Call, Storage, Config, ValidateUnsigned},
        Staking: pallet_staking::{Module, Call, Config<T>, Storage, Event<T>, ValidateUnsigned},
        ElectionProviderMultiPhase: pallet_election_provider_multi_phase::{Module, Call, Storage, Event<T>, ValidateUnsigned},
        Offences: pallet_offences::{Module, Call, Storage, Event},
    }
);

pub struct TransactionConverter;

impl fp_rpc::ConvertTransaction<UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(&self, transaction: pallet_ethereum::Transaction) -> UncheckedExtrinsic {
        UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact(transaction).into(),
        )
    }
}

impl fp_rpc::ConvertTransaction<opaque::UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(
        &self,
        transaction: pallet_ethereum::Transaction,
    ) -> opaque::UncheckedExtrinsic {
        let extrinsic = UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact(transaction).into(),
        );
        let encoded = extrinsic.encode();
        opaque::UncheckedExtrinsic::decode(&mut &encoded[..])
            .expect("Encoded extrinsic is always valid")
    }
}

/// Unchecked extrinsic type as expected by this runtime.
type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<Call, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, Call, SignedExtra>;
/// Executive: handles dispatch to the various modules.
type Executive =
    frame_executive::Executive<Runtime, Block, system::ChainContext<Runtime>, Runtime, AllModules>;

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The SignedExtension to the basic transaction logic.
type SignedExtra = (
    system::CheckSpecVersion<Runtime>,
    system::CheckTxVersion<Runtime>,
    system::CheckGenesis<Runtime>,
    system::CheckEra<Runtime>,
    system::CheckNonce<Runtime>,
    system::CheckWeight<Runtime>,
    transaction_payment::ChargeTransactionPayment<Runtime>,
    token_migration::OnlyMigrator<Runtime>,
);

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block)
        }

        fn initialize_block(header: &<Block as BlockT>::Header) {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            Runtime::metadata().into()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }

        fn random_seed() -> <Block as BlockT>::Hash {
            RandomnessCollectiveFlip::random_seed().0
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_babe::BabeApi<Block> for Runtime {
        fn configuration() -> sp_consensus_babe::BabeGenesisConfiguration {
            // The choice of `c` parameter (where `1 - c` represents the
            // probability of a slot being empty), is done in accordance to the
            // slot duration and expected target block time, for safely
            // resisting network delays of maximum two seconds.
            // <https://research.web3.foundation/en/latest/polkadot/BABE/Babe/#6-practical-results>
            sp_consensus_babe::BabeGenesisConfiguration {
                slot_duration: Babe::slot_duration(),
                epoch_length: EpochDuration::get(),
                c: BABE_GENESIS_EPOCH_CONFIG.c,
                genesis_authorities: Babe::authorities(),
                randomness: Babe::randomness(),
                allowed_slots: BABE_GENESIS_EPOCH_CONFIG.allowed_slots,
            }
        }

        fn current_epoch_start() -> sp_consensus_babe::Slot {
            Babe::current_epoch_start()
        }

        fn current_epoch() -> sp_consensus_babe::Epoch {
            Babe::current_epoch()
        }

        fn next_epoch() -> sp_consensus_babe::Epoch {
            Babe::next_epoch()
        }

        fn generate_key_ownership_proof(
            _slot: sp_consensus_babe::Slot,
            authority_id: sp_consensus_babe::AuthorityId,
        ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
            use codec::Encode;

            Historical::prove((sp_consensus_babe::KEY_TYPE, authority_id))
                .map(|p| p.encode())
                .map(sp_consensus_babe::OpaqueKeyOwnershipProof::new)
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            equivocation_proof: sp_consensus_babe::EquivocationProof<<Block as BlockT>::Header>,
            key_owner_proof: sp_consensus_babe::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;

            Babe::submit_unsigned_equivocation_report(
                equivocation_proof,
                key_owner_proof,
            )
        }
    }

    impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
        fn authorities() -> Vec<AuthorityDiscoveryId> {
            AuthorityDiscovery::authorities()
        }
    }

    impl fg_primitives::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> GrandpaAuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: fg_primitives::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            _key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: fg_primitives::SetId,
            _authority_id: GrandpaId,
        ) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
            // NOTE: this is the only implementation possible since we've
            // defined our key owner proof type as a bottom type (i.e. a type
            // with no values).
            None
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
        fn account_nonce(account: AccountId) -> Index {
            System::account_nonce(account)
        }
    }

    impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
        fn chain_id() -> u64 {
            <Runtime as pallet_evm::Config>::ChainId::get()
        }

        fn account_basic(address: H160) -> EVMAccount {
            EVM::account_basic(&address)
        }

        fn gas_price() -> U256 {
            <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price()
        }

        fn account_code_at(address: H160) -> Vec<u8> {
            EVM::account_codes(address)
        }

        fn author() -> H160 {
            <pallet_ethereum::Module<Runtime>>::find_author()
        }

        fn storage_at(address: H160, index: U256) -> H256 {
            let mut tmp = [0u8; 32];
            index.to_big_endian(&mut tmp);
            EVM::account_storages(address, H256::from_slice(&tmp[..]))
        }

        fn call(
            from: H160,
            to: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            gas_price: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
        ) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            <Runtime as pallet_evm::Config>::Runner::call(
                from,
                to,
                data,
                value,
                gas_limit.low_u64(),
                gas_price,
                nonce,
                config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
            ).map_err(|err| err.into())
        }

        fn create(
            from: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            gas_price: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
        ) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            <Runtime as pallet_evm::Config>::Runner::create(
                from,
                data,
                value,
                gas_limit.low_u64(),
                gas_price,
                nonce,
                config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
            ).map_err(|err| err.into())
        }

        fn current_transaction_statuses() -> Option<Vec<TransactionStatus>> {
            Ethereum::current_transaction_statuses()
        }

        fn current_block() -> Option<pallet_ethereum::Block> {
            Ethereum::current_block()
        }

        fn current_receipts() -> Option<Vec<pallet_ethereum::Receipt>> {
            Ethereum::current_receipts()
        }

        fn current_all() -> (
            Option<pallet_ethereum::Block>,
            Option<Vec<pallet_ethereum::Receipt>>,
            Option<Vec<TransactionStatus>>
        ) {
            (
                Ethereum::current_block(),
                Ethereum::current_receipts(),
                Ethereum::current_transaction_statuses()
            )
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }

        fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> pallet_transaction_payment_rpc_runtime_api::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
    }

    impl poa::runtime_api::PoAApi<Block, AccountId, Balance> for Runtime {
        fn get_treasury_account() -> AccountId {
            PoAModule::treasury_account()
        }

        fn get_treasury_balance() -> Balance {
            PoAModule::treasury_balance()
        }

        fn get_total_emission_in_epoch(epoch_no: poa::EpochNo) -> Balance {
            PoAModule::get_total_emission_in_epoch(epoch_no)
        }
    }

    impl price_feed::runtime_api::PriceFeedApi<Block> for Runtime {
        fn token_usd_price() -> Option<u32> {
            PriceFeedModule::price()
        }

        fn token_usd_price_from_contract() -> Option<u32> {
            PriceFeedModule::get_price_from_contract().map_or(None, |(v, _)| Some(v))
        }
    }

    impl fiat_filter_rpc_runtime_api::FiatFeeRuntimeApi<Block, Balance> for Runtime {
        fn get_call_fee_dock(uxt: <Block as BlockT>::Extrinsic) -> Result<Balance, fiat_filter_rpc_runtime_api::Error> {
            match FiatFilterModule::get_call_fee_dock_(&uxt.function) {
                Ok((fee_microdock,_weight)) => Ok(fee_microdock),
                Err(e) => Err(fiat_filter_rpc_runtime_api::Error::new_getcallfeedock(e))
            }
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch, add_benchmark, TrackedStorageKey};
            // Following line copied from substrate node
            // Trying to add benchmarks directly to the Session Pallet caused cyclic dependency issues.
            // To get around that, we separated the Session benchmarks into its own crate, which is why
            // we need these two lines below.
            // use pallet_session_benchmarking::Module as SessionBench;
            use frame_system_benchmarking::Module as SystemBench;

            // impl pallet_session_benchmarking::Trait for Runtime {}
            impl frame_system_benchmarking::Config for Runtime {}

            let whitelist: Vec<TrackedStorageKey> = vec![
                // Block Number
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
                // Total Issuance
                hex_literal::hex!("c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80").to_vec().into(),
                // Execution Phase
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
                // Event Count
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
                // System Events
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
            ];

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmark!(params, batches, did, DIDModule);
            add_benchmark!(params, batches, revoke, Revoke);
            add_benchmark!(params, batches, blob, BlobStore);
            add_benchmark!(params, batches, balances, Balances);
            add_benchmark!(params, batches, token_migration, MigrationModule);
            add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);

            add_benchmark!(params, batches, pallet_collective, Council);
            add_benchmark!(params, batches, pallet_democracy, Democracy);
            add_benchmark!(params, batches, pallet_scheduler, Scheduler);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_system::offchain::CreateSignedTransaction;

    #[test]
    fn validate_transaction_submitter_bounds() {
        fn is_submit_signed_transaction<T>()
        where
            T: CreateSignedTransaction<Call>,
        {
        }

        is_submit_signed_transaction::<Runtime>();
    }
}
