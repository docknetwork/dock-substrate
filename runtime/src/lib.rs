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
pub use core_mods::bbs_plus;
pub use core_mods::blob;
pub use core_mods::did;
pub use core_mods::master;
pub use core_mods::revoke;
pub mod weight_to_fee;

pub use poa;
pub use price_feed;
pub use token_migration;

use codec::{Decode, Encode};
use frame_support::{
    construct_runtime, parameter_types,
    traits::{
        Currency, CurrencyToVote, Filter, FindAuthor, Imbalance, KeyOwnerProofSystem,
        LockIdentifier, OnUnbalanced, Randomness,
    },
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_PER_SECOND},
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
use sp_core::u32_trait::{_1, _2, _3, _4, _5};
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
    ApplyExtrinsicResult, FixedPointNumber, ModuleId, MultiSignature, Perbill, Percent, Permill,
    Perquintill, SaturatedConversion,
};
use sp_std::collections::btree_map::BTreeMap;
use transaction_payment::{CurrencyAdapter, Multiplier, TargetedFeeAdjustment};

use evm::Config as EvmConfig;
use fp_rpc::TransactionStatus;
use pallet_ethereum::{Call::transact, Transaction as EthereumTransaction};
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
use sp_runtime::curve::PiecewiseLinear;

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

/// This runtime version. Whe compiling with feature "mainnet", `spec_name` will be "dock-main-runtime",
/// when compiling with feature "testnet", `spec_name` will be "dock-test-runtime", when not using either
/// of those, `spec_name` will be "dock-dev-runtime"
pub const VERSION: RuntimeVersion = RuntimeVersion {
    #[cfg(feature = "mainnet")]
    spec_name: create_runtime_str!("dock-pos-main-runtime"),
    #[cfg(feature = "testnet")]
    spec_name: create_runtime_str!("dock-pos-test-runtime"),
    #[cfg(not(any(feature = "testnet", feature = "mainnet")))]
    spec_name: create_runtime_str!("dock-pos-dev-runtime"),
    impl_name: create_runtime_str!("Dock"),
    authoring_version: 1,
    spec_version: 33,
    impl_version: 1,
    transaction_version: 1,
    apis: RUNTIME_API_VERSIONS,
};

/// `fastblock` reduces the block time for faster testing. It isn't recommended for production.
/// Also build the node in release mode to support small block times (< 1 sec)
/// TODO: Support instant seal
#[cfg(feature = "fastblock")]
pub const MILLISECS_PER_BLOCK: u64 = 600;

#[cfg(not(feature = "fastblock"))]
pub const MILLISECS_PER_BLOCK: u64 = 3000;

const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// The modules `small_durations` is used to generate runtimes with small duration events like epochs, eras,
// bonding durations, etc for testing purposes. They should NOT be used in production.
#[allow(dead_code)]
mod small_durations {
    use super::{BlockNumber, DAYS, MINUTES};

    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 2 * MINUTES;
    pub const EPOCH_DURATION_IN_SLOTS: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 3;
    /// Bonding duration is in number of era
    pub const BONDING_DURATION: pallet_staking::EraIndex = 24 * 8;
    pub const SLASH_DEFER_DURATION: pallet_staking::EraIndex = 24 * 2; // 1/4 the bonding duration.
    /// Specifies the number of blocks for which the equivocation is valid.
    pub const REPORT_LONGEVITY: u64 =
        BONDING_DURATION as u64 * SESSIONS_PER_ERA as u64 * EPOCH_DURATION_IN_SLOTS;
    /// The number of blocks before the end of the era from which election submissions are allowed. Used for validator elections.
    pub const ELECTION_LOOKAHEAD: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;

    /// How long each seat is kept for elections. Used for gov.
    pub const TERM_DURATION: BlockNumber = 7 * DAYS;
    /// The time-out for council motions.
    pub const COUNCIL_MOTION_DURATION: BlockNumber = 10 * MINUTES;
    /// The time-out for technical committee motions.
    pub const TECHNICAL_MOTION_DURATION: BlockNumber = 10 * MINUTES;
    /// Delay after which an accepted proposal executes
    pub const ENACTMENT_PERIOD: BlockNumber = 1 * MINUTES;
    /// How often new public referrenda are launched
    pub const LAUNCH_PERIOD: BlockNumber = 15 * MINUTES;
    pub const VOTING_PERIOD: BlockNumber = 10 * MINUTES;
    pub const FAST_TRACK_VOTING_PERIOD: BlockNumber = 2 * MINUTES;
    pub const COOLOFF_PERIOD: BlockNumber = 60 * MINUTES;

    /// Duration after which funds from treasury are spent for approved bounties
    pub const SPEND_PERIOD: BlockNumber = 15 * MINUTES;
    /// The delay period for which a bounty beneficiary need to wait before claim the payout.
    pub const BOUNTY_DEPOSIT_PAYOUT_DELAY: BlockNumber = 1 * MINUTES;
    /// The period for which a tip remains open after is has achieved threshold tippers.
    pub const TIP_COUNTDOWN: BlockNumber = 1 * MINUTES;
    /// Bounty duration in blocks.
    pub const BOUNTY_UPDATE_PERIOD: BlockNumber = 5 * MINUTES;
}

#[allow(dead_code)]
mod prod_durations {
    use super::{BlockNumber, DAYS, HOURS, MINUTES};

    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 3 * HOURS;
    pub const EPOCH_DURATION_IN_SLOTS: u64 = EPOCH_DURATION_IN_BLOCKS as u64;

    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 4; // 12 hours
    /// Bonding duration is in number of era
    pub const BONDING_DURATION: pallet_staking::EraIndex = 2 * 7; // 7 days
    pub const SLASH_DEFER_DURATION: pallet_staking::EraIndex = 7; // 1/2 the bonding duration.
    /// Specifies the number of blocks for which the equivocation is valid.
    pub const REPORT_LONGEVITY: u64 =
        BONDING_DURATION as u64 * SESSIONS_PER_ERA as u64 * EPOCH_DURATION_IN_SLOTS;
    /// The number of blocks before the end of the era from which election submissions are allowed. Used for validator elections.
    pub const ELECTION_LOOKAHEAD: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;

    /// How long each seat is kept for elections. Used for gov.
    pub const TERM_DURATION: BlockNumber = 7 * DAYS;
    /// The time-out for council motions.
    pub const COUNCIL_MOTION_DURATION: BlockNumber = 7 * DAYS;
    /// The time-out for technical committee motions.
    pub const TECHNICAL_MOTION_DURATION: BlockNumber = 7 * DAYS;
    /// Delay after which an accepted proposal executes
    pub const ENACTMENT_PERIOD: BlockNumber = 2 * DAYS;
    /// How often new public referrenda are launched
    pub const LAUNCH_PERIOD: BlockNumber = 20 * DAYS;
    pub const VOTING_PERIOD: BlockNumber = 15 * DAYS;
    pub const FAST_TRACK_VOTING_PERIOD: BlockNumber = 3 * HOURS;
    pub const COOLOFF_PERIOD: BlockNumber = 28 * 24 * 60 * MINUTES;

    /// Duration after which funds from treasury are spent for approved bounties
    pub const SPEND_PERIOD: BlockNumber = 1 * DAYS;
    /// The delay period for which a bounty beneficiary need to wait before claim the payout.
    pub const BOUNTY_DEPOSIT_PAYOUT_DELAY: BlockNumber = 1 * DAYS;
    /// The period for which a tip remains open after is has achieved threshold tippers.
    pub const TIP_COUNTDOWN: BlockNumber = 1 * DAYS;
    /// Bounty duration in blocks.
    pub const BOUNTY_UPDATE_PERIOD: BlockNumber = 14 * DAYS;
}

#[cfg(not(feature = "small_durations"))]
use prod_durations::*;
#[cfg(feature = "small_durations")]
use small_durations::*;

/// Era duration should be less than or equal year
// Milliseconds per year for the Julian year (365.25 days).
const MILLISECONDS_PER_YEAR: u64 = 1000 * 3600 * 24 * 36525 / 100;
const_assert!(
    (SESSIONS_PER_ERA as u64 * EPOCH_DURATION_IN_BLOCKS as u64 * MILLISECS_PER_BLOCK)
        <= MILLISECONDS_PER_YEAR
);

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
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(BlockExecutionWeight::get())
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
}

const_assert!(NORMAL_DISPATCH_RATIO.deconstruct() >= AVERAGE_ON_INITIALIZE_RATIO.deconstruct());

#[cfg(feature = "testnet")]
parameter_types! {
    pub const SS58Prefix: u8 = 21;
}

#[cfg(feature = "mainnet")]
parameter_types! {
    pub const SS58Prefix: u8 = 22;
}

#[cfg(not(any(feature = "testnet", feature = "mainnet")))]
parameter_types! {
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
    type SystemWeightInfo = frame_system::weights::SubstrateWeight<Runtime>;
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
    /// Specifies the number of blocks for which the equivocation is valid.
    pub const ReportLongevity: u64 = REPORT_LONGEVITY;
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
    pub const SessionsPerEra: sp_staking::SessionIndex = SESSIONS_PER_ERA;
    /// Bonding duration is in number of era
    pub const BondingDuration: pallet_staking::EraIndex = BONDING_DURATION;
    pub const SlashDeferDuration: pallet_staking::EraIndex = SLASH_DEFER_DURATION;
    /// A validator will only have 256 nominators, so max (rewarded) nominators is 256*50 = 12800.
    /// This number is smaller than current token holders (20K) but not all holder participate. Keeping
    /// it small to batch payout extrinsics
    pub const MaxNominatorRewardedPerValidator: u32 = 256;
    pub const ElectionLookahead: BlockNumber = ELECTION_LOOKAHEAD;
    pub const MaxIterations: u32 = 10;
    // 0.05%. The higher the value, the more strict solution acceptance becomes.
    pub MinSolutionScoreBump: Perbill = Perbill::from_rational(5u32, 10_000);
    pub OffchainSolutionWeightLimit: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
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
    type RewardRemainder = Treasury;
    type Event = Event;
    type Slash = Treasury; // send the slashed funds to the treasury.
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
    type EraPayout = StakingRewards;
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
    // TODO: Experiment with on-chain phragmen
    pub const Fallback: pallet_election_provider_multi_phase::FallbackStrategy =
        pallet_election_provider_multi_phase::FallbackStrategy::Nothing;

    pub SolutionImprovementThreshold: Perbill = Perbill::from_rational(1u32, 10_000);

    // miner configs
    pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
    pub const MinerMaxIterations: u32 = 10;
    pub MinerMaxWeight: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
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
    type WeightInfo = timestamp::weights::SubstrateWeight<Runtime>;
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
    type WeightInfo = balances::weights::SubstrateWeight<Runtime>;
    type MaxLocks = MaxLocks;
}

parameter_types! {
    /// .01 token
    pub const TransactionByteFee: Balance = DOCK / 100;
    pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(25);
    pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(1, 100_000);
    pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 1_000_000_000u128);
}

impl transaction_payment::Config for Runtime {
    type OnChargeTransaction = CurrencyAdapter<Balances, DealWithFees>;
    type TransactionByteFee = TransactionByteFee;
    type WeightToFee = TxnFee<Balance>;
    /// This would be useless after enabling fiat filter
    type FeeMultiplierUpdate =
        TargetedFeeAdjustment<Self, TargetBlockFullness, AdjustmentVariable, MinimumMultiplier>;
}

impl did::Trait for Runtime {
    type Event = Event;
}

impl revoke::Trait for Runtime {}

impl bbs_plus::Config for Runtime {
    type Event = Event;
    type ParamsMaxSize = ParamsMaxSize;
    type ParamsPerByteWeight = ParamsPerByteWeight;
    type PublicKeyMaxSize = PublicKeyMaxSize;
    type PublicKeyPerByteWeight = PublicKeyPerByteWeight;
}

parameter_types! {
    // 8KB
    pub const MaxBlobSize: u32 = 8192;
    pub const StorageWeight: Weight = 1100;
    pub const ParamsMaxSize: u32 = 65536;
    pub const ParamsPerByteWeight: Weight = 10;
    pub const PublicKeyMaxSize: u32 = 128;
    pub const PublicKeyPerByteWeight: Weight = 10;
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
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
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

/// This origin indicates that either >=66.66% of Council members approved some dispatch (through a proposal)
/// or the dispatch was done as `Root` (by sudo or master)
type RootOrTwoThirdCouncil = EnsureOneOf<
    AccountId,
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionAtLeast<_2, _3, AccountId, CouncilCollective>,
>;

type CouncilMember = pallet_collective::EnsureMember<AccountId, CouncilCollective>;

const fn deposit(items: u32, bytes: u32) -> Balance {
    items as Balance * 15 * (DOCK / 100) + (bytes as Balance) * 6 * (DOCK / 100)
}

parameter_types! {
    pub const CandidacyBond: Balance = 10 * DOCK;
    // 1 storage item created, key size is 32 bytes, value size is 16+16.
    pub const VotingBondBase: Balance = deposit(1, 64);
    // additional data per vote is 32 bytes (account id).
    pub const VotingBondFactor: Balance = deposit(0, 32);
    pub const TermDuration: BlockNumber = TERM_DURATION;
    pub const DesiredMembers: u32 = 13;
    pub const DesiredRunnersUp: u32 = 7;
    pub const ElectionsPhragmenModuleId: LockIdentifier = *b"phrelect";
}

// Make sure that there are no more than `MaxMembers` members elected via elections-phragmen.
const_assert!(DesiredMembers::get() <= CouncilMaxMembers::get());

impl pallet_elections_phragmen::Config for Runtime {
    type Event = Event;
    type ModuleId = ElectionsPhragmenModuleId;
    type Currency = Balances;
    type ChangeMembers = Council;
    // NOTE: this implies that council's genesis members cannot be set directly and must come from
    // this module.
    type InitializeMembers = Council;
    type CurrencyToVote = U64CurrencyToVote;
    type CandidacyBond = CandidacyBond;
    type VotingBondBase = VotingBondBase;
    type VotingBondFactor = VotingBondFactor;
    type LoserCandidate = ();
    type KickedMember = ();
    type DesiredMembers = DesiredMembers;
    type DesiredRunnersUp = DesiredRunnersUp;
    type TermDuration = TermDuration;
    type WeightInfo = pallet_elections_phragmen::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const CouncilMotionDuration: BlockNumber = COUNCIL_MOTION_DURATION;
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
    type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
}

/// This instance of the membership pallet corresponds to Council.
/// Adding, removing, swapping, resetting members requires an approval of simple majority of the Council
/// or `Root` origin
impl pallet_membership::Config<pallet_membership::Instance1> for Runtime {
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
    pub const TechnicalMotionDuration: BlockNumber = TECHNICAL_MOTION_DURATION;
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
    type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
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
    type WeightInfo = pallet_scheduler::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const EnactmentPeriod: BlockNumber = ENACTMENT_PERIOD;
    pub const LaunchPeriod: BlockNumber = LAUNCH_PERIOD;
    pub const VotingPeriod: BlockNumber = VOTING_PERIOD;
    pub const FastTrackVotingPeriod: BlockNumber = FAST_TRACK_VOTING_PERIOD;
    /// 1000 tokens
    pub const MinimumDeposit: Balance = 1_000 * DOCK;
    /// 0.1 token
    pub const PreimageByteDeposit: Balance = DOCK / 10;
    pub const MaxVotes: u32 = 100;
    pub const MaxProposals: u32 = 100;
    pub const InstantAllowed: bool = true;
    pub const CooloffPeriod: BlockNumber = COOLOFF_PERIOD;
}

impl pallet_democracy::Config for Runtime {
    type Proposal = Call;
    type Event = Event;
    type Currency = Balances;
    type EnactmentPeriod = EnactmentPeriod;
    type LaunchPeriod = LaunchPeriod;
    type VotingPeriod = VotingPeriod;
    type CooloffPeriod = CooloffPeriod;
    type MinimumDeposit = MinimumDeposit;
    /// A straight majority of the council can decide what their next motion is.
    type ExternalOrigin =
        pallet_collective::EnsureProportionAtLeast<_1, _2, AccountId, CouncilCollective>;
    /// A super-majority can have the next scheduled referendum be a straight majority-carries vote.
    type ExternalMajorityOrigin =
        pallet_collective::EnsureProportionAtLeast<_3, _4, AccountId, CouncilCollective>;
    /// A unanimous council can have the next scheduled referendum be a straight default-carries
    /// (NTB) vote.
    type ExternalDefaultOrigin =
        pallet_collective::EnsureProportionAtLeast<_1, _1, AccountId, CouncilCollective>;
    /// Two thirds of the technical committee can have an ExternalMajority/ExternalDefault vote
    /// be tabled immediately and with a shorter voting/enactment period.
    type FastTrackOrigin = EnsureOneOf<
        AccountId,
        pallet_collective::EnsureProportionAtLeast<_2, _3, AccountId, TechnicalCollective>,
        EnsureRoot<AccountId>,
    >;
    /// Root or the Technical committee unanimously agreeing can make a Council proposal a referendum instantly.
    type InstantOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<_1, _1, AccountId, TechnicalCollective>,
    >;
    type InstantAllowed = InstantAllowed;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    /// To cancel a proposal which has been passed, 2/3 of the council must agree to it.
    type CancellationOrigin = RootOrTwoThirdCouncil;
    // To cancel a proposal before it has been passed, the technical committee must be unanimous or
    // Root must agree.
    type CancelProposalOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<_1, _1, AccountId, TechnicalCollective>,
    >;
    type PreimageByteDeposit = PreimageByteDeposit;
    type Slash = Treasury;
    type OperationalPreimageOrigin = CouncilMember;
    type BlacklistOrigin = EnsureRoot<AccountId>;
    // Any single technical committee member may veto a coming council proposal, however they can
    // only do it once and it lasts only for the cool-off period.
    type VetoOrigin = pallet_collective::EnsureMember<AccountId, TechnicalCollective>;
    type Scheduler = Scheduler;
    type PalletsOrigin = OriginCaller;
    type MaxVotes = MaxVotes;
    type MaxProposals = MaxProposals;
    type WeightInfo = pallet_democracy::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const ProposalBond: Permill = Permill::from_percent(5);
    pub const ProposalBondMinimum: Balance = 1 * DOCK;
    pub const SpendPeriod: BlockNumber = SPEND_PERIOD;
    /// We are fixed supply token, we don't burn any tokens
    pub const Burn: Permill = Permill::from_percent(0);
    pub const DataDepositPerByte: Balance = DOCK / 100;
    pub const BountyDepositBase: Balance = 1 * DOCK;
    pub const BountyDepositPayoutDelay: BlockNumber = BOUNTY_DEPOSIT_PAYOUT_DELAY;
    pub const BountyCuratorDeposit: Permill = Permill::from_percent(50);
    pub const BountyValueMinimum: Balance = 5 * DOCK;
    pub const TipCountdown: BlockNumber = TIP_COUNTDOWN;
    pub const TipFindersFee: Percent = Percent::from_percent(20);
    pub const TipReportDepositBase: Balance = 1 * DOCK;
    /// Matches treasury account created during PoA.
    pub const TreasuryModuleId: ModuleId = ModuleId(*b"Treasury");
    pub const BountyUpdatePeriod: BlockNumber = BOUNTY_UPDATE_PERIOD;
    pub const MaximumReasonLength: u32 = 16384;
}

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

/// Deals with transaction fees
pub struct DealWithFees;

impl DealWithFees {
    /// Credit fee and tip, if any, to treasury and block author in a ratio
    fn credit_to_treasury_and_block_author(fee_and_tip: NegativeImbalance) {
        let treasury_share = TreasuryRewardsPct::get().deconstruct() as u32;
        let block_author_share = 100 - treasury_share;
        let split = fee_and_tip.ration(treasury_share, block_author_share);
        Treasury::on_unbalanced(split.0);
        Balances::resolve_creating(&Authorship::author(), split.1);
    }
}

impl OnUnbalanced<NegativeImbalance> for DealWithFees {
    fn on_unbalanceds<B>(mut fees_then_tips: impl Iterator<Item = NegativeImbalance>) {
        if let Some(mut fees) = fees_then_tips.next() {
            if let Some(tips) = fees_then_tips.next() {
                fees.subsume(tips);
            }
            DealWithFees::credit_to_treasury_and_block_author(fees);
        }
    }

    fn on_unbalanced(amount: NegativeImbalance) {
        DealWithFees::credit_to_treasury_and_block_author(amount);
    }
}

impl pallet_treasury::Config for Runtime {
    type ModuleId = TreasuryModuleId;
    type Currency = Balances;
    type ApproveOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<_3, _5, AccountId, CouncilCollective>,
    >;
    type RejectOrigin = EnsureOneOf<
        AccountId,
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionMoreThan<_1, _2, AccountId, CouncilCollective>,
    >;
    type Event = Event;
    type OnSlash = ();
    type ProposalBond = ProposalBond;
    type ProposalBondMinimum = ProposalBondMinimum;
    type SpendPeriod = SpendPeriod;
    type Burn = Burn;
    type BurnDestination = Treasury;
    type SpendFunds = Bounties;
    type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
}

impl pallet_tips::Config for Runtime {
    type Event = Event;
    type DataDepositPerByte = DataDepositPerByte;
    type MaximumReasonLength = MaximumReasonLength;
    type Tippers = Elections;
    type TipCountdown = TipCountdown;
    type TipFindersFee = TipFindersFee;
    type TipReportDepositBase = TipReportDepositBase;
    type WeightInfo = pallet_tips::weights::SubstrateWeight<Runtime>;
}

impl pallet_bounties::Config for Runtime {
    type Event = Event;
    type BountyDepositBase = BountyDepositBase;
    type BountyDepositPayoutDelay = BountyDepositPayoutDelay;
    type BountyUpdatePeriod = BountyUpdatePeriod;
    type BountyCuratorDeposit = BountyCuratorDeposit;
    type BountyValueMinimum = BountyValueMinimum;
    type DataDepositPerByte = DataDepositPerByte;
    type MaximumReasonLength = MaximumReasonLength;
    type WeightInfo = pallet_bounties::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const BasicDeposit: Balance = 10 * DOCK;       // 258 bytes on-chain
    pub const FieldDeposit: Balance = 2 * DOCK;        // 66 bytes on-chain
    pub const SubAccountDeposit: Balance = 2 * DOCK;   // 53 bytes on-chain
    pub const MaxSubAccounts: u32 = 100;
    pub const MaxAdditionalFields: u32 = 100;
    pub const MaxRegistrars: u32 = 20;
}

impl pallet_identity::Config for Runtime {
    type Event = Event;
    type Currency = Balances;
    type BasicDeposit = BasicDeposit;
    type FieldDeposit = FieldDeposit;
    type SubAccountDeposit = SubAccountDeposit;
    type MaxSubAccounts = MaxSubAccounts;
    type MaxAdditionalFields = MaxAdditionalFields;
    type MaxRegistrars = MaxRegistrars;
    /// Slashed funds go to treasury
    type Slashed = Treasury;
    /// Root or >50% Council required to kill identity and slash
    type ForceOrigin = RootOrMoreThanHalfCouncil;
    /// Root or >50% Council required to add new registrar
    type RegistrarOrigin = RootOrMoreThanHalfCouncil;
    type WeightInfo = pallet_identity::weights::SubstrateWeight<Runtime>;
}

pallet_staking_reward_curve::build! {
    const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
        min_inflation: 0_050_000,
        max_inflation: 0_053_200,
        ideal_stake: 0_400_000,
        falloff: 0_050_000,
        max_piece_count: 40,
        test_precision: 0_005_000,
    );
}

parameter_types! {
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
    pub const RewardDecayPct: Percent = Percent::from_percent(25);
    pub const TreasuryRewardsPct: Percent = Percent::from_percent(50);
}

impl staking_rewards::Config for Runtime {
    type Event = Event;
    /// Emission rewards decay by this % each year
    type RewardDecayPct = RewardDecayPct;
    /// Treasury gets this much % out of emission rewards for each era
    type TreasuryRewardsPct = TreasuryRewardsPct;
    /// NPoS reward curve
    type RewardCurve = RewardCurve;
}

pub struct FindAuthorTruncated<F>(PhantomData<F>);
impl<F: FindAuthor<u32>> FindAuthor<H160> for FindAuthorTruncated<F> {
    fn find_author<'a, I>(digests: I) -> Option<H160>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        if let Some(author_index) = F::find_author(digests) {
            let authority_id = Babe::authorities()[author_index as usize].clone();
            return Some(H160::from_slice(&authority_id.0.to_raw_vec()[4..24]));
        }
        None
    }
}

impl pallet_ethereum::Config for Runtime {
    type Event = Event;
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
    type OnChargeTransaction = EVMCurrencyAdapter<Balances, DealWithFees>;

    type BlockGasLimit = BlockGasLimit;
    type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping;
    type FindAuthor = FindAuthorTruncated<Babe>;

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

parameter_types! {
    /// Price of Dock/USD pair as 10th of cent. Value of 10 means 1 cent
    pub const MinDockFiatRate: u32 = 10;
}

impl fiat_filter::Config for Runtime {
    type Call = Call;
    type PriceProvider = price_feed::Module<Runtime>;
    type Currency = balances::Module<Runtime>;
    type MinDockFiatRate = MinDockFiatRate;
}

pub struct BaseFilter;
impl Filter<Call> for BaseFilter {
    fn filter(call: &Call) -> bool {
        match call {
            // Disable fiat_filter for now
            Call::FiatFilterModule(_) => false,
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
        Timestamp: timestamp::{Module, Call, Storage, Inherent},
        Balances: balances::{Module, Call, Storage, Config<T>, Event<T>},
        Session: pallet_session::{Module, Call, Storage, Event, Config<T>},
        PoAModule: poa::{Module, Call, Storage, Config<T>},
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
        Attest: attest::{Module, Call, Storage},
        Democracy: pallet_democracy::{Module, Call, Storage, Event<T>},
        Council: pallet_collective::<Instance1>::{Module, Call, Storage, Origin<T>, Event<T>, Config<T>},
        TechnicalCommittee: pallet_collective::<Instance2>::{Module, Call, Storage, Origin<T>, Event<T>, Config<T>},
        TechnicalCommitteeMembership: pallet_membership::<Instance1>::{Module, Call, Storage, Event<T>, Config<T>},
        Scheduler: pallet_scheduler::{Module, Call, Storage, Event<T>},
        Ethereum: pallet_ethereum::{Module, Call, Storage, Event, Config, ValidateUnsigned},
        EVM: pallet_evm::{Module, Config, Call, Storage, Event<T>},
        PriceFeedModule: price_feed::{Module, Call, Storage, Event},
        FiatFilterModule: fiat_filter::{Module, Call},
        AuthorityDiscovery: pallet_authority_discovery::{Module, Call, Config},
        Historical: pallet_session_historical::{Module},
        ImOnline: pallet_im_online::{Module, Call, Storage, Event<T>, ValidateUnsigned, Config<T>},
        Babe: pallet_babe::{Module, Call, Storage, Config, ValidateUnsigned},
        Staking: pallet_staking::{Module, Call, Config<T>, Storage, Event<T>, ValidateUnsigned},
        ElectionProviderMultiPhase: pallet_election_provider_multi_phase::{Module, Call, Storage, Event<T>, ValidateUnsigned},
        Offences: pallet_offences::{Module, Call, Storage, Event},
        Treasury: pallet_treasury::{Module, Call, Storage, Config, Event<T>},
        Bounties: pallet_bounties::{Module, Call, Storage, Event<T>},
        StakingRewards: staking_rewards::{Module, Call, Storage, Event<T>},
        Elections: pallet_elections_phragmen::{Module, Call, Storage, Event<T>, Config<T>},
        Tips: pallet_tips::{Module, Call, Storage, Event<T>},
        Identity: pallet_identity::{Module, Call, Storage, Event<T>},
        BBSPlus: bbs_plus::{Module, Call, Storage, Event},
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
            pallet_babe::RandomnessFromOneEpochAgo::<Runtime>::random_seed().0
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
            equivocation_proof: fg_primitives::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;

            Grandpa::submit_unsigned_equivocation_report(
                equivocation_proof,
                key_owner_proof,
            )
        }

        fn generate_key_ownership_proof(
            _set_id: fg_primitives::SetId,
            authority_id: GrandpaId,
        ) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
            Historical::prove((fg_primitives::KEY_TYPE, authority_id))
                .map(|p| p.encode())
                .map(fg_primitives::OpaqueKeyOwnershipProof::new)
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
            <pallet_evm::Module<Runtime>>::find_author()
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

        fn extrinsic_filter(
            xts: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<EthereumTransaction> {
            xts.into_iter().filter_map(|xt| match xt.function {
                Call::Ethereum(transact(t)) => Some(t),
                _ => None
            }).collect::<Vec<EthereumTransaction>>()
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

    impl staking_rewards::runtime_api::StakingRewardsApi<Block, Balance> for Runtime {
        fn yearly_emission(total_staked: Balance, total_issuance: Balance) -> Balance {
            StakingRewards::yearly_emission(total_staked, total_issuance)
        }

        fn max_yearly_emission() -> Balance {
            StakingRewards::max_yearly_emission()
        }
    }

    impl core_mods::runtime_api::CoreModsApi<Block> for Runtime {
        fn bbs_plus_params(id: bbs_plus::ParametersStorageKey) -> Option<bbs_plus::BBSPlusParameters> {
            BBSPlus::get_params(id.0, id.1)
        }

        fn bbs_plus_public_key_with_params(id: bbs_plus::PublicKeyStorageKey) -> Option<bbs_plus::PublicKeyWithParams> {
            BBSPlus::get_public_key_with_params(&id)
        }

        fn bbs_plus_params_by_did(did: did::Did) -> BTreeMap<u32, bbs_plus::BBSPlusParameters> {
            BBSPlus::get_params_by_did(&did)
        }

        fn bbs_plus_public_keys_by_did(did: did::Did) -> BTreeMap<u32, bbs_plus::PublicKeyWithParams> {
            BBSPlus::get_public_key_by_did(&did)
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
            use pallet_session_benchmarking::Module as SessionBench;
            use pallet_offences_benchmarking::Module as OffencesBench;
            use frame_system_benchmarking::Module as SystemBench;

            impl pallet_session_benchmarking::Config for Runtime {}
            impl pallet_offences_benchmarking::Config for Runtime {}
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

            add_benchmark!(params, batches, pallet_babe, Babe);
            add_benchmark!(params, batches, pallet_election_provider_multi_phase, ElectionProviderMultiPhase);
            add_benchmark!(params, batches, pallet_grandpa, Grandpa);
            add_benchmark!(params, batches, pallet_im_online, ImOnline);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_system::offchain::CreateSignedTransaction;
    use sp_core::crypto::AccountId32;
    use std::str::FromStr;

    #[test]
    fn validate_transaction_submitter_bounds() {
        fn is_submit_signed_transaction<T>()
        where
            T: CreateSignedTransaction<Call>,
        {
        }

        is_submit_signed_transaction::<Runtime>();
    }

    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Runtime>()
            .unwrap()
            .into()
    }

    #[test]
    fn deal_with_fees() {
        // Check that `DealWithFees` works as intended
        new_test_ext().execute_with(|| {
            let treasury_account = Treasury::account_id();

            let treasury_balance1 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert_eq!(treasury_balance1, 0);

            let ed = ExistentialDeposit::get();
            let amount1 = 1000;
            assert!(amount1 > ed);
            DealWithFees::on_unbalanced(NegativeImbalance::new(amount1));
            let treasury_balance2 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert_eq!(treasury_balance2, 500);

            let amount2 = 6000;
            let amount3 = 4000;
            assert!((amount2 + amount3) > ed);

            DealWithFees::on_unbalanceds(
                Some(NegativeImbalance::new(amount2))
                    .into_iter()
                    .chain(Some(NegativeImbalance::new(amount3))),
            );
            let treasury_balance3 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert_eq!(treasury_balance3, 5500);
        })
    }

    #[test]
    fn evm_fees_are_received() {
        // Check that fees charged by EVM are received by treasury
        new_test_ext().execute_with(|| {
            let evm_addr = H160::from_str("0100000000000000000000000000000000000000").unwrap(); // Hex for value 1
            let addr = AccountId32::new([
                180, 11, 49, 203, 236, 115, 188, 178, 72, 85, 227, 29, 52, 227, 100, 236, 220, 72,
                200, 30, 69, 13, 32, 68, 73, 174, 159, 113, 36, 62, 136, 8,
            ]); // Corresponds to above `evm_addr` according to `TestAddressMapping`

            let evm_config = <Runtime as pallet_evm::Config>::config();

            let initial_bal = 1000000000;
            let gas_price = GasPrice::min_gas_price();
            let _ = <Balances as Currency<AccountId>>::deposit_creating(&addr, initial_bal);

            let treasury_account = Treasury::account_id();
            let treasury_balance1 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);

            // Using arbitrary bytecode as i only need to check fees. This arbitrary code will consume max gas
            <Runtime as pallet_evm::Config>::Runner::create(
                evm_addr,
                hex::decode("608060405234801561001057600080fd").unwrap(),
                U256::zero(),
                1000,
                Some(gas_price),
                Some(U256::zero()),
                evm_config,
            )
            .unwrap();

            // Txn fees is received by the module
            let treasury_balance2 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert!(treasury_balance2 > treasury_balance1);

            // Using arbitrary bytecode as i only need to check fees. This arbitrary code will consume max gas
            <Runtime as pallet_evm::Config>::Runner::create(
                evm_addr,
                hex::decode("608060405234801561001057600080fd1010ff25").unwrap(),
                U256::zero(),
                1000,
                Some(gas_price),
                Some(U256::zero()),
                evm_config,
            )
            .unwrap();

            let treasury_balance3 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert!(treasury_balance3 > treasury_balance2);
        });
    }
}
