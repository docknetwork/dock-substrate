//! Dock blockchain runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

#[cfg(not(feature = "std"))]
mod wasm_handlers {
    #[panic_handler]
    #[no_mangle]
    pub fn panic(info: &core::panic::PanicInfo) -> ! {
        let message = sp_std::alloc::format!("{}", info);
        log::error!("{}", message);
        ::core::arch::wasm32::unreachable();
    }

    #[alloc_error_handler]
    pub fn oom(_: core::alloc::Layout) -> ! {
        log::error!("Runtime memory exhausted. Aborting");
        ::core::arch::wasm32::unreachable();
    }
}

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

pub use dock_core::{
    accumulator, anchor, attest, blob, common, did, master,
    offchain_signatures::{self, BBSPlusPublicKey, OffchainPublicKey, PSPublicKey},
    revoke, status_list_credential, trust_registry,
};
use dock_price_feed::{CurrencySymbolPair, PriceProvider, PriceRecord};
pub mod precompiles;
pub mod weight_to_fee;

pub use dock_poa;
pub use dock_price_feed;
pub use dock_token_migration;

use sp_core::crypto::ByteArray;

use codec::{Decode, Encode};
use dock_core::util::IncId;
use dock_staking_rewards::DurationInEras;
use frame_election_provider_support::{onchain, SequentialPhragmen};
use frame_support::{
    construct_runtime, parameter_types,
    traits::*,
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_PER_SECOND},
        ConstantMultiplier, DispatchClass, DispatchInfo, Weight,
    },
    ConsensusEngineId, PalletId,
};
use frame_system::{
    self as system,
    limits::{BlockLength, BlockWeights},
    EnsureRoot,
};
use grandpa::{fg_primitives, AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use pallet_democracy::DepositLockConfig;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_session::historical as pallet_session_historical;
use pallet_sudo as sudo;
use scale_info::prelude::string::String;
use sp_api::impl_runtime_apis;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, H160, H256, U256};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{
        AccountIdLookup, BlakeTwo256, Block as BlockT, CheckedConversion, ConvertInto,
        Dispatchable, Extrinsic, IdentifyAccount, Keccak256, NumberFor, OpaqueKeys,
        PostDispatchInfoOf, StaticLookup, UniqueSaturatedInto, Verify,
    },
    transaction_validity::{
        TransactionPriority, TransactionSource, TransactionValidity, TransactionValidityError,
    },
    ApplyExtrinsicResult, DispatchResult, FixedPointNumber, MultiSignature, Perbill, Percent,
    Permill, Perquintill, SaturatedConversion,
};
use sp_std::collections::{btree_map::BTreeMap, btree_set::BTreeSet};
use transaction_payment::{CurrencyAdapter, Multiplier, TargetedFeeAdjustment};

use evm::Config as EvmConfig;
use fp_rpc::TransactionStatus;
use pallet_ethereum::{Call::transact, Transaction as EthereumTransaction};
use pallet_evm::{
    Account as EVMAccount, EVMCurrencyAdapter, EnsureAddressTruncated, FeeCalculator,
    HashedAddressMapping, Runner,
};

use crate::weight_to_fee::TxnFee;
#[cfg(any(feature = "std", test))]
pub use balances::Call as BalancesCall;
#[cfg(any(feature = "std", test))]
pub use frame_system::Call as SystemCall;
pub use pallet_election_provider_multi_phase::Call as EPMCall;
#[cfg(feature = "std")]
pub use pallet_staking::StakerStatus;
use precompiles::FrontierPrecompiles;
use sp_runtime::curve::PiecewiseLinear;
use sp_std::{convert::TryFrom, marker::PhantomData, prelude::*};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

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
        pub grandpa: GrandpaFinality,
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
    state_version: 0,
    #[cfg(feature = "mainnet")]
    spec_name: create_runtime_str!("dock-pos-main-runtime"),
    #[cfg(feature = "testnet")]
    spec_name: create_runtime_str!("dock-pos-test-runtime"),
    #[cfg(feature = "devnet")]
    spec_name: create_runtime_str!("dock-pos-devnet-runtime"),
    #[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
    spec_name: create_runtime_str!("dock-pos-dev-runtime"),
    impl_name: create_runtime_str!("Dock"),
    authoring_version: 1,
    spec_version: 66,
    impl_version: 2,
    transaction_version: 2,
    apis: RUNTIME_API_VERSIONS,
};

/// `fastblock` reduces the block time for faster testing. It isn't recommended for production.
/// Also build the node in release mode to support small block times (< 1 sec)
/// TODO: Support instant seal
#[cfg(feature = "fastblock")]
pub const MILLISECS_PER_BLOCK: u64 = 500;

#[cfg(not(feature = "fastblock"))]
pub const MILLISECS_PER_BLOCK: u64 = 3000;

pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time is measured by number of blocks.
pub const MINUTE: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOUR: BlockNumber = 60 * MINUTE;
pub const DAY: BlockNumber = 24 * HOUR;
pub const WEEK: BlockNumber = 7 * DAY;

// The modules `small_durations` is used to generate runtimes with small duration events like epochs, eras,
// bonding durations, etc for testing purposes. They should NOT be used in production.
#[allow(dead_code)]
mod small_durations {
    use super::{BlockNumber, MINUTE, WEEK};

    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 2 * MINUTE;
    pub const EPOCH_DURATION_IN_SLOTS: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 3;
    /// Bonding duration is in number of era
    pub const BONDING_DURATION: u32 = 24 * 8;
    pub const SLASH_DEFER_DURATION: u32 = 24 * 2; // 1/4 the bonding duration.
    /// Specifies the number of blocks for which the equivocation is valid.
    pub const REPORT_LONGEVITY: u64 =
        BONDING_DURATION as u64 * SESSIONS_PER_ERA as u64 * EPOCH_DURATION_IN_SLOTS;
    /// The number of blocks before the end of the era from which election submissions are allowed. Used for validator elections.
    pub const ELECTION_LOOKAHEAD: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;

    /// How long each seat is kept for elections. Used for gov.
    pub const TERM_DURATION: BlockNumber = WEEK;
    /// The time-out for council motions.
    pub const COUNCIL_MOTION_DURATION: BlockNumber = 10 * MINUTE;
    /// The time-out for technical committee motions.
    pub const TECHNICAL_MOTION_DURATION: BlockNumber = 10 * MINUTE;
    /// Delay after which an accepted proposal executes
    pub const ENACTMENT_PERIOD: BlockNumber = MINUTE;
    /// How often new public referrenda are launched
    pub const LAUNCH_PERIOD: BlockNumber = 15 * MINUTE;
    pub const VOTING_PERIOD: BlockNumber = 10 * MINUTE;
    pub const FAST_TRACK_VOTING_PERIOD: BlockNumber = 2 * MINUTE;
    pub const COOLOFF_PERIOD: BlockNumber = 60 * MINUTE;

    /// Duration after which funds from treasury are spent for approved bounties
    pub const SPEND_PERIOD: BlockNumber = 15 * MINUTE;
    /// The delay period for which a bounty beneficiary need to wait before claim the payout.
    pub const BOUNTY_DEPOSIT_PAYOUT_DELAY: BlockNumber = MINUTE;
    /// The period for which a tip remains open after is has achieved threshold tippers.
    pub const TIP_COUNTDOWN: BlockNumber = MINUTE;
    /// Bounty duration in blocks.
    pub const BOUNTY_UPDATE_PERIOD: BlockNumber = 5 * MINUTE;
}

#[allow(dead_code)]
mod prod_durations {
    use super::{BlockNumber, DAY, HOUR, MINUTE, WEEK};

    pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 3 * HOUR;
    pub const EPOCH_DURATION_IN_SLOTS: u64 = EPOCH_DURATION_IN_BLOCKS as u64;

    pub const SESSIONS_PER_ERA: sp_staking::SessionIndex = 4; // 12 hours
    /// Bonding duration is in number of era
    pub const BONDING_DURATION: u32 = 2 * 7; // 7 days
    pub const SLASH_DEFER_DURATION: u32 = 7; // 1/2 the bonding duration.
    /// Specifies the number of blocks for which the equivocation is valid.
    pub const REPORT_LONGEVITY: u64 =
        BONDING_DURATION as u64 * SESSIONS_PER_ERA as u64 * EPOCH_DURATION_IN_SLOTS;
    /// The number of blocks before the end of the era from which election submissions are allowed. Used for validator elections.
    pub const ELECTION_LOOKAHEAD: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;

    /// How long each seat is kept for elections. Used for gov.
    pub const TERM_DURATION: BlockNumber = WEEK;
    /// The time-out for council motions.
    pub const COUNCIL_MOTION_DURATION: BlockNumber = WEEK;
    /// The time-out for technical committee motions.
    pub const TECHNICAL_MOTION_DURATION: BlockNumber = WEEK;
    /// Delay after which an accepted proposal executes
    pub const ENACTMENT_PERIOD: BlockNumber = 2 * DAY;
    /// How often new public referrenda are launched
    pub const LAUNCH_PERIOD: BlockNumber = 20 * DAY;
    pub const VOTING_PERIOD: BlockNumber = 15 * DAY;
    pub const FAST_TRACK_VOTING_PERIOD: BlockNumber = 3 * HOUR;
    pub const COOLOFF_PERIOD: BlockNumber = 28 * 24 * 60 * MINUTE;

    /// Duration after which funds from treasury are spent for approved bounties
    pub const SPEND_PERIOD: BlockNumber = DAY;
    /// The delay period for which a bounty beneficiary need to wait before claim the payout.
    pub const BOUNTY_DEPOSIT_PAYOUT_DELAY: BlockNumber = DAY;
    /// The period for which a tip remains open after is has achieved threshold tippers.
    pub const TIP_COUNTDOWN: BlockNumber = DAY;
    /// Bounty duration in blocks.
    pub const BOUNTY_UPDATE_PERIOD: BlockNumber = 14 * DAY;
}

#[cfg(not(feature = "small_durations"))]
use prod_durations::*;
#[cfg(feature = "small_durations")]
use small_durations::*;

/// Era duration should be less than or equal year
// Milliseconds per year for the Julian year (365.25 days).
#[allow(unused)]
pub const MILLISECONDS_PER_YEAR: u64 = 1000 * 3600 * 24 * 36525 / 100;
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

#[cfg(any(feature = "testnet", feature = "devnet"))]
parameter_types! {
    pub const SS58Prefix: u8 = 21;
}

#[cfg(feature = "mainnet")]
parameter_types! {
    pub const SS58Prefix: u8 = 22;
}

#[cfg(not(any(feature = "testnet", feature = "mainnet", feature = "devnet")))]
parameter_types! {
    pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Runtime {
    type MaxConsumers = ConstU32<16>;
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = Everything;
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
    type OnSetCode = ();
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
            transaction_payment::ChargeTransactionPayment::from(tip),
            dock_token_migration::OnlyMigrator::<Runtime>::new(),
        );
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = <Runtime as frame_system::Config>::Lookup::unlookup(account);
        let (call, extra, _) = raw_payload.deconstruct();
        Some((call, (address, signature, extra)))
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
    type MaxKeys = ConstU32<100>;
    type MaxPeerInHeartbeats = ConstU32<100>;
    type MaxPeerDataEncodingSize = ConstU32<100>;

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
    type DisabledValidators = ();
    type MaxAuthorities = ConstU32<100>;

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

pub struct U64CurrencyToVote;

impl CurrencyToVote<u64> for U64CurrencyToVote {
    fn to_vote(value: u64, _issuance: u64) -> u64 {
        value
    }

    fn to_currency(value: u128, _issuance: u64) -> u64 {
        value.saturated_into()
    }
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
    type System = Runtime;
    type Solver = SequentialPhragmen<AccountId, sp_runtime::Perbill>;
    type DataProvider = Staking;
    type WeightInfo = frame_election_provider_support::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub MaxNominations: u32 = <NposSolution16 as frame_election_provider_support::NposSolution>::LIMIT as u32;
}
pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
    type MaxValidators = ConstU32<100>;
    type MaxNominators = ConstU32<200>;
}

parameter_types! {
    pub const SessionsPerEra: sp_staking::SessionIndex = SESSIONS_PER_ERA;
    /// Bonding duration is in number of era
    pub const BondingDuration: u32 = BONDING_DURATION;
    pub const SlashDeferDuration: u32 = SLASH_DEFER_DURATION;
    /// A validator will only have 256 nominators, so max (rewarded) nominators is 256*50 = 12800.
    /// This number is smaller than current token holders (20K) but not all holder participate. Keeping
    /// it small to batch payout extrinsics
    pub const MaxNominatorRewardedPerValidator: u32 = 256;
    pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
}

impl pallet_staking::Config for Runtime {
    type CurrencyBalance = u64;
    type MaxNominations = MaxNominations;
    type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Self>;
    type MaxUnlockingChunks = ();
    type OnStakerSlash = ();
    type BenchmarkingConfig = StakingBenchmarkingConfig;

    type GenesisElectionProvider = onchain::UnboundedExecution<OnChainSeqPhragmen>;
    type OffendingValidatorsThreshold = OffendingValidatorsThreshold;

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
    type SlashCancelOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 4>,
    >;
    type SessionInterface = Self;
    type EraPayout = StakingRewards;
    type NextNewSession = Session;
    type MaxNominatorRewardedPerValidator = MaxNominatorRewardedPerValidator;
    type ElectionProvider = ElectionProviderMultiPhase;
    type WeightInfo = pallet_staking::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    // miner configs
    pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
    pub MinerMaxWeight: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
}

/// Denotes when the system should decrease/increase the base fee based on how much weight was used by the last block.
/// `target` is the ideal congestion of the network where the base fee should remain unchanged.
/// Under normal circumstances the `target` should be 50%.
/// If we go below the `target`, the base fee is linearly decreased by the Elasticity delta of lower`~`target.
/// If we go above the `target`, the base fee is linearly increased by the Elasticity delta of upper`~`target.
/// The base fee is fully increased (default 12.5%) if the block is upper full (default 100%).
/// The base fee is fully decreased (default 12.5%) if the block is lower empty (default 0%).
pub struct BaseFeeThreshold;
impl pallet_base_fee::BaseFeeThreshold for BaseFeeThreshold {
    fn lower() -> Permill {
        Permill::zero()
    }
    fn ideal() -> Permill {
        Permill::from_parts(500_000)
    }
    fn upper() -> Permill {
        Permill::from_parts(1_000_000)
    }
}

parameter_types! {
    pub DefaultElasticity: Permill = Permill::from_parts(125_000);
}

impl pallet_base_fee::Config for Runtime {
    type DefaultBaseFeePerGas = ();

    type Event = Event;
    type Threshold = BaseFeeThreshold;
    type DefaultElasticity = DefaultElasticity;
}

parameter_types! {
    pub MaxElectingVoters: u32 = 4_000;
}

frame_election_provider_support::generate_solution_type!(
    #[compact]
    pub struct NposSolution16::<
        VoterIndex = u32,
        TargetIndex = u16,
        Accuracy = sp_runtime::PerU16,
        MaxVoters = MaxElectingVoters,
    >(16)
);

/// The numbers configured here could always be more than the the maximum limits of staking pallet
/// to ensure election snapshot will not run out of memory. For now, we set them to smaller values
/// since the staking is bounded and the weight pipeline takes hours for this single pallet.
pub struct BenchmarkConfig;
impl pallet_election_provider_multi_phase::BenchmarkingConfig for BenchmarkConfig {
    const VOTERS: [u32; 2] = [1000, 2000];
    const TARGETS: [u32; 2] = [500, 1000];
    const ACTIVE_VOTERS: [u32; 2] = [500, 800];
    const DESIRED_TARGETS: [u32; 2] = [25, 100];
    const SNAPSHOT_MAXIMUM_VOTERS: u32 = 1000;
    const MINER_MAXIMUM_VOTERS: u32 = 1000;
    const MAXIMUM_TARGETS: u32 = 75;
}

parameter_types! {
    pub const SignedRewardBase: Balance = DOCK;
    pub const SignedDepositBase: Balance = 500 * DOCK;
    pub const SignedDepositByte: Balance = DOCK / 100;
    pub const OffchainRepeat: BlockNumber = 5;

    pub BetterUnsignedThreshold: Perbill = Perbill::from_rational(5u32, 10_000);

    // phase durations. 1/4 of the last session for each.
    pub const SignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const UnsignedPhase: u32 = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const MaxElectableTargets: u16 = u16::MAX;
}

impl pallet_election_provider_multi_phase::Config for Runtime {
    type BetterSignedThreshold = ();
    type BetterUnsignedThreshold = BetterUnsignedThreshold;
    type MinerConfig = Self;
    type SignedMaxRefunds = ConstU32<3>;
    type MaxElectingVoters = MaxElectingVoters;
    type MaxElectableTargets = MaxElectableTargets;
    type GovernanceFallback = onchain::UnboundedExecution<OnChainSeqPhragmen>;

    type EstimateCallFee = TransactionPayment;
    type OffchainRepeat = OffchainRepeat;
    type SignedMaxSubmissions = ConstU32<10>;
    type SignedMaxWeight = MinerMaxWeight;
    type SignedRewardBase = SignedRewardBase;
    type SignedDepositBase = SignedDepositBase;
    type SignedDepositByte = SignedDepositByte;
    type SignedDepositWeight = ();
    type SlashHandler = ();
    type RewardHandler = ();
    type Solver = SequentialPhragmen<
        AccountId,
        pallet_election_provider_multi_phase::SolutionAccuracyOf<Self>,
    >;
    type ForceOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
    >;

    type Event = Event;
    type Currency = Balances;
    type SignedPhase = SignedPhase;
    type UnsignedPhase = UnsignedPhase;
    type MinerTxPriority = MultiPhaseUnsignedPriority;
    type DataProvider = Staking;
    type Fallback = pallet_election_provider_multi_phase::NoFallback<Self>;
    type WeightInfo = pallet_election_provider_multi_phase::weights::SubstrateWeight<Self>;
    type BenchmarkingConfig = BenchmarkConfig;
}

impl pallet_authority_discovery::Config for Runtime {
    type MaxAuthorities = ConstU32<100>;
}

impl grandpa::Config for Runtime {
    type MaxAuthorities = ConstU32<100>;

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
}

impl balances::Config for Runtime {
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];

    /// The type for recording an account's balance.
    type Balance = Balance;
    type DustRemoval = ();
    /// The ubiquitous event type.
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = balances::weights::SubstrateWeight<Runtime>;
    type MaxLocks = ConstU32<50>;
}

parameter_types! {
    /// .0001 token
    pub const TransactionByteFee: Balance = DOCK / 10000;
    pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(25);
    pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(1, 100_000);
    pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 1_000_000_000u128);
}

impl transaction_payment::Config for Runtime {
    type Event = Event;
    type OperationalFeeMultiplier = ConstU8<5>;
    type LengthToFee = ConstantMultiplier<u64, TransactionByteFee>;
    type OnChargeTransaction = CurrencyAdapter<Balances, DealWithFees>;
    type WeightToFee = TxnFee<Balance>;
    /// This would be useless after enabling fiat filter
    type FeeMultiplierUpdate =
        TargetedFeeAdjustment<Self, TargetBlockFullness, AdjustmentVariable, MinimumMultiplier>;
}

impl did::Config for Runtime {
    type Event = Event;
    type OnDidRemoval = OffchainSignatures;
}

impl trust_registry::Config for Runtime {
    type Event = Event;
}

impl revoke::Config for Runtime {
    type Event = Event;
}

impl common::Limits for Runtime {
    type MaxPolicyControllers = ConstU32<15>;

    type MaxDidDocRefSize = ConstU32<1024>;
    type MaxDidServiceEndpointIdSize = ConstU32<1024>;
    type MaxDidServiceEndpointOriginSize = ConstU32<1025>;
    type MaxDidServiceEndpointOrigins = ConstU32<64>;

    type MinStatusListCredentialSize = ConstU32<500>;
    type MaxStatusListCredentialSize = ConstU32<40_000>;

    type MaxPSPublicKeySize = ConstU32<65536>;
    type MaxBBSPublicKeySize = ConstU32<256>;
    type MaxBBSPlusPublicKeySize = ConstU32<256>;
    type MaxBBDT16PublicKeySize = ConstU32<256>;

    /// 128 bytes, for large labels, hash of a label can be used
    type MaxOffchainParamsLabelSize = ConstU32<128>;
    /// 16KB
    type MaxOffchainParamsBytesSize = ConstU32<65_536>;

    /// 128 bytes, for large labels, hash of a label can be used
    type MaxAccumulatorLabelSize = ConstU32<128>;
    type MaxAccumulatorParamsSize = ConstU32<512>;
    type MaxAccumulatorPublicKeySize = ConstU32<256>;
    type MaxAccumulatorAccumulatedSize = ConstU32<128>;

    /// 8KB
    type MaxBlobSize = ConstU32<8192>;
    /// 1KB
    type MaxIriSize = ConstU32<1024>;

    type MaxMasterMembers = ConstU32<25>;

    type MaxIssuerPriceCurrencySymbolSize = ConstU32<10>;
    type MaxIssuersPerSchema = ConstU32<100>;
    type MaxVerifiersPerSchema = ConstU32<2_000>;
    type MaxIssuerPriceCurrencies = ConstU32<25>;
    type MaxTrustRegistryNameSize = ConstU32<50>;
    type MaxConvenerRegistries = ConstU32<1000>;
    type MaxDelegatedIssuers = ConstU32<10>;
    type MaxRegistriesPerIssuer = ConstU32<250>;
    type MaxRegistriesPerVerifier = ConstU32<250>;
    type MaxSchemasPerRegistry = ConstU32<1_000>;
    type MaxSchemasPerIssuer = ConstU32<1_000>;
    type MaxSchemasPerVerifier = ConstU32<1_000>;
    type MaxTrustRegistryGovFrameworkSize = ConstU32<1_000>;
    type MaxParticipantsPerRegistry = ConstU32<10_000>;

    type MaxRegistryParticipantOrgNameSize = ConstU32<100>;
    type MaxRegistryParticipantLogoSize = ConstU32<250>;
    type MaxRegistryParticipantDescriptionSize = ConstU32<500>;
}

impl status_list_credential::Config for Runtime {
    type Event = Event;
}

impl offchain_signatures::Config for Runtime {
    type Event = Event;
}

impl accumulator::Config for Runtime {
    type Event = Event;
}

impl blob::Config for Runtime {}

parameter_types! {
    pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(17);
}

impl pallet_session::Config for Runtime {
    type Event = Event;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ValidatorIdOf = pallet_staking::StashOf<Self>;
    type ShouldEndSession = Babe;
    type NextSessionRotation = Babe;
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = SessionKeys;
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
}

impl dock_poa::Config for Runtime {
    type Currency = balances::Pallet<Runtime>;
}

parameter_types! {
    /// Number of vesting milestones
    pub const VestingMilestones: u8 = 3;
    /// Vesting duration in number of blocks. Duration is 183 days and block time is 3 sec. (183 * 24 * 3600) / 3 = 5270400
    pub const VestingDuration: u32 = 5270400;

    pub const MaxVestingBonuses: u32 = 100;
    pub const MaxSwapBonuses: u32 = 100;
}

// `VestingMilestones` and `VestingDuration` must be > 0
const_assert!(VestingMilestones::get() > 0);
const_assert!(VestingDuration::get() > 0);

impl dock_token_migration::Config for Runtime {
    type Event = Event;
    type Currency = balances::Pallet<Runtime>;
    type BlockNumberToBalance = ConvertInto;
    type VestingMilestones = VestingMilestones;
    type VestingDuration = VestingDuration;
    type MaxVestingBonuses = MaxVestingBonuses;
    type MaxSwapBonuses = MaxSwapBonuses;
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
    type PalletsOrigin = OriginCaller;

    type Event = Event;
    type Call = Call;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

/// MMR helper types.
mod mmr {
    use super::Runtime;
    pub use pallet_mmr::primitives::*;

    pub type Hash = <Runtime as pallet_mmr::Config>::Hash;
}

type MmrHash = <Keccak256 as sp_runtime::traits::Hash>::Output;

/// Dummy Merkle Mountain Range pallet configuration.
impl pallet_mmr::Config for Runtime {
    const INDEXING_PREFIX: &'static [u8] = b"mmr";

    type Hashing = Keccak256;
    type Hash = MmrHash;
    type OnNewRoot = ();
    type WeightInfo = ();
    type LeafData = ();
}

impl master::Config for Runtime {
    type Event = Event;
    type Call = Call;
}

impl sudo::Config for Runtime {
    type Event = Event;
    type Call = Call;
}

impl anchor::Config for Runtime {
    type Event = Event;
}

impl attest::Config for Runtime {}

/// This origin indicates that either >50% (simple majority) of Council members approved some dispatch (through a proposal)
/// or the dispatch was done as `Root` (by sudo or master)
type RootOrMoreThanHalfCouncil = EitherOfDiverse<
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
>;

/// This origin indicates that either >=66.66% of Council members approved some dispatch (through a proposal)
/// or the dispatch was done as `Root` (by sudo or master)
type RootOrTwoThirdCouncil = EitherOfDiverse<
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 2, 3>,
>;

type CouncilMember = pallet_collective::EnsureMember<AccountId, CouncilCollective>;

const fn deposit(items: u32, bytes: u32) -> Balance {
    items as Balance * 15 * (DOCK / 100) + (bytes as Balance) * 6 * (DOCK / 100)
}

parameter_types! {
    pub const CandidacyBond: Balance = 20_000 * DOCK;
    // 1 storage item created, key size is 32 bytes, value size is 16+16.
    pub const VotingBondBase: Balance = deposit(1, 64);
    // additional data per vote is 32 bytes (account id).
    pub const VotingBondFactor: Balance = deposit(0, 32);
    pub const TermDuration: BlockNumber = TERM_DURATION;
    pub const DesiredMembers: u32 = 6;
    pub const DesiredRunnersUp: u32 = 3;
    pub const ElectionsPhragmenPalletId: LockIdentifier = *b"phrelect";
    pub const MaxVoters: u32 = 4 * 200;
    pub const MaxCandidates: u32 = 200;
    /// Require 3 days in blocks for each candidate to be allowed for the election.
    pub const CandidacyDelay: u32 = 86400;
}

// Make sure that there are no more than `MaxMembers` members elected via elections-phragmen.
const_assert!(DesiredMembers::get() <= CouncilMaxMembers::get());

impl pallet_elections_phragmen::Config for Runtime {
    type MaxCandidates = MaxCandidates;
    type MaxVoters = MaxVoters;
    type CandidacyDelay = CandidacyDelay;
    type Event = Event;
    type PalletId = ElectionsPhragmenPalletId;
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
    type CandidateIdentityProvider = identity_provider::PalletIdentityAsIdentityProvider<Self>;
    type WeightInfo = pallet_elections_phragmen::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const CouncilMotionDuration: BlockNumber = COUNCIL_MOTION_DURATION;
    pub const CouncilMaxProposals: u32 = 100;
    pub const CouncilMaxMembers: u32 = 10;
    /// Proposal with lifetime less than 2 hours (in blocks) requires to be approved by all members.
    pub const ShortTimeProposal: u32 = 2400;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Runtime {
    type ShortTimeProposal = ShortTimeProposal;
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
    type MaxMembers = CouncilMaxMembers;
    type WeightInfo = ();

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
    pub const TechnicalMaxMembers: u32 = 10;
}

type TechnicalCollective = pallet_collective::Instance2;
impl pallet_collective::Config<TechnicalCollective> for Runtime {
    type ShortTimeProposal = ShortTimeProposal;
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
    // Retry a scheduled item every 20 blocks (1 minute) until the preimage exists.
    pub const NoPreimagePostponement: Option<u32> = Some(20);
}

impl pallet_scheduler::Config for Runtime {
    type OriginPrivilegeCmp = EqualPrivilegeOnly;
    type PreimageProvider = ();
    type NoPreimagePostponement = NoPreimagePostponement;

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
    /// 0.02 token
    pub const PreimageByteDeposit: Balance = DOCK / 50;
    pub const MaxVotes: u32 = 100;
    pub const MaxProposals: u32 = 100;
    pub const InstantAllowed: bool = true;
    pub const CooloffPeriod: BlockNumber = COOLOFF_PERIOD;
}

parameter_types! {
    /// A limit for off-chain phragmen unsigned solution length.
    ///
    /// We allow up to 90% of the block's size to be consumed by the solution.
    pub OffchainSolutionLengthLimit: u32 = Perbill::from_rational(90_u32, 100) *
        *RuntimeBlockLength::get()
        .max
        .get(DispatchClass::Normal);
    /// A limit for off-chain phragmen unsigned solution weight.
    ///
    /// We allow up to max extrinisic weight be consumed by the solution.
    pub OffchainSolutionWeightLimit: Weight = RuntimeBlockWeights::get()
        .get(DispatchClass::Normal)
        .max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
        .saturating_sub(BlockExecutionWeight::get());
}

impl pallet_election_provider_multi_phase::MinerConfig for Runtime {
    type AccountId = AccountId;
    type MaxLength = OffchainSolutionLengthLimit;
    type MaxWeight = OffchainSolutionWeightLimit;
    type Solution = NposSolution16;
    type MaxVotesPerVoter = <
		<Self as pallet_election_provider_multi_phase::Config>::DataProvider
		as
		frame_election_provider_support::ElectionDataProvider
	>::MaxVotesPerVoter;

    // The unsigned submissions have to respect the weight of the submit_unsigned call, thus their
    // weight estimate function is wired to this call's weight.
    fn solution_weight(v: u32, t: u32, a: u32, d: u32) -> Weight {
        <
			<Self as pallet_election_provider_multi_phase::Config>::WeightInfo
			as
			pallet_election_provider_multi_phase::WeightInfo
		>::submit_unsigned(v, t, a, d)
    }
}

/// Require 10K DOCK tokens to participate in the voting to immediately pay back provider's deposit.
/// Otherwise, lock the deposit for 90 days.
const PREIMAGE_DEPOSIT_LOCK_STRATEGY: DepositLockConfig<Runtime> =
    DepositLockConfig::new(DAY, 90, 10_000 * DOCK);

parameter_types! {
    pub const DepositLockStrategy: DepositLockConfig<Runtime> = PREIMAGE_DEPOSIT_LOCK_STRATEGY;
}

impl pallet_democracy::Config for Runtime {
    type VoteLockingPeriod = EnactmentPeriod; // Same as EnactmentPeriod
    type Proposal = Call;
    type Event = Event;
    type Currency = Balances;
    type EnactmentPeriod = EnactmentPeriod;
    type DepositLockStrategy = DepositLockStrategy;
    type LaunchPeriod = LaunchPeriod;
    type VotingPeriod = VotingPeriod;
    type CooloffPeriod = CooloffPeriod;
    type MinimumDeposit = MinimumDeposit;
    /// A straight majority of the council can decide what their next motion is.
    type ExternalOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 2>,
    >;
    /// A super-majority can have the next scheduled referendum be a straight majority-carries vote.
    type ExternalMajorityOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 4>,
    >;
    /// A unanimous council can have the next scheduled referendum be a straight default-carries
    /// (NTB) vote.
    type ExternalDefaultOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 1>,
    >;
    /// Two thirds of the technical committee can have an ExternalMajority/ExternalDefault vote
    /// be tabled immediately and with a shorter voting/enactment period.
    type FastTrackOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 2, 3>,
    >;
    /// Root or the Technical committee unanimously agreeing can make a Council proposal a referendum instantly.
    type InstantOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 1, 1>,
    >;
    type InstantAllowed = InstantAllowed;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    /// To cancel a proposal which has been passed, 2/3 of the council must agree to it.
    type CancellationOrigin = RootOrTwoThirdCouncil;
    // To cancel a proposal before it has been passed, the technical committee must be unanimous or
    // Root must agree.
    type CancelProposalOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, TechnicalCollective, 1, 1>,
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
    pub const ProposalBondMinimum: Balance = DOCK;
    pub const SpendPeriod: BlockNumber = SPEND_PERIOD;
    /// We are fixed supply token, we don't burn any tokens
    pub const Burn: Permill = Permill::from_percent(0);
    pub const DataDepositPerByte: Balance = DOCK / 100;
    pub const BountyDepositBase: Balance = DOCK;
    pub const BountyCuratorDepositMin: Balance = DOCK / 2;
    pub const BountyCuratorDepositMax: Balance = 250 * DOCK;
    pub const BountyDepositPayoutDelay: BlockNumber = BOUNTY_DEPOSIT_PAYOUT_DELAY;
    pub const BountyCuratorDepositMultiplier: Permill = Permill::from_percent(50);
    pub const BountyValueMinimum: Balance = 5 * DOCK;
    pub const TipCountdown: BlockNumber = TIP_COUNTDOWN;
    pub const TipFindersFee: Percent = Percent::from_percent(20);
    pub const TipReportDepositBase: Balance = DOCK;
    /// Matches treasury account created during PoA.
    pub const TreasuryPalletId: PalletId = PalletId(*b"Treasury");
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
        if let Some(author) = Authorship::author() {
            Balances::resolve_creating(&author, split.1);
        }
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

parameter_types! {
    pub const MaxApprovals: u32 = 100;
}

impl pallet_treasury::Config for Runtime {
    type MaxApprovals = MaxApprovals;
    type ProposalBondMaximum = ();
    type SpendOrigin = frame_support::traits::NeverEnsureOrigin<u64>;

    type PalletId = TreasuryPalletId;
    type Currency = Balances;
    type ApproveOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 3, 5>,
    >;
    type RejectOrigin = EitherOfDiverse<
        EnsureRoot<AccountId>,
        pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
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
    type CuratorDepositMultiplier = BountyCuratorDepositMultiplier;
    type CuratorDepositMax = BountyCuratorDepositMax;
    type CuratorDepositMin = BountyCuratorDepositMin;
    type ChildBountyManager = ();

    type Event = Event;
    type BountyDepositBase = BountyDepositBase;
    type BountyDepositPayoutDelay = BountyDepositPayoutDelay;
    type BountyUpdatePeriod = BountyUpdatePeriod;
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

mod identity_provider {
    use super::*;
    use utils::{Identity, IdentityProvider};

    /// A wrapper that implements `IdentityProvider`/`IdentitySetter` traits for the `Identity` pallet.
    pub struct PalletIdentityAsIdentityProvider<T: pallet_identity::Config>(
        pub pallet_identity::Pallet<T>,
    );

    /// Registration for the identity.
    #[derive(Clone, Debug)]
    pub struct RegisteredIdentity<T: pallet_identity::Config>(pub Registration<T>);
    dock_core::impl_wrapper!(RegisteredIdentity<T> where T: pallet_identity::Config => (Registration<T>));

    /// Identity information.
    #[derive(Clone, Debug)]
    pub struct IdentityInfo<T: pallet_identity::Config>(
        pub pallet_identity::IdentityInfo<<T as pallet_identity::Config>::MaxAdditionalFields>,
    );
    dock_core::impl_wrapper!(IdentityInfo<T> where T: pallet_identity::Config => (pallet_identity::IdentityInfo<<T as pallet_identity::Config>::MaxAdditionalFields>));

    impl<T: pallet_identity::Config> Default for IdentityInfo<T> {
        fn default() -> Self {
            Self(pallet_identity::IdentityInfo {
                additional: Default::default(),
                display: Default::default(),
                legal: Default::default(),
                web: Default::default(),
                riot: Default::default(),
                email: Default::default(),
                pgp_fingerprint: Default::default(),
                image: Default::default(),
                twitter: Default::default(),
            })
        }
    }

    impl<T: pallet_identity::Config> Identity for RegisteredIdentity<T> {
        type Info = IdentityInfo<T>;
        type Justification = Option<(u32, pallet_identity::Judgement<BalanceOf<T>>)>;

        fn verified(&self) -> bool {
            use pallet_identity::Judgement::*;

            self.0
                .judgements
                .iter()
                .any(|(_idx, judjement)| matches!(judjement, KnownGood | Reasonable))
        }

        fn info(&self) -> Self::Info {
            IdentityInfo(self.0.info.clone())
        }

        fn verify(&mut self, justification: Self::Justification) -> DispatchResult {
            self.0
                .judgements
                .try_push(justification.unwrap_or((0, pallet_identity::Judgement::KnownGood)))
                .map_err(|_| pallet_identity::Error::<T>::TooManyRegistrars.into())
        }
    }

    type BalanceOf<T> = <<T as pallet_identity::Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;
    type Registration<T> = pallet_identity::Registration<
        BalanceOf<T>,
        <T as pallet_identity::Config>::MaxRegistrars,
        <T as pallet_identity::Config>::MaxAdditionalFields,
    >;

    impl<T: pallet_identity::Config> IdentityProvider<T> for PalletIdentityAsIdentityProvider<T> {
        type Identity = RegisteredIdentity<T>;

        fn identity(who: &T::AccountId) -> Option<Self::Identity> {
            pallet_identity::Pallet::<T>::identity(who).map(RegisteredIdentity)
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    mod identity_setter {
        use super::*;
        use frame_support::storage_alias;
        use utils::IdentitySetter;

        #[storage_alias]
        type IdentityOf<T: pallet_identity::Config> = StorageMap<
            pallet_identity::Pallet<T>,
            frame_support::Twox64Concat,
            <T as frame_system::Config>::AccountId,
            Registration<T>,
            frame_support::pallet_prelude::OptionQuery,
        >;

        impl<T: pallet_identity::Config> IdentitySetter<T> for PalletIdentityAsIdentityProvider<T> {
            fn set_identity(
                account: T::AccountId,
                info: <Self::Identity as Identity>::Info,
            ) -> DispatchResult {
                IdentityOf::<T>::insert(
                    account,
                    pallet_identity::Registration {
                        judgements: Default::default(),
                        deposit: Default::default(),
                        info: info.into(),
                    },
                );

                Ok(())
            }

            fn verify_identity(
                account: &T::AccountId,
                justification: <Self::Identity as Identity>::Justification,
            ) -> DispatchResult {
                IdentityOf::<T>::try_mutate(account, |identity_opt| {
                    let mut identity = identity_opt
                        .take()
                        .map(RegisteredIdentity::<T>)
                        .ok_or(pallet_identity::Error::<T>::NotFound)?;
                    identity.verify(justification)?;
                    identity_opt.replace(identity.into());

                    Ok(())
                })
            }

            fn remove_identity(account: &T::AccountId) -> DispatchResult {
                frame_support::ensure!(
                    IdentityOf::<T>::take(account).is_some(),
                    pallet_identity::Error::<T>::NoIdentity
                );

                Ok(())
            }
        }
    }
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

/// Pay high-rate rewards for 3 months (in eras) after the upgrade.
/// At the moment, we still have 18 remaining eras of enabled high-rate rewards.
const POST_UPGRADE_HIGH_RATE_DURATION: DurationInEras =
    DurationInEras::new_non_zero((81 * DAY / EPOCH_DURATION_IN_BLOCKS / SESSIONS_PER_ERA) as u16);

// 1 era lasts for 12h.
#[cfg(not(feature = "small_durations"))]
const_assert_eq!(POST_UPGRADE_HIGH_RATE_DURATION.0.get(), 81 * 2);

parameter_types! {
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
    pub const HighRateRewardDecayPct: Percent = Percent::from_percent(50);
    pub const LowRateRewardDecayPct: Percent = Percent::from_percent(25);
    pub const TreasuryRewardsPct: Percent = Percent::from_percent(50);
    pub const PostUpgradeHighRateDuration: Option<DurationInEras> = Some(POST_UPGRADE_HIGH_RATE_DURATION);
}

impl dock_staking_rewards::Config for Runtime {
    type Event = Event;
    type PostUpgradeHighRateDuration = PostUpgradeHighRateDuration;
    /// High-rate emission rewards decay by this % each year
    type HighRateRewardDecayPct = HighRateRewardDecayPct;
    /// Low-rate emission rewards decay by this % each year
    type LowRateRewardDecayPct = LowRateRewardDecayPct;
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
    type StateRoot = pallet_ethereum::IntermediateStateRoot<Self>;
}

parameter_types! {
    /// Keeping 22 as its the ss58 prefix of mainnet
    pub const DockChainId: u64 = 22;
    pub BlockGasLimit: U256 = U256::from(u32::max_value());
    pub const ByteReadWeight: Weight = Weight::from_ref_time(100);
}

/// Fixed gas price.
/// Gas price is always 50 mirco-token (0.00005 token) per gas.
///
/// Considering the cost of following ops assuming 1 gas = 1 mirco-token.
/// ERC token deploy - 891,328 gas = 0.8 tokens
/// ERC token send - 28,500 gas = 0.0285 tokens
/// Link token deploy - 951,000 gas = 0.951 tokens
/// Link token send - 47,066 gas = 0.047 tokens
/// AccessControlledAggregator - 4,425,900 gas = 4.425 tokens
/// AggregatorProxy - 1,665,600 gas = 1.665 tokens
/// Aggregator submit - 209,500 gas = 0.209 tokens
/// Aggregator add access - 45,200 gas = 0.045 tokens
/// Add oracle - 135,600 gas = 0.135 tokens
/// EVM transfer DOCK token - 21,000 gas = 0.021 tokens
///
/// The above is much lower than we would like. At this price it seems better to use EVM for token transfers.
pub struct GasPrice;
impl FeeCalculator for GasPrice {
    fn min_gas_price() -> (U256, Weight) {
        (50.into(), Weight::zero())
    }
}

pub const WEIGHT_PER_GAS: u64 = 50;

pub struct GasWeightMap;
impl pallet_evm::GasWeightMapping for GasWeightMap {
    fn gas_to_weight(gas: u64) -> Weight {
        Weight::from_ref_time(gas.saturating_mul(WEIGHT_PER_GAS))
    }
    fn weight_to_gas(weight: Weight) -> u64 {
        weight.ref_time().wrapping_div(WEIGHT_PER_GAS)
    }
}

pallet_evm_precompile_storage_reader::impl_pallet_storage_metadata_provider! {
    for Runtime:
        "System" => System,
        "Timestamp" => Timestamp,
        "Balances" => Balances,
        "Session" => Session,
        "PoAModule" => PoAModule,
        "GrandpaFinality" => GrandpaFinality,
        "Authorship" => Authorship,
        "TransactionPayment" => TransactionPayment,
        "Utility" => Utility,
        "OffchainSignatures" => OffchainSignatures,
        "DIDModule" => DIDModule,
        "Revoke" => Revoke,
        "BlobStore" => BlobStore,
        "Master" => Master,
        "Sudo" => Sudo,
        "MigrationModule" => MigrationModule,
        "Anchor" => Anchor,
        "Attest" => Attest,
        "Democracy" => Democracy,
        "Council" => Council,
        "TechnicalCommittee" => TechnicalCommittee,
        "TechnicalCommitteeMembership" => TechnicalCommitteeMembership,
        "Scheduler" => Scheduler,
        "Ethereum" => Ethereum,
        "EVM" => EVM,
        "PriceFeedModule" => PriceFeedModule,
        "AuthorityDiscovery" => AuthorityDiscovery,
        "Historical" => Historical,
        "ImOnline" => ImOnline,
        "Babe" => Babe,
        "Staking" => Staking,
        "ElectionProviderMultiPhase" => ElectionProviderMultiPhase,
        "Offences" => Offences,
        "Treasury" => Treasury,
        "Bounties" => Bounties,
        "StakingRewards" => StakingRewards,
        "Elections" => Elections,
        "Tips" => Tips,
        "Identity" => Identity,
        "Accumulator" => Accumulator,
        "BaseFee" => BaseFee,
        "StatusListCredential" => StatusListCredential,
        "TrustRegistry" => TrustRegistry
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
    type ByteReadWeight = ByteReadWeight;
    type Event = Event;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type PrecompilesType = FrontierPrecompiles<Self>;
    type PrecompilesValue = PrecompilesValue;
    type ChainId = DockChainId;
    type OnChargeTransaction = EVMCurrencyAdapter<Balances, DealWithFees>;

    type BlockGasLimit = BlockGasLimit;
    type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
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

parameter_types! {
    pub const MaxSymbolBytesLen: u32 = 10;
    pub BurnDestination: AccountId = AccountId::from_slice(&[99u8; 32]).unwrap();
}

impl dock_price_feed::Config for Runtime {
    type MaxSymbolBytesLen = ConstU32<10>;
    type Event = Event;
}

impl dock_agreement::Config for Runtime {
    type Event = Event;
}

impl dock_cheqd_migration::Config for Runtime {
    type Event = Event;
    type Currency = Balances;
    type BurnDestination = BurnDestination;
}

parameter_types! {
    pub PrecompilesValue: FrontierPrecompiles<Runtime> = FrontierPrecompiles::<_>::new();
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: system::{Pallet, Call, Config, Storage, Event<T>} = 0,
        Timestamp: timestamp::{Pallet, Call, Storage, Inherent} = 1,
        // Balances pallet has to be put before Session in construct_runtime otherwise there is a runtime panic.
        Balances: balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 2,
        Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>} = 3,
        PoAModule: dock_poa::{Pallet, Storage, Config<T>} = 4,
        GrandpaFinality: grandpa::{Pallet, Call, Storage, Config, Event} = 5,
        Authorship: pallet_authorship::{Pallet, Call, Storage} = 6,
        TransactionPayment: transaction_payment::{Pallet, Storage, Event<T>} = 7,
        Utility: pallet_utility::{Pallet, Call, Event} = 8,
        OffchainSignatures: offchain_signatures::{Pallet, Call, Storage, Event} = 9,
        DIDModule: did::{Pallet, Call, Storage, Event<T>, Config<T>} = 10,
        Revoke: revoke::{Pallet, Call, Storage, Event} = 11,
        BlobStore: blob::{Pallet, Call, Storage} = 12,
        Master: master::{Pallet, Call, Storage, Event<T>, Config<T>} = 13,
        Sudo: sudo::{Pallet, Call, Storage, Event<T>, Config<T>} = 14,
        MigrationModule: dock_token_migration::{Pallet, Call, Storage, Event<T>} = 15,
        Anchor: anchor::{Pallet, Call, Storage, Event<T>} = 16,
        Attest: attest::{Pallet, Call, Storage} = 17,
        Democracy: pallet_democracy::{Pallet, Call, Storage, Event<T>} = 18,
        Council: pallet_collective::<Instance1>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 19,
        TechnicalCommittee: pallet_collective::<Instance2>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 20,
        TechnicalCommitteeMembership: pallet_membership::<Instance1>::{Pallet, Call, Storage, Event<T>, Config<T>} = 21,
        Scheduler: pallet_scheduler::{Pallet, Call, Storage, Event<T>} = 22,
        Ethereum: pallet_ethereum::{Pallet, Call, Storage, Event, Config, Origin} = 23,
        EVM: pallet_evm::{Pallet, Config, Call, Storage, Event<T>} = 24,
        PriceFeedModule: dock_price_feed::{Pallet, Call, Storage, Event<T>} = 25,
        // `fiat_filter` = 26 was here
        AuthorityDiscovery: pallet_authority_discovery::{Pallet, Config} = 27,
        Historical: pallet_session_historical::{Pallet} = 28,
        ImOnline: pallet_im_online::{Pallet, Call, Storage, Event<T>, ValidateUnsigned, Config<T>} = 29,
        Babe: pallet_babe::{Pallet, Call, Storage, Config, ValidateUnsigned} = 30,
        Staking: pallet_staking::{Pallet, Call, Config<T>, Storage, Event<T>} = 31,
        ElectionProviderMultiPhase: pallet_election_provider_multi_phase::{Pallet, Call, Storage, Event<T>, ValidateUnsigned} = 32,
        Offences: pallet_offences::{Pallet, Storage, Event} = 33,
        Treasury: pallet_treasury::{Pallet, Call, Storage, Config, Event<T>} = 34,
        Bounties: pallet_bounties::{Pallet, Call, Storage, Event<T>} = 35,
        StakingRewards: dock_staking_rewards::{Pallet, Call, Storage, Event<T>} = 36,
        Elections: pallet_elections_phragmen::{Pallet, Call, Storage, Event<T>, Config<T>} = 37,
        Tips: pallet_tips::{Pallet, Call, Storage, Event<T>} = 38,
        Identity: pallet_identity::{Pallet, Call, Storage, Event<T>} = 39,
        Accumulator: accumulator::{Pallet, Call, Storage, Event} = 40,
        BaseFee: pallet_base_fee::{Pallet, Call, Storage, Config<T>, Event} = 41,
        StatusListCredential: status_list_credential::{Pallet, Call, Storage, Event} = 42,
        TrustRegistry: trust_registry::{Pallet, Call, Storage, Event} = 43,
        Agreement: dock_agreement::{Pallet, Call, Event} = 44,
        CheqdMigration: dock_cheqd_migration::{Pallet, Call, Event<T>} = 45
    }
);

pub struct TransactionConverter;

impl fp_rpc::ConvertTransaction<UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(&self, transaction: pallet_ethereum::Transaction) -> UncheckedExtrinsic {
        UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        )
    }
}

impl fp_rpc::ConvertTransaction<opaque::UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(
        &self,
        transaction: pallet_ethereum::Transaction,
    ) -> opaque::UncheckedExtrinsic {
        let extrinsic = UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        );
        let encoded = extrinsic.encode();
        opaque::UncheckedExtrinsic::decode(&mut &encoded[..])
            .expect("Encoded extrinsic is always valid")
    }
}

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    fp_self_contained::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<Call, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = fp_self_contained::CheckedExtrinsic<AccountId, Call, SignedExtra, H160>;
/// Executive: handles dispatch to the various modules.
type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    transaction_payment::ChargeTransactionPayment<Runtime>,
    dock_token_migration::OnlyMigrator<Runtime>,
);

impl fp_self_contained::SelfContainedCall for Call {
    type SignedInfo = H160;

    fn is_self_contained(&self) -> bool {
        match self {
            Call::Ethereum(call) => call.is_self_contained(),
            _ => false,
        }
    }

    fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
        match self {
            Call::Ethereum(call) => call.check_self_contained(),
            _ => None,
        }
    }

    fn validate_self_contained(
        &self,
        info: &Self::SignedInfo,
        dispatch_info: &DispatchInfo,
        idx: usize,
    ) -> Option<TransactionValidity> {
        match self {
            Call::Ethereum(call) => call.validate_self_contained(info, dispatch_info, idx),
            _ => None,
        }
    }

    fn pre_dispatch_self_contained(
        &self,
        info: &Self::SignedInfo,
        dispatch_info: &DispatchInfo,
        idx: usize,
    ) -> Option<Result<(), TransactionValidityError>> {
        match self {
            Call::Ethereum(call) => call.pre_dispatch_self_contained(info, dispatch_info, idx),
            _ => None,
        }
    }

    fn apply_self_contained(
        self,
        info: Self::SignedInfo,
    ) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
        match self {
            call @ Call::Ethereum(pallet_ethereum::Call::transact { .. }) => Some(call.dispatch(
                Origin::from(pallet_ethereum::RawOrigin::EthereumTransaction(info)),
            )),
            _ => None,
        }
    }
}

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
            OpaqueMetadata::new(Runtime::metadata().into())
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
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
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
        fn configuration() -> sp_consensus_babe::BabeConfiguration {
            // The choice of `c` parameter (where `1 - c` represents the
            // probability of a slot being empty), is done in accordance to the
            // slot duration and expected target block time, for safely
            // resisting network delays of maximum two seconds.
            // <https://research.web3.foundation/en/latest/polkadot/BABE/Babe/#6-practical-results>
            sp_consensus_babe::BabeConfiguration {
                slot_duration: Babe::slot_duration(),
                epoch_length: EpochDuration::get(),
                c: BABE_GENESIS_EPOCH_CONFIG.c,
                authorities: Babe::authorities().to_vec(),
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
        fn current_set_id() -> fg_primitives::SetId {
            GrandpaFinality::current_set_id()
        }

        fn grandpa_authorities() -> GrandpaAuthorityList {
            GrandpaFinality::grandpa_authorities()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            equivocation_proof: fg_primitives::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;

            GrandpaFinality::submit_unsigned_equivocation_report(
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

    impl beefy_primitives::BeefyApi<Block> for Runtime {
        fn validator_set() -> Option<beefy_primitives::ValidatorSet<beefy_primitives::crypto::AuthorityId>> {
            None
        }
    }

    impl pallet_mmr::primitives::MmrApi<
        Block,
        mmr::Hash,
    > for Runtime {
        fn generate_proof(_leaf_index: pallet_mmr::primitives::LeafIndex)
            -> Result<(mmr::EncodableOpaqueLeaf, mmr::Proof<mmr::Hash>), mmr::Error>
        {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn verify_proof(_leaf: mmr::EncodableOpaqueLeaf, _proof: mmr::Proof<mmr::Hash>)
            -> Result<(), mmr::Error>
        {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn verify_proof_stateless(
            _root: mmr::Hash,
            _leaf: mmr::EncodableOpaqueLeaf,
            _proof: mmr::Proof<mmr::Hash>
        ) -> Result<(), mmr::Error> {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn generate_batch_proof(_leaf_indices: Vec<pallet_mmr::primitives::LeafIndex>)
            -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::BatchProof<mmr::Hash>), mmr::Error>
        {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn verify_batch_proof(_leaves: Vec<mmr::EncodableOpaqueLeaf>, _proof: mmr::BatchProof<mmr::Hash>)
            -> Result<(), mmr::Error>
        {
            Err(mmr::Error::PalletNotIncluded)
        }

        fn verify_batch_proof_stateless(
            _root: mmr::Hash,
            _leaves: Vec<mmr::EncodableOpaqueLeaf>,
            _proof: mmr::BatchProof<mmr::Hash>
        ) -> Result<(), mmr::Error> {
            Err(mmr::Error::PalletNotIncluded)
        }
    }

    impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
        fn chain_id() -> u64 {
            <Runtime as pallet_evm::Config>::ChainId::get()
        }

        fn account_basic(address: H160) -> EVMAccount {
            let (account, _) = EVM::account_basic(&address);
            account
        }

        fn gas_price() -> U256 {
            let (gas_price, _) = <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price();
            gas_price
        }

        fn account_code_at(address: H160) -> Vec<u8> {
            EVM::account_codes(address)
        }

        fn author() -> H160 {
            <pallet_evm::Pallet<Runtime>>::find_author()
        }

        fn storage_at(address: H160, index: U256) -> H256 {
            let mut tmp = [0u8; 32];
            index.to_big_endian(&mut tmp);
            EVM::account_storages(address, H256::from_slice(&tmp[..]))
        }

        #[allow(clippy::or_fun_call)]
        fn call(
            from: H160,
            to: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
            access_list: Option<Vec<(H160, Vec<H256>)>>,
        ) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            let is_transactional = false;
            let validate = true;
            let evm_config = config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config());
            <Runtime as pallet_evm::Config>::Runner::call(
                from,
                to,
                data,
                value,
                gas_limit.unique_saturated_into(),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                access_list.unwrap_or_default(),
                is_transactional,
                validate,
                evm_config,
            ).map_err(|err| err.error.into())
        }

        #[allow(clippy::or_fun_call)]
        fn create(
            from: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
            access_list: Option<Vec<(H160, Vec<H256>)>>,
        ) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            let is_transactional = false;
            let validate = true;
            let evm_config = config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config());
            <Runtime as pallet_evm::Config>::Runner::create(
                from,
                data,
                value,
                gas_limit.unique_saturated_into(),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                access_list.unwrap_or_default(),
                is_transactional,
                validate,
                evm_config,
            ).map_err(|err| err.error.into())
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
            xts.into_iter().filter_map(|xt| match xt.0.function {
                Call::Ethereum(transact { transaction }) => Some(transaction),
                _ => None
            }).collect::<Vec<EthereumTransaction>>()
        }

        fn elasticity() -> Option<Permill> {
            Some(BaseFee::elasticity())
        }
    }

    impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
        fn convert_transaction(transaction: EthereumTransaction) -> <Block as BlockT>::Extrinsic {
            UncheckedExtrinsic::new_unsigned(
                pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
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

    impl dock_poa::runtime_api::PoAApi<Block, AccountId, Balance> for Runtime {
        fn get_treasury_account() -> AccountId {
            PoAModule::treasury_account()
        }

        fn get_treasury_balance() -> Balance {
            PoAModule::treasury_balance()
        }
    }

    impl dock_price_feed::runtime_api::PriceFeedApi<Block, <Runtime as frame_system::Config>::BlockNumber> for Runtime {
        fn price(currency_pair: CurrencySymbolPair<String, String>) -> Option<PriceRecord<<Runtime as frame_system::Config>::BlockNumber>> {
           PriceFeedModule::pair_price(currency_pair).ok().flatten()
        }
    }

    impl dock_staking_rewards::runtime_api::StakingRewardsApi<Block, Balance> for Runtime {
        fn yearly_emission(total_staked: Balance, total_issuance: Balance) -> Balance {
            StakingRewards::yearly_emission(total_staked, total_issuance)
        }

        fn max_yearly_emission() -> Balance {
            StakingRewards::max_yearly_emission()
        }
    }

    impl dock_core::runtime_api::CoreModsApi<Block, Runtime> for Runtime {
        fn did_details(did: did::Did, params: Option<did::AggregatedDidDetailsRequestParams>) -> Option<did::AggregatedDidDetailsResponse<Runtime>> {
            DIDModule::aggregate_did_details(&did, params.unwrap_or_default())
        }

        fn did_list_details(dids: Vec<did::Did>, params: Option<did::AggregatedDidDetailsRequestParams>) -> Vec<Option<did::AggregatedDidDetailsResponse<Runtime>>> {
            let params = params.unwrap_or_default();

            dids.into_iter().map(|did| DIDModule::aggregate_did_details(&did, params)).collect()
        }

        fn bbs_public_key_with_params((did, key_id): offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_key(did, key_id)
                .and_then(CheckedConversion::checked_into)
        }

        fn bbs_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSParameters<Runtime>> {
            OffchainSignatures::did_params(&owner)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn bbs_public_keys_by_did(did: did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_keys(&did)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn bbs_plus_public_key_with_params((did, key_id): offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBSPlusPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_key(did, key_id)
                .and_then(CheckedConversion::checked_into)
        }

        fn bbs_plus_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBSPlusParameters<Runtime>> {
            OffchainSignatures::did_params(&owner)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn bbs_plus_public_keys_by_did(did: did::Did) -> BTreeMap<IncId, offchain_signatures::BBSPlusPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_keys(&did)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn ps_public_key_with_params((did, key_id): offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::PSPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_key(did, key_id)
                .and_then(CheckedConversion::checked_into)
        }

        fn ps_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::PSParameters<Runtime>> {
            OffchainSignatures::did_params(&owner)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn ps_public_keys_by_did(did: did::Did) -> BTreeMap<IncId, offchain_signatures::PSPublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_keys(&did)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn accumulator_public_key_with_params(id: accumulator::AccumPublicKeyStorageKey) -> Option<accumulator::AccumPublicKeyWithParams<Runtime>> {
            Accumulator::public_key_with_params(&id)
        }

        fn accumulator_with_public_key_and_params(id: accumulator::AccumulatorId) -> Option<(Vec<u8>, Option<accumulator::AccumPublicKeyWithParams<Runtime>>)> {
            Accumulator::get_accumulator_with_public_key_and_params(&id)
        }

        fn schema_metadata(
            id: trust_registry::TrustRegistrySchemaId
        ) -> BTreeMap<trust_registry::TrustRegistryId, trust_registry::AggregatedTrustRegistrySchemaMetadata<Runtime>> {
            TrustRegistry::schema_metadata_by_schema_id(id).map(|(registry_id, schema_metadata)| (registry_id, schema_metadata.aggregate(registry_id))).collect()
        }

        fn schema_issuers(
            id: trust_registry::TrustRegistrySchemaId
        ) -> BTreeMap<trust_registry::TrustRegistryId, trust_registry::AggregatedTrustRegistrySchemaIssuers<Runtime>> {
            TrustRegistry::schema_metadata_by_schema_id(id).map(|(registry_id, schema_metadata)| (registry_id, schema_metadata.aggregate(registry_id).issuers)).collect()
        }

        fn schema_verifiers(
            id: trust_registry::TrustRegistrySchemaId
        ) -> BTreeMap<trust_registry::TrustRegistryId, trust_registry::TrustRegistrySchemaVerifiers<Runtime>> {
            TrustRegistry::schema_metadata_by_schema_id(id).map(|(registry_id, schema_metadata)| (registry_id, schema_metadata.verifiers)).collect()
        }

        fn schema_metadata_in_registry(
            id: trust_registry::TrustRegistrySchemaId,
            registry_id: trust_registry::TrustRegistryId
        ) -> Option<trust_registry::AggregatedTrustRegistrySchemaMetadata<Runtime>> {
            TrustRegistry::schema_metadata(id, registry_id).map(|schema_metadata| schema_metadata.aggregate(registry_id))
        }

        fn schema_issuers_in_registry(
            id: trust_registry::TrustRegistrySchemaId,
            registry_id: trust_registry::TrustRegistryId
        ) -> Option<trust_registry::AggregatedTrustRegistrySchemaIssuers<Runtime>> {
            TrustRegistry::schema_metadata(id, registry_id).map(|schema_metadata| schema_metadata.aggregate(registry_id).issuers)
        }

        fn schema_verifiers_in_registry(
            id: trust_registry::TrustRegistrySchemaId,
            registry_id: trust_registry::TrustRegistryId
        ) -> Option<trust_registry::TrustRegistrySchemaVerifiers<Runtime>> {
            TrustRegistry::schema_metadata(id, registry_id).map(|schema_metadata| schema_metadata.verifiers)
        }

        fn all_registry_schema_metadata(
            registry_id: trust_registry::TrustRegistryId
        ) -> BTreeMap<trust_registry::TrustRegistrySchemaId, trust_registry::AggregatedTrustRegistrySchemaMetadata<Runtime>> {
            TrustRegistry::schema_metadata_by_registry_id(registry_id).map(|(schema_id, schema_metadata)| (schema_id, schema_metadata.aggregate(registry_id))).collect()
        }

        fn all_registry_schema_issuers(
            registry_id: trust_registry::TrustRegistryId
        ) -> BTreeMap<trust_registry::TrustRegistrySchemaId, trust_registry::AggregatedTrustRegistrySchemaIssuers<Runtime>> {
            TrustRegistry::schema_metadata_by_registry_id(registry_id).map(|(schema_id, schema_metadata)| (schema_id, schema_metadata.aggregate(registry_id).issuers)).collect()
        }

        fn all_registry_schema_verifiers(
            registry_id: trust_registry::TrustRegistryId
        ) -> BTreeMap<trust_registry::TrustRegistrySchemaId, trust_registry::TrustRegistrySchemaVerifiers<Runtime>> {
            TrustRegistry::schema_metadata_by_registry_id(registry_id).map(|(schema_id, schema_metadata)| (schema_id, schema_metadata.verifiers)).collect()
        }

        fn registries_info_by(
            by: trust_registry::QueryTrustRegistriesBy
        ) -> BTreeMap<trust_registry::TrustRegistryId, trust_registry::TrustRegistryInfo<Runtime>> {
            by.resolve_to_registries_info()
        }

        fn registry_schemas_metadata_by(
            by: trust_registry::QueryTrustRegistryBy,
            reg_id: trust_registry::TrustRegistryId
        ) -> BTreeMap<trust_registry::TrustRegistrySchemaId, trust_registry::AggregatedTrustRegistrySchemaMetadata<Runtime>> {
            by.resolve_to_schemas_metadata_in_registry(reg_id)
        }

        fn registries_ids_by(
            by: trust_registry::QueryTrustRegistriesBy
        ) -> BTreeSet<trust_registry::TrustRegistryId> {
            by.resolve_to_registry_ids::<Runtime>()
        }

        fn registry_schemas_ids_by(
            by: trust_registry::QueryTrustRegistryBy,
            reg_id: trust_registry::TrustRegistryId
        ) -> BTreeSet<trust_registry::TrustRegistrySchemaId> {
            by.resolve_to_schema_ids_in_registry::<Runtime>(reg_id)
        }

        fn bbdt16_public_key_with_params((did, key_id): offchain_signatures::SignaturePublicKeyStorageKey) -> Option<offchain_signatures::BBDT16PublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_key(did, key_id)
                .and_then(CheckedConversion::checked_into)
        }

        fn bbdt16_params_by_did(owner: offchain_signatures::SignatureParamsOwner) -> BTreeMap<IncId, offchain_signatures::BBDT16Parameters<Runtime>> {
            OffchainSignatures::did_params(&owner)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }

        fn bbdt16_public_keys_by_did(did: did::Did) -> BTreeMap<IncId, offchain_signatures::BBDT16PublicKeyWithParams<Runtime>> {
            OffchainSignatures::did_public_keys(&did)
                .filter_map(checked_convert_indexed_item)
                .collect()
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            // use frame_system_benchmarking::Pallet as SystemBench;
            use frame_benchmarking::{list_benchmark, Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;

            let mut list = Vec::<BenchmarkList>::new();

            // Core modules
            list_benchmark!(list, extra, accumulator, Accumulator);
            list_benchmark!(list, extra, attest, Anchor);
            list_benchmark!(list, extra, anchor, Attest);
            list_benchmark!(list, extra, blob, BlobStore);
            list_benchmark!(list, extra, did, DIDModule);
            list_benchmark!(list, extra, offchain_signatures, OffchainSignatures);
            list_benchmark!(list, extra, revoke, Revoke);
            list_benchmark!(list, extra, status_list_credential, StatusListCredential);
            list_benchmark!(list, extra, trust_registry, TrustRegistry);

            // Substrate pallets
            list_benchmark!(list, extra, balances, Balances);
            list_benchmark!(list, extra, pallet_staking, Staking);
            list_benchmark!(list, extra, dock_token_migration, MigrationModule);
            // list_benchmark!(list, extra, frame_system, SystemBench::<Runtime>);

            list_benchmark!(list, extra, pallet_collective, Council);
            list_benchmark!(list, extra, pallet_democracy, Democracy);
            list_benchmark!(list, extra, pallet_elections_phragmen, Elections);
            list_benchmark!(list, extra, pallet_scheduler, Scheduler);

            list_benchmark!(list, extra, pallet_babe, Babe);
            list_benchmark!(list, extra, pallet_election_provider_multi_phase, ElectionProviderMultiPhase);
            list_benchmark!(list, extra, pallet_grandpa, GrandpaFinality);
            list_benchmark!(list, extra, pallet_im_online, ImOnline);
            list_benchmark!(list, extra, pallet_migration, CheqdMigration);

            macro_rules! storage_info {
                ($($pallet: ty),+) => {
                    [$(<$pallet>::storage_info()),+].concat()
                }
            }

            let storage_info = storage_info!(
                System,
                Timestamp,
                Balances,
                Session,
                PoAModule,
                GrandpaFinality,
                Authorship,
                TransactionPayment,
                Utility,
                DIDModule,
                Revoke,
                BlobStore,
                Master,
                Sudo,
                MigrationModule,
                Anchor,
                Attest,
                Democracy,
                Council,
                TechnicalCommittee,
                TechnicalCommitteeMembership,
                Scheduler,
                Ethereum,
                EVM,
                PriceFeedModule,
                AuthorityDiscovery,
                Historical,
                ImOnline,
                Babe,
                Staking,
                ElectionProviderMultiPhase,
                Offences,
                Treasury,
                Bounties,
                StakingRewards,
                Elections,
                Tips,
                Identity,
                OffchainSignatures,
                Accumulator,
                BaseFee,
                StatusListCredential,
                TrustRegistry
            );

            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch, add_benchmark, TrackedStorageKey};
            // Following line copied from substrate node
            // Trying to add benchmarks directly to the Session Pallet caused cyclic dependency issues.
            // To get around that, we separated the Session benchmarks into its own crate, which is why
            // we need these two lines below.
            //use pallet_session_benchmarking::Module as SessionBench;
            //use pallet_offences_benchmarking::Module as OffencesBench;
            // use frame_system_benchmarking::Pallet as SystemBench;

            //impl pallet_session_benchmarking::Config for Runtime {}
            //impl pallet_offences_benchmarking::Config for Runtime {}
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

            // Core modules
            add_benchmark!(params, batches, accumulator, Accumulator);
            add_benchmark!(params, batches, attest, Anchor);
            add_benchmark!(params, batches, anchor, Attest);
            add_benchmark!(params, batches, blob, BlobStore);
            add_benchmark!(params, batches, did, DIDModule);
            add_benchmark!(params, batches, offchain_signatures, OffchainSignatures);
            add_benchmark!(params, batches, revoke, Revoke);
            add_benchmark!(params, batches, status_list_credential, StatusListCredential);
            add_benchmark!(params, batches, trust_registry, TrustRegistry);

            // Substrate pallets
            add_benchmark!(params, batches, balances, Balances);
            add_benchmark!(params, batches, pallet_staking, Staking);
            add_benchmark!(params, batches, dock_token_migration, MigrationModule);
            // add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);

            add_benchmark!(params, batches, pallet_collective, Council);
            add_benchmark!(params, batches, pallet_democracy, Democracy);
            add_benchmark!(params, batches, pallet_elections_phragmen, Elections);
            add_benchmark!(params, batches, pallet_scheduler, Scheduler);

            add_benchmark!(params, batches, pallet_babe, Babe);
            add_benchmark!(params, batches, pallet_election_provider_multi_phase, ElectionProviderMultiPhase);
            add_benchmark!(params, batches, pallet_grandpa, GrandpaFinality);
            add_benchmark!(params, batches, pallet_im_online, ImOnline);
            add_benchmark!(params, batches, pallet_migration, CheqdMigration);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}

/// Executes `CheckedConversion::try_into` on the indexed item, returning the mapped indexed item in case of success.
fn checked_convert_indexed_item<Idx, I, O>((idx, item): (Idx, I)) -> Option<(Idx, O)>
where
    I: TryInto<O>,
{
    item.checked_into().map(|item| (idx, item))
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
        frame_system::GenesisConfig::default()
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
            let is_transactional = false;
            let validate = true;

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
                Some(gas_price.0),
                None,
                Some(U256::zero()),
                Vec::new(),
                is_transactional,
                validate,
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
                Some(gas_price.0),
                None,
                Some(U256::zero()),
                Vec::new(),
                is_transactional,
                validate,
                evm_config,
            )
            .unwrap();

            let treasury_balance3 =
                <Balances as Currency<AccountId>>::free_balance(&treasury_account);
            assert!(treasury_balance3 > treasury_balance2);
        });
    }
}
