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

pub mod anchor;
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_utils;
pub mod blob;
pub mod did;
pub mod master;
pub mod revoke;
pub mod weight_to_fee;

pub use poa;
pub use simple_democracy;
pub use token_migration;

#[cfg(test)]
mod test_common;

use codec::{Decode, Encode};
use frame_support::{
    construct_runtime, parameter_types,
    traits::{Filter, KeyOwnerProofSystem, Randomness},
    weights::{
        constants::{
            BlockExecutionWeight as DefaultBlockExecutionWeight, ExtrinsicBaseWeight,
            RocksDbWeight, WEIGHT_PER_SECOND,
        },
        Weight,
    },
};
use frame_system as system;
use frame_system::{EnsureOneOf, EnsureRoot};
use grandpa::fg_primitives;
use grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use pallet_sudo as sudo;
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::u32_trait::{_1, _2, _3};
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, ConvertInto, IdentifyAccount, IdentityLookup, NumberFor,
    OpaqueKeys, Saturating, Verify,
};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, MultiSignature, Perbill,
};

use crate::weight_to_fee::TxnFee;
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u64;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// The token has 6 decimal places
pub const DOCK: Balance = 1_000_000;

/// Any state change that needs to be signed is first wrapped in this enum and then its serialized.
/// This is done to prevent make it unambiguous which command was intended as the SCALE codec's
/// not self describing.
/// Never change the order of variants in this enum
#[derive(Encode, Decode)]
pub enum StateChange {
    KeyUpdate(did::KeyUpdate),
    DIDRemoval(did::DidRemoval),
    Revoke(revoke::Revoke),
    UnRevoke(revoke::UnRevoke),
    RemoveRegistry(revoke::RemoveRegistry),
    Blob(blob::Blob),
    MasterVote(master::Payload),
}

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core datastructures.
pub mod opaque {
    use super::*;

    use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;

    impl_opaque_keys! {
        pub struct SessionKeys {
            pub aura: Aura,
            pub grandpa: Grandpa,
        }
    }
}

/// This runtime version.
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("dock-main-runtime"),
    impl_name: create_runtime_str!("dock-main-runtime"),
    authoring_version: 1,
    spec_version: 17,
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

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    /// We allow for 1 seconds of compute with a 3 second average block time.
    pub const MaximumBlockWeight: Weight = WEIGHT_PER_SECOND;
    /// Since there are no `Operational` transactions as of now, the whole block can be filled with
    /// `Normal` transactions.
    pub const AvailableBlockRatio: Perbill = Perbill::from_percent(100);
    /// Assume 10% of weight for average on_initialize calls.
    pub MaximumExtrinsicWeight: Weight = AvailableBlockRatio::get().saturating_sub(Perbill::from_percent(10)) * MaximumBlockWeight::get();
    /// DefaultBlockExecutionWeight is the weight of any empty block.
    /// After each block we
    /// - update stats, which is 1 read and 1 write
    /// - check if there is any fees in storage item `TxnFees`, which is 1 read
    /// - credit fees to block author's account which is 1 read and 1 write
    /// - reset the storage item `TxnFees`, 1 write
    /// Thus in the worst case, we do 3 reads and 3 writes
    pub BlockExecutionWeight: Weight = DefaultBlockExecutionWeight::get() +
        <Runtime as system::Trait>::DbWeight::get().reads_writes(3, 3);
    pub const MaximumBlockLength: u32 = 5 * 1024 * 1024;
    pub const Version: RuntimeVersion = VERSION;
}

impl system::Trait for Runtime {
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
    type Lookup = IdentityLookup<AccountId>;
    /// The header type.
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// The ubiquitous event type.
    type Event = Event;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// Maximum weight of each block.
    type MaximumBlockWeight = MaximumBlockWeight;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    /// The weight of the overhead invoked on the block import process, independent of the
    /// extrinsics included in that block.
    type BlockExecutionWeight = BlockExecutionWeight;
    /// The base weight of any extrinsic processed by the runtime, independent of the
    /// logic of that extrinsic. (Signature verification, nonce increment, fee, etc...)
    /// The storage item `TxnFees` would potentially be read and written after each extrinsic if that
    /// pays fees but that read and write goes to DB only once per block due to Substrate's _overlay change set_
    /// and is captured in weight calculation of `BlockExecutionWeight`
    type ExtrinsicBaseWeight = ExtrinsicBaseWeight;
    /// The maximum weight that a single extrinsic of `Normal` dispatch class can have,
    /// independent of the logic of that extrinsics. (Roughly max block weight - average on
    /// initialize cost).
    type MaximumExtrinsicWeight = MaximumExtrinsicWeight;
    /// Maximum size of all encoded transactions (in bytes) that are allowed in one block.
    type MaximumBlockLength = MaximumBlockLength;
    /// Portion of the block weight that is available to all normal transactions.
    type AvailableBlockRatio = AvailableBlockRatio;
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
}

impl aura::Trait for Runtime {
    type AuthorityId = AuraId;
}

impl grandpa::Trait for Runtime {
    type Event = Event;

    type Call = Call;

    type KeyOwnerProof =
        <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;

    type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
        KeyTypeId,
        GrandpaId,
    )>>::IdentificationTuple;

    type KeyOwnerProofSystem = ();

    type HandleEquivocation = ();

    type WeightInfo = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl timestamp::Trait for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 500;
    pub const MaxLocks: u32 = 50;
}

impl balances::Trait for Runtime {
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

impl transaction_payment::Trait for Runtime {
    type Currency = balances::Module<Runtime>;
    /// Transaction fees is handled by PoA module
    type OnTransactionPayment = PoAModule;
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
}

impl blob::Trait for Runtime {
    type MaxBlobSize = MaxBlobSize;
}

impl pallet_session::Trait for Runtime {
    type Event = Event;
    type ValidatorId = <Self as system::Trait>::AccountId;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = PoAModule;
    type NextSessionRotation = ();
    type SessionManager = PoAModule;
    type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = opaque::SessionKeys;
    type DisabledValidatorsThreshold = ();
    type WeightInfo = ();
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
    /// Not accepting any uncles
    pub const UncleGenerations: u32 = 0;
}

impl pallet_authorship::Trait for Runtime {
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = ();
    type EventHandler = ();
}

/// Utility pallet is needed to send extrinsics in a batch
impl pallet_utility::Trait for Runtime {
    type Event = Event;
    type Call = Call;
    type WeightInfo = ();
}

impl master::Trait for Runtime {
    type Event = Event;
    type Call = Call;
}

impl sudo::Trait for Runtime {
    type Event = Event;
    type Call = Call;
}

impl anchor::Trait for Runtime {
    type Event = Event;
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
impl pallet_collective::Trait<CouncilCollective> for Runtime {
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
impl pallet_membership::Trait<pallet_membership::Instance1> for Runtime {
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
impl pallet_collective::Trait<TechnicalCollective> for Runtime {
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
impl pallet_membership::Trait<pallet_membership::Instance2> for Runtime {
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

impl pallet_scheduler::Trait for Runtime {
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
    pub const EnactmentPeriod: BlockNumber = 30;    // 30 sec
    pub const LaunchPeriod: BlockNumber = 3 * MINUTES;
    pub const VotingPeriod: BlockNumber = 2 * MINUTES;
    pub const CooloffPeriod: BlockNumber = 1 * MINUTES;
    pub const FastTrackVotingPeriod: BlockNumber = 1 * MINUTES;
    /// 10K tokens
    pub const MinimumDeposit: Balance = 10_000 * DOCK;
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

pub struct BaseFilter;

impl Filter<Call> for BaseFilter {
    fn filter(call: &Call) -> bool {
        match call {
            Call::Democracy(_) => false,
            _ => true,
        }
    }
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: system::{Module, Call, Config, Storage, Event<T>},
        RandomnessCollectiveFlip: randomness_collective_flip::{Module, Call, Storage},
        Timestamp: timestamp::{Module, Call, Storage, Inherent},
        Session: pallet_session::{Module, Call, Storage, Event, Config<T>},
        PoAModule: poa::{Module, Call, Storage, Event<T>, Config<T>},
        Aura: aura::{Module, Config<T>, Inherent},
        Grandpa: grandpa::{Module, Call, Storage, Config, Event},
        Balances: balances::{Module, Call, Storage, Config<T>, Event<T>},
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
    }
);

/// Block header type as expected by this runtime.
type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
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
/// Unchecked extrinsic type as expected by this runtime.
type UncheckedExtrinsic = generic::UncheckedExtrinsic<AccountId, Call, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
type Executive =
    frame_executive::Executive<Runtime, Block, system::ChainContext<Runtime>, Runtime, AllModules>;

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
            RandomnessCollectiveFlip::random_seed()
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

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> u64 {
            Aura::slot_duration()
        }

        fn authorities() -> Vec<AuraId> {
            Aura::authorities()
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
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

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
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
            impl frame_system_benchmarking::Trait for Runtime {}

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
