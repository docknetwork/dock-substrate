#![cfg(test)]

use super::*;
use codec::Encode;
use frame_support::{
    parameter_types,
    sp_runtime::{
        testing::{Header, UintAuthorityId},
        traits::{BlakeTwo256, Block as BlockT, Dispatchable, Hash, IdentityLookup, OpaqueKeys},
        BuildStorage, KeyTypeId, Perbill,
    },
    traits::OnInitialize,
    weights::{constants::WEIGHT_PER_SECOND, Weight},
};
use frame_system::{self as system, EnsureOneOf, EnsureRoot};
use sp_core::u32_trait::{_1, _2, _3};
use sp_core::{crypto::key_types, H256};
use std::cell::RefCell;

use crate as simple_democracy;

type AccountId = u64;
type BlockNumber = u64;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 2 * WEIGHT_PER_SECOND;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl system::Trait for TestRuntime {
    type BaseCallFilter = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = BlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type DbWeight = ();
    type BlockExecutionWeight = ();
    type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type PalletInfo = ();
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
}

parameter_types! {
    pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * MaximumBlockWeight::get();
}

impl pallet_scheduler::Trait for TestRuntime {
    type Event = ();
    type Origin = Origin;
    type PalletsOrigin = OriginCaller;
    type Call = Call;
    type MaximumWeight = MaximumSchedulerWeight;
    type ScheduleOrigin = EnsureRoot<u64>;
    type MaxScheduledPerBlock = ();
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

impl balances::Trait for TestRuntime {
    type MaxLocks = ();
    type Balance = u64;
    type Event = ();
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
}

parameter_types! {
    pub const LaunchPeriod: u64 = 6;
    pub const VotingPeriod: u64 = 4;
    pub const FastTrackVotingPeriod: u64 = 2;
    pub const MinimumDeposit: u64 = 50;
    pub const EnactmentPeriod: u64 = 2;
    pub const CooloffPeriod: u64 = 2;
    pub const MaxVotes: u32 = 100;
    pub const MaxProposals: u32 = 100;
}

thread_local! {
    static PREIMAGE_BYTE_DEPOSIT: RefCell<u64> = RefCell::new(1);
    static INSTANT_ALLOWED: RefCell<bool> = RefCell::new(false);
}
pub struct PreimageByteDeposit;
impl Get<u64> for PreimageByteDeposit {
    fn get() -> u64 {
        PREIMAGE_BYTE_DEPOSIT.with(|v| *v.borrow())
    }
}

/// This origin indicates that either >50% (simple majority) of Council members approved some dispatch (through a proposal)
/// or the dispatch was done as `Root` (by sudo or master)
type RootOrMoreThanHalfCouncil = EnsureOneOf<
    AccountId,
    EnsureRoot<AccountId>,
    pallet_collective::EnsureProportionMoreThan<_1, _2, AccountId, CouncilCollective>,
>;

type CouncilMember = pallet_collective::EnsureMember<AccountId, CouncilCollective>;

impl pallet_democracy::Trait for TestRuntime {
    type Proposal = Call;
    type Event = ();
    type Currency = balances::Module<Self>;
    type EnactmentPeriod = EnactmentPeriod;
    type LaunchPeriod = LaunchPeriod;
    type VotingPeriod = VotingPeriod;
    type FastTrackVotingPeriod = FastTrackVotingPeriod;
    type MinimumDeposit = MinimumDeposit;
    type ExternalOrigin = CouncilMember;
    type ExternalMajorityOrigin = CouncilMember;
    type ExternalDefaultOrigin = CouncilMember;
    type FastTrackOrigin = EnsureOneOf<
        AccountId,
        pallet_collective::EnsureProportionAtLeast<_2, _3, AccountId, TechnicalCollective>,
        EnsureRoot<AccountId>,
    >;
    type CancellationOrigin = RootOrMoreThanHalfCouncil;
    type CancelProposalOrigin = CouncilMember;
    type OperationalPreimageOrigin = pallet_collective::EnsureMember<AccountId, CouncilCollective>;
    type VetoOrigin = pallet_collective::EnsureMember<AccountId, TechnicalCollective>;
    type CooloffPeriod = CooloffPeriod;
    type PreimageByteDeposit = PreimageByteDeposit;
    type Slash = SimpleDemocracy;
    type InstantOrigin = RootOrMoreThanHalfCouncil;
    type InstantAllowed = ();
    type Scheduler = Scheduler;
    type MaxVotes = MaxVotes;
    type MaxProposals = MaxProposals;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = ();
}

parameter_types! {
    pub const CouncilMotionDuration: BlockNumber = 7;
    pub const CouncilMaxProposals: u32 = 100;
    pub const CouncilMaxMembers: u32 = 30;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Trait<CouncilCollective> for TestRuntime {
    type Origin = Origin;
    type Proposal = Call;
    type Event = ();
    type MotionDuration = CouncilMotionDuration;
    type MaxProposals = CouncilMaxProposals;
    type MaxMembers = CouncilMaxMembers;
    type DefaultVote = pallet_collective::MoreThanMajorityThenPrimeDefaultVote;
    type WeightInfo = ();
}

/// This instance of the membership pallet corresponds to Council.
/// Adding, removing, swapping, reseting members requires an approval of simple majority of the Council
/// or `Root` origin
impl pallet_membership::Trait<pallet_membership::Instance1> for TestRuntime {
    type Event = ();
    type AddOrigin = RootOrMoreThanHalfCouncil;
    type RemoveOrigin = RootOrMoreThanHalfCouncil;
    type SwapOrigin = RootOrMoreThanHalfCouncil;
    type ResetOrigin = RootOrMoreThanHalfCouncil;
    type PrimeOrigin = RootOrMoreThanHalfCouncil;
    type MembershipInitialized = Council;
    type MembershipChanged = Council;
}

parameter_types! {
    pub const TechnicalMotionDuration: BlockNumber = 7;
    pub const TechnicalMaxProposals: u32 = 100;
    pub const TechnicalMaxMembers: u32 = 50;
}

type TechnicalCollective = pallet_collective::Instance2;
impl pallet_collective::Trait<TechnicalCollective> for TestRuntime {
    type Origin = Origin;
    type Proposal = Call;
    type Event = ();
    type MotionDuration = TechnicalMotionDuration;
    type MaxProposals = TechnicalMaxProposals;
    type MaxMembers = TechnicalMaxMembers;
    type DefaultVote = pallet_collective::MoreThanMajorityThenPrimeDefaultVote;
    type WeightInfo = ();
}

/// This instance of the membership pallet corresponds to the Technical committee which can fast track proposals.
/// Adding, removing, swapping, resetting members requires an approval of simple majority of the Council
/// or `Root` origin, the technical committee itself cannot change its membership
impl pallet_membership::Trait<pallet_membership::Instance2> for TestRuntime {
    type Event = ();
    type AddOrigin = RootOrMoreThanHalfCouncil;
    type RemoveOrigin = RootOrMoreThanHalfCouncil;
    type SwapOrigin = RootOrMoreThanHalfCouncil;
    type ResetOrigin = RootOrMoreThanHalfCouncil;
    type PrimeOrigin = RootOrMoreThanHalfCouncil;
    type MembershipInitialized = TechnicalCommittee;
    type MembershipChanged = TechnicalCommittee;
}

/// Dummy session handler as the pallet's trait needs the session pallet's trait
pub struct TestSessionHandler;
type ValidatorId = u64;
impl pallet_session::SessionHandler<ValidatorId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [KeyTypeId] = &[key_types::DUMMY];

    fn on_genesis_session<K: OpaqueKeys>(_validators: &[(ValidatorId, K)]) {}

    fn on_new_session<K: OpaqueKeys>(
        _changed: bool,
        _validators: &[(ValidatorId, K)],
        _queued_validators: &[(ValidatorId, K)],
    ) {
    }

    fn on_disabled(_validator_index: usize) {}
}

impl pallet_session::Trait for TestRuntime {
    type Event = ();
    type ValidatorId = AccountId;
    type ValidatorIdOf = ();
    type ShouldEndSession = PoAModule;
    type NextSessionRotation = ();
    type SessionManager = PoAModule;
    type SessionHandler = TestSessionHandler;
    type Keys = UintAuthorityId;
    type DisabledValidatorsThreshold = ();
    type WeightInfo = ();
}

impl pallet_authorship::Trait for TestRuntime {
    type FindAuthor = ();
    type UncleGenerations = ();
    type FilterUncle = ();
    type EventHandler = ();
}

impl poa::Trait for TestRuntime {
    type Event = ();
    type Currency = balances::Module<Self>;
}

impl super::Trait for TestRuntime {
    type Event = ();
    type VoterOrigin = CouncilMember;
}

pub type Block = sp_runtime::generic::Block<Header, UncheckedExtrinsic>;
pub type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<u32, u64, Call, ()>;

frame_support::construct_runtime!(
    pub enum TestRuntime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: system::{Module, Call},
        Balances: balances::{Module, Call, Storage},
        SimpleDemocracy: simple_democracy::{Module, Call},
        Democracy: pallet_democracy::{Module, Call, Storage},
        Council: pallet_collective::<Instance1>::{Module, Call, Origin<T>},
        CouncilMembership: pallet_membership::<Instance1>::{Module, Call, Storage, Config<T>},
        TechnicalCommittee: pallet_collective::<Instance2>::{Module, Call, Origin<T>},
        TechnicalCommitteeMembership: pallet_membership::<Instance2>::{Module, Call, Storage, Config<T>},
        Scheduler: pallet_scheduler::{Module, Call, Storage},
        PoAModule: poa::{Module, Call, Storage, Event<T>, Config<T>},
    }
);

fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = GenesisConfig {
        pallet_membership_Instance1: Some(pallet_membership::GenesisConfig {
            members: vec![1, 2, 3],
            phantom: Default::default(),
        }),
        pallet_membership_Instance2: Some(pallet_membership::GenesisConfig {
            members: vec![4, 5, 6],
            phantom: Default::default(),
        }),
        poa: Some(PoAModuleConfig {
            min_epoch_length: 25,
            max_active_validators: 4,
            active_validators: vec![],
            emission_supply: 0,
            max_emm_validator_epoch: 0,
            treasury_reward_pc: 75,
            validator_reward_lock_pc: 50,
            emission_status: false,
        }),
    }
    .build_storage()
    .unwrap()
    .into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn make_council_proposal(proposal: Call, threshold: u32) -> Call {
    Call::Council(pallet_collective::Call::propose(
        threshold,
        Box::new(proposal),
        1000,
    ))
}

fn make_council_vote(proposal_hash: H256, proposal_index: u32, approve: bool) -> Call {
    Call::Council(pallet_collective::Call::vote(
        proposal_hash,
        proposal_index,
        approve,
    ))
}

fn make_council_close(proposal_hash: H256, proposal_index: u32) -> Call {
    Call::Council(pallet_collective::Call::close(
        proposal_hash,
        proposal_index,
        1000000000,
        1000,
    ))
}

fn make_tech_comm_proposal(proposal: Call, threshold: u32) -> Call {
    Call::TechnicalCommittee(pallet_collective::Call::propose(
        threshold,
        Box::new(proposal),
        1000,
    ))
}

fn make_tech_comm_vote(proposal_hash: H256, proposal_index: u32, approve: bool) -> Call {
    Call::TechnicalCommittee(pallet_collective::Call::vote(
        proposal_hash,
        proposal_index,
        approve,
    ))
}

fn make_tech_comm_close(proposal_hash: H256, proposal_index: u32) -> Call {
    Call::TechnicalCommittee(pallet_collective::Call::close(
        proposal_hash,
        proposal_index,
        1000000000,
        1000,
    ))
}

fn execute_as_council_member(call: Call) -> Call {
    Call::Council(pallet_collective::Call::execute(Box::new(call), 1000))
}

// Some test helpers copied from forked democracy pallet and adapted
fn set_balance_proposal(balance: u64) -> Vec<u8> {
    Call::Balances(balances::Call::set_balance(42, balance, 0)).encode()
}

fn set_balance_proposal_hash(balance: u64) -> H256 {
    BlakeTwo256::hash(&set_balance_proposal(balance)[..])
}

fn set_balance_proposal_hash_and_note(balance: u64) -> H256 {
    let p = set_balance_proposal(balance);
    let h = BlakeTwo256::hash(&p[..]);
    // Give sufficient balance for deposit
    let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(&117, 1000);
    SimpleDemocracy::note_preimage(Origin::signed(117), p).unwrap();
    h
}

fn propose_set_balance_and_note(who: u64, balance: u64) -> DispatchResult {
    SimpleDemocracy::propose(
        Origin::signed(who),
        set_balance_proposal_hash_and_note(balance),
        50,
    )
}

fn next_block() {
    System::set_block_number(System::block_number() + 1);
    Scheduler::on_initialize(System::block_number());
    Democracy::on_initialize(System::block_number());
    SimpleDemocracy::on_initialize(System::block_number());
}

fn fast_forward_to(n: u64) {
    while System::block_number() < n {
        next_block();
    }
}

fn aye() -> bool {
    true
}

fn nay() -> bool {
    false
}

fn council_votes_and_concludes(balance_set_prop_hash: H256, balance_set_prop: Vec<u8>) {
    // One council member approves
    let vote_1 = Call::SimpleDemocracy(crate::Call::vote(0, aye()));
    let exec_1 = execute_as_council_member(vote_1);
    exec_1.dispatch(Origin::signed(1)).unwrap();

    // One council member disapproves
    let vote_2 = Call::SimpleDemocracy(crate::Call::vote(0, nay()));
    let exec_2 = execute_as_council_member(vote_2);
    exec_2.dispatch(Origin::signed(2)).unwrap();

    assert_eq!(
        Democracy::referendum_status(0).unwrap().tally,
        Tally {
            ayes: 1,
            nays: 1,
            turnout: 0
        }
    );

    // Last council member approves
    let vote_3 = Call::SimpleDemocracy(crate::Call::vote(0, aye()));
    let exec_3 = execute_as_council_member(vote_3);
    exec_3.dispatch(Origin::signed(3)).unwrap();

    assert_eq!(
        Democracy::referendum_status(0).unwrap().tally,
        Tally {
            ayes: 2,
            nays: 1,
            turnout: 0
        }
    );

    assert!(pallet_scheduler::Agenda::<TestRuntime>::get(12).is_empty());

    let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(&10, 1000);
    assert_eq!(Balances::free_balance(10), 1000);

    assert!(SimpleDemocracy::get_preimage(balance_set_prop_hash).is_none());
    SimpleDemocracy::note_preimage(Origin::signed(10), balance_set_prop).unwrap();
    assert!(SimpleDemocracy::get_preimage(balance_set_prop_hash).is_some());
    assert!(Balances::free_balance(10) < 1000);

    fast_forward_to(10);
    assert!(Democracy::referendum_status(0).is_err());
    // The proposal is scheduled to be enacted
    assert!(pallet_scheduler::Agenda::<TestRuntime>::get(12)[0].is_some());
    assert_eq!(Balances::free_balance(42), 0);

    fast_forward_to(12);
    assert_eq!(Balances::free_balance(42), 2);
    assert_eq!(Balances::free_balance(10), 1000);
    // The proposal is enacted
    assert!(pallet_scheduler::Agenda::<TestRuntime>::get(12).is_empty());
}

/// Wait for proposal to become referendum and then council votes in favor and proposal is executed
fn conclude_proposal(balance_set_prop_hash: H256, balance_set_prop: Vec<u8>) {
    assert_eq!(Council::members(), vec![1, 2, 3]);

    assert_eq!(Democracy::referendum_count(), 0);
    fast_forward_to(4);
    assert_eq!(Democracy::referendum_count(), 0);
    fast_forward_to(6);
    // launch period ends, referendum is chosen
    assert_eq!(Democracy::referendum_count(), 1);
    assert_eq!(
        Democracy::referendum_status(0),
        Ok(ReferendumStatus {
            end: 10, // 6+4, i.e. launch period + voting period
            proposal_hash: balance_set_prop_hash,
            threshold: VoteThreshold::SimpleMajority,
            delay: 2, // enactment delay
            tally: Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            },
        })
    );
    council_votes_and_concludes(balance_set_prop_hash, balance_set_prop)
}

fn execute_poa_config_proposal(start: u64, ref_id: ReferendumIndex, proposal: Vec<u8>) {
    fast_forward_to(start + 6);

    // One council member approves
    let vote_1 = Call::SimpleDemocracy(crate::Call::vote(ref_id, aye()));
    let exec_1 = execute_as_council_member(vote_1);
    exec_1.dispatch(Origin::signed(1)).unwrap();

    // Another council member approves
    let vote_2 = Call::SimpleDemocracy(crate::Call::vote(ref_id, aye()));
    let exec_2 = execute_as_council_member(vote_2);
    exec_2.dispatch(Origin::signed(2)).unwrap();

    let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(&10, 1000);
    SimpleDemocracy::note_preimage(Origin::signed(10), proposal).unwrap();

    fast_forward_to(start + 12);
}

#[test]
fn change_council_membership() {
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(Council::proposals().len(), 0);

        // Add a new member to Council with simple majority
        // Account 1 proposes and implicitly approves
        let proposal_to_add = Call::CouncilMembership(pallet_membership::Call::add_member(10));
        // 2 out of 3 make simple majority
        let proposal_call_1 = make_council_proposal(proposal_to_add, 2);
        proposal_call_1.dispatch(Origin::signed(1)).unwrap();
        assert_eq!(Council::proposals().len(), 1);

        // Account 2 approves
        let vote_call_1 = make_council_vote(Council::proposals()[0], 0, true);
        vote_call_1.dispatch(Origin::signed(2)).unwrap();

        // Any account, 100 in this case can close
        let close_call_1 = make_council_close(Council::proposals()[0], 0);
        close_call_1.dispatch(Origin::signed(100)).unwrap();

        // New member added
        assert_eq!(Council::proposals().len(), 0);
        assert_eq!(Council::members(), vec![1, 2, 3, 10]);

        // Remove member from Council with simple majority
        let proposal_to_remove = Call::CouncilMembership(pallet_membership::Call::remove_member(1));
        // 3 out of 4 make simple majority
        let proposal_call_2 = make_council_proposal(proposal_to_remove, 3);
        proposal_call_2.dispatch(Origin::signed(2)).unwrap();
        assert_eq!(Council::proposals().len(), 1);

        let vote_call_2 = make_council_vote(Council::proposals()[0], 1, true);
        vote_call_2.dispatch(Origin::signed(3)).unwrap();

        let vote_call_3 = make_council_vote(Council::proposals()[0], 1, true);
        vote_call_3.dispatch(Origin::signed(10)).unwrap();

        let close_call_2 = make_council_close(Council::proposals()[0], 1);
        close_call_2.dispatch(Origin::signed(100)).unwrap();

        assert_eq!(Council::proposals().len(), 0);
        // Member removed
        assert_eq!(Council::members(), vec![2, 3, 10]);

        // Try to add new member to Council but get rejected by simple majority
        let proposal_to_add_failing =
            Call::CouncilMembership(pallet_membership::Call::add_member(1));
        // 2 out of 3 make simple majority
        let proposal_call_3 = make_council_proposal(proposal_to_add_failing, 2);
        proposal_call_3.dispatch(Origin::signed(10)).unwrap();
        assert_eq!(Council::proposals().len(), 1);

        let vote_call_4 = make_council_vote(Council::proposals()[0], 2, false);
        vote_call_4.dispatch(Origin::signed(2)).unwrap();

        let vote_call_5 = make_council_vote(Council::proposals()[0], 2, false);
        vote_call_5.dispatch(Origin::signed(3)).unwrap();

        let close_call_3 = make_council_close(Council::proposals()[0], 2);
        close_call_3.dispatch(Origin::signed(100)).unwrap();

        assert_eq!(Council::proposals().len(), 0);
        // Member not added
        assert_eq!(Council::members(), vec![2, 3, 10]);
    });
}

#[test]
fn change_technical_committee_membership() {
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(TechnicalCommitteeMembership::members(), vec![4, 5, 6]);

        // Add new member to Council with simple majority
        // Account 1 proposes and implicitly approves
        let proposal_to_add =
            Call::TechnicalCommitteeMembership(pallet_membership::Call::add_member(10));
        // 2 out of 3 make simple majority
        let proposal_call_1 = make_council_proposal(proposal_to_add, 2);
        proposal_call_1.dispatch(Origin::signed(1)).unwrap();

        // Account 2 approves
        let vote_call_1 = make_council_vote(Council::proposals()[0], 0, true);
        vote_call_1.dispatch(Origin::signed(2)).unwrap();

        // Any account, 100 in this case can close
        let close_call_1 = make_council_close(Council::proposals()[0], 0);
        close_call_1.dispatch(Origin::signed(100)).unwrap();

        // New member added
        assert_eq!(TechnicalCommitteeMembership::members(), vec![4, 5, 6, 10]);

        // Remove member from Technical Committee with simple majority
        let proposal_to_remove =
            Call::TechnicalCommitteeMembership(pallet_membership::Call::remove_member(4));
        // 2 out of 3 make simple majority
        let proposal_call_2 = make_council_proposal(proposal_to_remove, 2);
        proposal_call_2.dispatch(Origin::signed(2)).unwrap();

        let vote_call_2 = make_council_vote(Council::proposals()[0], 1, true);
        vote_call_2.dispatch(Origin::signed(1)).unwrap();

        let close_call_2 = make_council_close(Council::proposals()[0], 1);
        close_call_2.dispatch(Origin::signed(100)).unwrap();

        // Member removed
        assert_eq!(TechnicalCommitteeMembership::members(), vec![5, 6, 10]);

        // Try to add new member to Technical Committee but get rejected by simple majority
        let proposal_to_add_failing =
            Call::TechnicalCommitteeMembership(pallet_membership::Call::add_member(4));
        // 2 out of 3 make simple majority
        let proposal_call_3 = make_council_proposal(proposal_to_add_failing, 2);
        proposal_call_3.dispatch(Origin::signed(3)).unwrap();

        let vote_call_3 = make_council_vote(Council::proposals()[0], 2, false);
        vote_call_3.dispatch(Origin::signed(1)).unwrap();

        let vote_call_4 = make_council_vote(Council::proposals()[0], 2, false);
        vote_call_4.dispatch(Origin::signed(2)).unwrap();

        let close_call_3 = make_council_close(Council::proposals()[0], 2);
        close_call_3.dispatch(Origin::signed(100)).unwrap();

        // Member not added
        assert_eq!(TechnicalCommitteeMembership::members(), vec![5, 6, 10]);
    });
}

#[test]
fn council_proposes_root_action_and_accepts() {
    new_test_ext().execute_with(|| {
        assert_eq!(Balances::free_balance(42), 0);

        System::set_block_number(0);

        assert!(SimpleDemocracy::next_external().is_none());

        let balance_set_prop = set_balance_proposal(2);
        let balance_set_prop_hash = BlakeTwo256::hash(&balance_set_prop);

        let proposal = Call::SimpleDemocracy(crate::Call::council_propose(balance_set_prop_hash));
        let exec = execute_as_council_member(proposal);

        // Non council member cannot call `council_propose`, i.e. propose as council
        assert!(exec.clone().dispatch(Origin::signed(5)).is_err());
        assert!(SimpleDemocracy::next_external().is_none());

        // Only council member can send
        exec.dispatch(Origin::signed(1)).unwrap();
        SimpleDemocracy::next_external().unwrap();

        conclude_proposal(balance_set_prop_hash, balance_set_prop);
    });
}

#[test]
fn public_proposes_root_action_and_council_accepts() {
    new_test_ext().execute_with(|| {
        assert_eq!(Balances::free_balance(42), 0);

        let proposer = 50;
        let backer = 60;
        System::set_block_number(0);

        let balance_set_prop = set_balance_proposal(2);
        let balance_set_prop_hash = BlakeTwo256::hash(&balance_set_prop);

        // Proposer should have at least `MinimumDeposit` balance to propose which is 50
        let deposit = 50;
        // Give some balance but less than `MinimumDeposit`
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer,
            deposit - 10,
        );
        assert!(Balances::free_balance(proposer) < deposit);
        assert_eq!(Balances::reserved_balance(proposer), 0);

        // Proposing should fail
        assert!(
            SimpleDemocracy::propose(Origin::signed(proposer), balance_set_prop_hash, deposit)
                .is_err()
        );

        // Give some more balance to reach `MinimumDeposit`
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(&proposer, 10);
        let _ =
            <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(&backer, deposit);
        assert!(Balances::free_balance(proposer) >= deposit);
        assert!(Balances::free_balance(backer) >= deposit);

        assert_eq!(SimpleDemocracy::public_prop_count(), 0);
        // Proposing should work and proposer's balance should be reserved
        SimpleDemocracy::propose(Origin::signed(proposer), balance_set_prop_hash, deposit).unwrap();
        assert_eq!(SimpleDemocracy::public_prop_count(), 1);

        SimpleDemocracy::second(Origin::signed(backer), 0, 10).unwrap();

        // Proposer and backer got their balance locked (reserved)
        assert_eq!(Balances::reserved_balance(proposer), deposit);
        assert_eq!(Balances::reserved_balance(backer), deposit);
        assert!(Balances::free_balance(proposer) < deposit);
        assert!(Balances::free_balance(backer) < deposit);

        conclude_proposal(balance_set_prop_hash, balance_set_prop);

        // Proposer and backer got their balance back (unreserved)
        assert_eq!(Balances::free_balance(proposer), deposit);
        assert_eq!(Balances::free_balance(backer), deposit);
        assert_eq!(Balances::reserved_balance(proposer), 0);
        assert_eq!(Balances::reserved_balance(backer), 0);
    });
}

#[test]
fn public_proposes_root_action_and_council_rejects() {
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(Balances::free_balance(42), 0);

        let proposer = 5;
        let backer_1 = 6;
        let backer_2 = 7;

        let balance_set_prop = set_balance_proposal(2);
        let balance_set_prop_hash = BlakeTwo256::hash(&balance_set_prop);

        let deposit = 50;
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer,
            10 * deposit,
        );
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &backer_1,
            10 * deposit,
        );
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &backer_2,
            10 * deposit,
        );

        assert_eq!(Balances::reserved_balance(proposer), 0);
        assert_eq!(Balances::reserved_balance(backer_1), 0);
        assert_eq!(Balances::reserved_balance(backer_1), 0);
        assert!(SimpleDemocracy::deposit_of(0).is_none());

        // Public proposal backed by 2 more accounts
        SimpleDemocracy::propose(Origin::signed(proposer), balance_set_prop_hash, deposit).unwrap();
        SimpleDemocracy::second(Origin::signed(backer_1), 0, 10).unwrap();
        SimpleDemocracy::second(Origin::signed(backer_2), 0, 10).unwrap();
        assert_eq!(SimpleDemocracy::public_props().len(), 1);

        // Proposer's and backers' free balance decreases and that balance is reserved.
        assert_eq!(Balances::reserved_balance(proposer), deposit);
        assert_eq!(Balances::reserved_balance(backer_1), deposit);
        assert_eq!(Balances::reserved_balance(backer_1), deposit);
        assert_eq!(SimpleDemocracy::deposit_of(0).unwrap().0.len(), 3);
        assert_eq!(SimpleDemocracy::deposit_of(0).unwrap().1, deposit);

        let treasury_balance = PoAModule::treasury_balance();

        let proposal = Call::SimpleDemocracy(crate::Call::cancel_proposal(0));
        let exec = execute_as_council_member(proposal);

        // Non council member cannot cancel the proposal
        assert!(exec.clone().dispatch(Origin::signed(5)).is_err());
        assert_eq!(SimpleDemocracy::public_props().len(), 1);

        // Council member cancels the proposal
        exec.dispatch(Origin::signed(1)).unwrap();
        assert_eq!(SimpleDemocracy::public_props().len(), 0);

        // Proposer's and backers' balance is slashed and treasury is credited
        assert!(SimpleDemocracy::deposit_of(0).is_none());
        assert_eq!(Balances::reserved_balance(proposer), 0);
        assert_eq!(Balances::reserved_balance(backer_1), 0);
        assert_eq!(Balances::reserved_balance(backer_1), 0);
        assert_eq!(Balances::free_balance(proposer), 9 * deposit);
        assert_eq!(Balances::free_balance(backer_1), 9 * deposit);
        assert_eq!(Balances::free_balance(backer_1), 9 * deposit);
        assert_eq!(
            treasury_balance + 3 * deposit,
            PoAModule::treasury_balance()
        );

        // The proposal's intended change did not happen
        assert_eq!(Balances::free_balance(42), 0);
    });
}

#[test]
fn only_council_can_vote() {
    // Only council can vote. Neither public not technical committee can vote
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(TechnicalCommitteeMembership::members(), vec![4, 5, 6]);
        assert_eq!(Balances::free_balance(42), 0);

        let proposer = 20;
        System::set_block_number(0);

        let balance_set_prop = set_balance_proposal(2);
        let balance_set_prop_hash = BlakeTwo256::hash(&balance_set_prop);

        let deposit = 50;
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer, deposit,
        );

        assert_eq!(SimpleDemocracy::public_props().len(), 0);

        // Public proposal
        SimpleDemocracy::propose(Origin::signed(proposer), balance_set_prop_hash, deposit).unwrap();
        assert_eq!(SimpleDemocracy::public_props().len(), 1);
        assert_eq!(SimpleDemocracy::referendum_count(), 0);

        fast_forward_to(6);
        // launch period ends, referendum is chosen
        assert_eq!(SimpleDemocracy::referendum_count(), 1);

        assert_eq!(
            SimpleDemocracy::referendum_status(0),
            Ok(ReferendumStatus {
                end: 10, // 6+4, i.e. launch period + voting period
                proposal_hash: balance_set_prop_hash,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2, // enactment delay
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );

        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        // A public (non-council, non-committee) account approves
        let vote_1 = Call::SimpleDemocracy(crate::Call::vote(0, aye()));
        let exec_1 = execute_as_council_member(vote_1);
        assert!(exec_1.dispatch(Origin::signed(50)).is_err());
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        // A public (non-council, non-committee) account disapproves
        let vote_2 = Call::SimpleDemocracy(crate::Call::vote(0, nay()));
        let exec_2 = execute_as_council_member(vote_2);
        assert!(exec_2.dispatch(Origin::signed(50)).is_err());
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        // A committee member approves
        let vote_3 = Call::SimpleDemocracy(crate::Call::vote(0, aye()));
        let exec_3 = execute_as_council_member(vote_3);
        assert!(exec_3.dispatch(Origin::signed(4)).is_err());
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        // A committee member disapproves
        let vote_4 = Call::SimpleDemocracy(crate::Call::vote(0, nay()));
        let exec_4 = execute_as_council_member(vote_4);
        assert!(exec_4.dispatch(Origin::signed(4)).is_err());
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        council_votes_and_concludes(balance_set_prop_hash, balance_set_prop);

        assert_eq!(Balances::free_balance(proposer), 50);
    });
}

#[test]
fn can_change_remove_vote() {
    // Voter (Council) can change vote or remove vote
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(Balances::free_balance(42), 0);

        let proposer = 23;
        System::set_block_number(0);

        let balance_set_prop = set_balance_proposal(2);
        let balance_set_prop_hash = BlakeTwo256::hash(&balance_set_prop);

        let deposit = 50;
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer, deposit,
        );
        // Public proposal
        SimpleDemocracy::propose(Origin::signed(proposer), balance_set_prop_hash, deposit).unwrap();

        assert_eq!(SimpleDemocracy::referendum_count(), 0);
        fast_forward_to(6);
        // launch period ends, referendum is chosen
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        // One council member approves
        let vote_1 = Call::SimpleDemocracy(crate::Call::vote(0, aye()));
        let exec_1 = execute_as_council_member(vote_1);
        exec_1.dispatch(Origin::signed(1)).unwrap();
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 1,
                nays: 0,
                turnout: 0
            }
        );

        // Same council member changes vote to disapproval
        let vote_2 = Call::SimpleDemocracy(crate::Call::vote(0, nay()));
        let exec_2 = execute_as_council_member(vote_2);
        exec_2.dispatch(Origin::signed(1)).unwrap();
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 1,
                turnout: 0
            }
        );

        // Same council member removes vote
        let vote_3 = Call::SimpleDemocracy(crate::Call::remove_vote(0));
        let exec_3 = execute_as_council_member(vote_3);
        exec_3.dispatch(Origin::signed(1)).unwrap();
        assert_eq!(
            SimpleDemocracy::referendum_status(0).unwrap().tally,
            Tally {
                ayes: 0,
                nays: 0,
                turnout: 0
            }
        );

        council_votes_and_concludes(balance_set_prop_hash, balance_set_prop);
    });
}

#[test]
fn proposals_picked_alternatively() {
    new_test_ext().execute_with(|| {
        System::set_block_number(0);

        let proposer_1 = 21;
        let proposer_2 = 22;
        let proposer_3 = 23;

        let deposit = 50;
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer_1,
            deposit,
        );
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer_2,
            deposit,
        );
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer_3,
            deposit,
        );

        assert_eq!(SimpleDemocracy::public_props().len(), 0);
        propose_set_balance_and_note(proposer_1, 20).unwrap();
        let public_prop_1 = set_balance_proposal_hash(20);
        assert_eq!(SimpleDemocracy::public_props().len(), 1);
        propose_set_balance_and_note(proposer_2, 30).unwrap();
        let public_prop_2 = set_balance_proposal_hash(30);
        assert_eq!(SimpleDemocracy::public_props().len(), 2);
        propose_set_balance_and_note(proposer_3, 40).unwrap();
        let public_prop_3 = set_balance_proposal_hash(40);
        assert_eq!(SimpleDemocracy::public_props().len(), 3);

        fast_forward_to(2);

        let council_prop_1 = set_balance_proposal_hash_and_note(5);
        let exec_1 = execute_as_council_member(Call::SimpleDemocracy(
            crate::Call::council_propose(council_prop_1),
        ));
        exec_1.dispatch(Origin::signed(1)).unwrap();

        fast_forward_to(6);

        assert_eq!(
            SimpleDemocracy::referendum_status(0),
            Ok(ReferendumStatus {
                end: 10,
                proposal_hash: council_prop_1,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );

        fast_forward_to(7);

        let council_prop_2 = set_balance_proposal_hash_and_note(6);
        let exec_2 = execute_as_council_member(Call::SimpleDemocracy(
            crate::Call::council_propose(council_prop_2),
        ));
        exec_2.dispatch(Origin::signed(2)).unwrap();

        fast_forward_to(12);

        assert_eq!(
            SimpleDemocracy::referendum_status(1),
            Ok(ReferendumStatus {
                end: 16,
                proposal_hash: public_prop_3,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );

        fast_forward_to(18);

        assert_eq!(
            SimpleDemocracy::referendum_status(2),
            Ok(ReferendumStatus {
                end: 22,
                proposal_hash: council_prop_2,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );

        fast_forward_to(24);

        assert_eq!(
            SimpleDemocracy::referendum_status(3),
            Ok(ReferendumStatus {
                end: 28,
                proposal_hash: public_prop_2,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );

        fast_forward_to(30);

        assert_eq!(
            SimpleDemocracy::referendum_status(4),
            Ok(ReferendumStatus {
                end: 34,
                proposal_hash: public_prop_1,
                threshold: VoteThreshold::SimpleMajority,
                delay: 2,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );
    });
}

#[test]
fn tech_committee_fast_tracks() {
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);
        assert_eq!(TechnicalCommitteeMembership::members(), vec![4, 5, 6]);
        assert_eq!(Balances::free_balance(42), 0);

        System::set_block_number(0);

        let council_prop = set_balance_proposal_hash_and_note(55);
        let exec = execute_as_council_member(Call::SimpleDemocracy(crate::Call::council_propose(
            council_prop,
        )));
        exec.dispatch(Origin::signed(1)).unwrap();

        assert_eq!(SimpleDemocracy::referendum_count(), 0);

        // Member 4 of technical committee proposes to set the voting period as 3 blocks and delay as 1 block
        let proposal_to_fast_track =
            Call::SimpleDemocracy(crate::Call::fast_track(council_prop, 3, 1));
        let proposal_call_1 = make_tech_comm_proposal(proposal_to_fast_track, 2);
        proposal_call_1.dispatch(Origin::signed(4)).unwrap();

        // Member 5 approves
        let vote_call_1 = make_tech_comm_vote(TechnicalCommittee::proposals()[0], 0, true);
        vote_call_1.dispatch(Origin::signed(5)).unwrap();

        // Any account, 100 in this case can close
        let close_call_1 = make_tech_comm_close(TechnicalCommittee::proposals()[0], 0);
        close_call_1.dispatch(Origin::signed(100)).unwrap();

        assert_eq!(SimpleDemocracy::referendum_count(), 1);

        assert_eq!(
            SimpleDemocracy::referendum_status(0),
            Ok(ReferendumStatus {
                end: 3,
                proposal_hash: council_prop,
                threshold: VoteThreshold::SimpleMajority,
                delay: 1,
                tally: Tally {
                    ayes: 0,
                    nays: 0,
                    turnout: 0
                },
            })
        );
    });
}

#[test]
fn changing_config_of_poa_module() {
    // The council and public both can change PoA module's config
    new_test_ext().execute_with(|| {
        assert_eq!(Council::members(), vec![1, 2, 3]);

        System::set_block_number(0);

        // Council proposes and changes treasury reward percentage
        assert_eq!(PoAModule::treasury_reward_pc(), 75);
        let proposal_to_increase_treasury_pc =
            Call::PoAModule(poa::Call::set_treasury_reward_pc(90)).encode();
        let prop_1_hash = BlakeTwo256::hash(&proposal_to_increase_treasury_pc);

        let proposal_1 = Call::SimpleDemocracy(crate::Call::council_propose(prop_1_hash));
        let exec_1 = execute_as_council_member(proposal_1);
        exec_1.dispatch(Origin::signed(1)).unwrap();

        execute_poa_config_proposal(0, 0, proposal_to_increase_treasury_pc);

        // Treasury reward percentage increased
        assert_eq!(PoAModule::treasury_reward_pc(), 90);

        // Public proposes and changes validator reward lock percentage
        assert_eq!(PoAModule::validator_reward_lock_pc(), 50);
        let proposer = 55;
        let proposal_to_decrease_val_lock_pc =
            Call::PoAModule(poa::Call::set_validator_reward_lock_pc(30)).encode();
        let prop_2_hash = BlakeTwo256::hash(&proposal_to_decrease_val_lock_pc);

        // Give some more balance to reach `MinimumDeposit`
        let deposit = 50;
        let _ = <TestRuntime as pallet_democracy::Trait>::Currency::deposit_creating(
            &proposer, deposit,
        );
        SimpleDemocracy::propose(Origin::signed(proposer), prop_2_hash, deposit).unwrap();

        execute_poa_config_proposal(12, 1, proposal_to_decrease_val_lock_pc);

        // Validator reward lock percentage decreased
        assert_eq!(PoAModule::validator_reward_lock_pc(), 30);
    });
}
