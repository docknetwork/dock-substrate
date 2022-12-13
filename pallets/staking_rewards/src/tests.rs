use crate as staking_rewards;

use frame_support::{assert_noop, assert_ok, parameter_types};
use frame_system::{self as system, RawOrigin};
use sp_core::H256;
use sp_runtime::{
    curve::PiecewiseLinear,
    testing::Header,
    traits::{BadOrigin, BlakeTwo256, IdentityLookup},
    Perbill, Percent,
};
use staking_rewards::*;
use std::cell::RefCell;

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Module, Call, Config, Storage, Event<T>},
        Balances: balances::{Module, Call, Storage},
        PoAModule: poa::{Module, Call, Storage, Config<T>},
        StakingRewards: staking_rewards::{Module, Call, Storage, Event<T>},
    }
);

pallet_staking_reward_curve::build! {
    const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
        min_inflation: 0_025_000,
        max_inflation: 0_100_000,
        ideal_stake: 0_750_000,
        falloff: 0_050_000,
        max_piece_count: 40,
        test_precision: 0_005_000,
    );
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 21;
    pub const TreasuryRewardsPct: Percent = Percent::from_percent(60);
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
}

// For testing, setting `RewardDecayPct` this way so it can be changed during tests
thread_local! {
    static REWARD_DECAY_PCT: RefCell<Percent> = RefCell::new(Percent::from_percent(10));
}
pub struct RewardDecayPct;
impl RewardDecayPct {
    fn set(value: Percent) {
        REWARD_DECAY_PCT.with(|v| v.replace(value));
    }
}
impl Get<Percent> for RewardDecayPct {
    fn get() -> Percent {
        REWARD_DECAY_PCT.with(|v| *v.borrow())
    }
}

impl system::Config for Test {
    type BaseCallFilter = ();
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
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
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
}

impl balances::Config for Test {
    type Balance = u64;
    type DustRemoval = ();
    type Event = ();
    type ExistentialDeposit = ();
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
}

impl staking_rewards::Config for Test {
    type Event = ();
    type RewardDecayPct = RewardDecayPct;
    type TreasuryRewardsPct = TreasuryRewardsPct;
    type RewardCurve = RewardCurve;
}

impl poa::Config for Test {
    type Currency = Balances;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}

#[test]
fn test_supply_set_get() {
    new_test_ext().execute_with(|| {
        assert_eq!(StakingRewards::staking_emission_supply(), 0);
        StakingRewards::set_new_emission_supply(10_000);
        assert_eq!(StakingRewards::staking_emission_supply(), 10_000);
    })
}

#[test]
fn test_emission_status_set_get() {
    new_test_ext().execute_with(|| {
        assert_eq!(StakingRewards::staking_emission_status(), false);

        assert_noop!(
            StakingRewards::set_emission_status(Origin::signed(4), true),
            BadOrigin
        );
        assert_eq!(StakingRewards::staking_emission_status(), false);

        // Only root can enable/disable emissions
        assert_ok!(StakingRewards::set_emission_status(
            RawOrigin::Root.into(),
            true
        ));
        assert_eq!(StakingRewards::staking_emission_status(), true);

        assert_noop!(
            StakingRewards::set_emission_status(Origin::signed(5), false),
            BadOrigin
        );
        assert_eq!(StakingRewards::staking_emission_status(), true);
    })
}

#[test]
fn test_yearly_rewards() {
    // Test yearly rewards at different staking rates
    new_test_ext().execute_with(|| {
        fn t(emission_supply: u64, max_yearly_decay: u64) {
            let total_issuance = 100_000u64;
            let reward_curve = <Test as staking_rewards::Config>::RewardCurve::get();

            // No tokens staked
            let total_staked_zilch = 0;
            let npos_reward = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                &reward_curve,
                total_staked_zilch,
                total_issuance,
            );
            let npos_reward_prop = StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                &reward_curve,
                total_staked_zilch,
                total_issuance,
            );
            let yearly_rewards_at_no_staking = StakingRewards::get_yearly_emission_reward(
                &reward_curve,
                total_staked_zilch,
                total_issuance,
                emission_supply,
            );
            let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
            assert_eq!(Perbill::from_percent(25), npos_reward_prop);
            assert_eq!(Percent::from_percent(25) * emission_supply, npos_reward);
            assert_eq!(max_yearly_decay, max_yearly);
            assert_eq!(
                Percent::from_percent(25) * max_yearly_decay,
                yearly_rewards_at_no_staking
            );

            // 50% tokens staked
            let total_staked = 50_000;
            let npos_reward = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                &reward_curve,
                total_staked,
                total_issuance,
            );
            let npos_reward_prop = StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                &reward_curve,
                total_staked,
                total_issuance,
            );
            let yearly_rewards = StakingRewards::get_yearly_emission_reward(
                &reward_curve,
                total_staked,
                total_issuance,
                emission_supply,
            );
            let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
            assert_eq!(Perbill::from_percent(75u32), npos_reward_prop);
            assert_eq!(Percent::from_percent(75) * emission_supply, npos_reward);
            assert_eq!(max_yearly_decay, max_yearly);
            assert_eq!(Percent::from_percent(75) * max_yearly_decay, yearly_rewards);

            // Yearly rewards when some tokens are staked are greater than when no tokens staked.
            assert!(yearly_rewards > yearly_rewards_at_no_staking);

            // 75% tokens staked which yield the maximum reward as per the reward curve
            let total_staked_ideal = 75_000;
            let npos_reward_ideal = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                &reward_curve,
                total_staked_ideal,
                total_issuance,
            );
            let npos_reward_prop_ideal =
                StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                    &reward_curve,
                    total_staked_ideal,
                    total_issuance,
                );
            let yearly_rewards_idea_staking = StakingRewards::get_yearly_emission_reward(
                &reward_curve,
                total_staked_ideal,
                total_issuance,
                emission_supply,
            );
            let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
            // 75% is ideal stake as per reward curve
            assert_eq!(Perbill::from_percent(100u32), npos_reward_prop_ideal);
            assert_eq!(emission_supply, npos_reward_ideal);
            assert_eq!(max_yearly_decay, max_yearly);
            assert_eq!(max_yearly_decay, yearly_rewards_idea_staking);
            assert!(yearly_rewards_idea_staking > yearly_rewards);

            // 80% tokens staked which yield less than the maximum reward as rewards decrease if more
            // tokens than ideal staked
            let total_staked_sub_ideal = 80_000;
            let npos_reward = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                &reward_curve,
                total_staked_sub_ideal,
                total_issuance,
            );
            let npos_reward_prop = StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                &reward_curve,
                total_staked_sub_ideal,
                total_issuance,
            );
            let yearly_rewards_sub_ideal = StakingRewards::get_yearly_emission_reward(
                &reward_curve,
                total_staked_sub_ideal,
                total_issuance,
                emission_supply,
            );
            let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
            assert!(npos_reward_prop_ideal > npos_reward_prop);
            assert!(npos_reward_ideal > npos_reward);
            assert_eq!(max_yearly_decay, max_yearly);
            assert!(yearly_rewards_idea_staking > yearly_rewards_sub_ideal);

            // Yearly rewards when some tokens are staked are greater than when no tokens staked.
            assert!(yearly_rewards_sub_ideal > yearly_rewards_at_no_staking);
        }

        // Decay is set to 10%
        t(10_000, 10_000 / 10);

        // Decay is set to 20%
        <Test as Config>::RewardDecayPct::set(Percent::from_percent(20));
        t(10_000, 10_000 / 5);

        // Decay is set to 25%
        <Test as Config>::RewardDecayPct::set(Percent::from_percent(25));
        t(10_000, 10_000 / 4);

        // Decay is set to 50%
        <Test as Config>::RewardDecayPct::set(Percent::from_percent(50));
        t(10_000, 10_000 / 2);
    })
}

#[test]
fn test_yearly_rewards_with_increasing_staking() {
    // Test emission rewards as amount of staked tokens increase
    new_test_ext().execute_with(|| {
        let mut total_issuance = 100_000u64;
        let mut emission_supply = 10_000u64;
        let reward_curve = <Test as staking_rewards::Config>::RewardCurve::get();
        let decay_pct = <Test as staking_rewards::Config>::RewardDecayPct::get();

        for total_staked in (1000u64..=(total_issuance + emission_supply)).step_by(1000) {
            let npos_reward = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                &reward_curve,
                total_staked,
                total_issuance,
            );
            let npos_reward_prop = StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                &reward_curve,
                total_staked,
                total_issuance,
            );
            assert_eq!(
                Perbill::from_rational(npos_reward, reward_curve.maximum * total_issuance),
                npos_reward_prop
            );

            let yearly_rewards = StakingRewards::get_yearly_emission_reward(
                &reward_curve,
                total_staked,
                total_issuance,
                emission_supply,
            );
            let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
            assert!(
                yearly_rewards
                    <= Perbill::from_percent(decay_pct.deconstruct() as u32) * emission_supply
            );
            assert!(yearly_rewards <= max_yearly);
            assert_eq!(npos_reward_prop * max_yearly, yearly_rewards);

            emission_supply -= yearly_rewards;
            total_issuance += yearly_rewards;
        }
    })
}

#[test]
fn test_yearly_rewards_with_constant_staking() {
    // Test emission rewards with amount of staked tokens remaining constant
    new_test_ext().execute_with(|| {
        let reward_curve = <Test as staking_rewards::Config>::RewardCurve::get();
        let decay_pct = <Test as staking_rewards::Config>::RewardDecayPct::get();

        for total_staked in vec![10_000, 50_000, 75_000, 100_000] {
            let mut total_issuance = 100_000u64;
            let mut emission_supply = 10_000u64;
            let mut total_rewards = 0;
            loop {
                let npos_reward = StakingRewards::get_yearly_emission_reward_as_per_npos_only(
                    &reward_curve,
                    total_staked,
                    total_issuance,
                );
                let npos_reward_prop =
                    StakingRewards::get_yearly_emission_reward_prop_as_per_npos_only(
                        &reward_curve,
                        total_staked,
                        total_issuance,
                    );
                assert_eq!(
                    Perbill::from_rational(npos_reward, reward_curve.maximum * total_issuance),
                    npos_reward_prop
                );

                let yearly_rewards = StakingRewards::get_yearly_emission_reward(
                    &reward_curve,
                    total_staked,
                    total_issuance,
                    emission_supply,
                );
                let max_yearly = StakingRewards::get_max_yearly_emission(emission_supply);
                assert!(
                    yearly_rewards
                        <= Perbill::from_percent(decay_pct.deconstruct() as u32) * emission_supply
                );
                assert!(yearly_rewards <= max_yearly);
                assert_eq!(npos_reward_prop * max_yearly, yearly_rewards);

                if yearly_rewards == 0 {
                    break;
                }

                emission_supply -= yearly_rewards;
                total_issuance += yearly_rewards;
                total_rewards += yearly_rewards;
            }
            assert!(total_rewards > 0);
        }
    })
}

#[test]
fn test_emission_reward_for_era_given_yearly() {
    // Given yearly rewards, test for an era
    new_test_ext().execute_with(|| {
        let rewards = 100_000;

        // 100 eras in an year
        let one_pc_of_yearly_duration = MILLISECONDS_PER_YEAR / 100;
        assert_eq!(
            StakingRewards::get_emission_reward_for_era_given_yearly(
                one_pc_of_yearly_duration,
                rewards
            ),
            rewards / 100
        );

        // 50 eras in an year
        let two_pc_of_yearly_duration = MILLISECONDS_PER_YEAR / 50;
        assert_eq!(
            StakingRewards::get_emission_reward_for_era_given_yearly(
                two_pc_of_yearly_duration,
                rewards
            ),
            rewards / 50
        );

        // 10 eras in an year
        let ten_pc_of_yearly_duration = MILLISECONDS_PER_YEAR / 10;
        assert_eq!(
            StakingRewards::get_emission_reward_for_era_given_yearly(
                ten_pc_of_yearly_duration,
                rewards
            ),
            rewards / 10
        );

        // 2 eras in an year
        let fifty_pc_of_yearly_duration = MILLISECONDS_PER_YEAR / 2;
        assert_eq!(
            StakingRewards::get_emission_reward_for_era_given_yearly(
                fifty_pc_of_yearly_duration,
                rewards
            ),
            rewards / 2
        );
    })
}

#[test]
fn test_emission_rewards_0_when_disabled() {
    // There should be no emission rewards if emissions are disabled
    new_test_ext().execute_with(|| {
        StakingRewards::set_new_emission_supply(10_000);
        let reward_curve = <Test as staking_rewards::Config>::RewardCurve::get();

        // Emission is disabled so no emission rewards
        assert_eq!(StakingRewards::staking_emission_status(), false);
        let (rewards, remaining) =
            StakingRewards::emission_reward_for_era(&reward_curve, 1_000, 100_000, 300_000_000);
        assert_eq!(rewards, 0);
        assert_eq!(remaining, 10_000);

        // Emission is enabled so some emission rewards
        StakingRewards::set_emission_status(RawOrigin::Root.into(), true).unwrap();
        assert_eq!(StakingRewards::staking_emission_status(), true);
        let (rewards, remaining) =
            StakingRewards::emission_reward_for_era(&reward_curve, 1_000, 100_000, 300_000_000);
        assert!(rewards > 0);
        assert!(remaining < 10_000);
    })
}

#[test]
fn test_emission_rewards_in_era() {
    // Test emission rewards in era and use storage
    new_test_ext().execute_with(|| {
        let mut total_issuance = 100_000u64;
        let initial_emission_supply = 10_000;
        let reward_curve = <Test as staking_rewards::Config>::RewardCurve::get();

        StakingRewards::set_new_emission_supply(initial_emission_supply);
        StakingRewards::set_emission_status(RawOrigin::Root.into(), true).unwrap();

        let mut total_staked = 1000;
        let mut total_reward = 0;
        loop {
            // For running the test in reasonable time, era duration is 1/4 of a year
            let (emission_reward, remaining) = StakingRewards::emission_reward_for_era(
                reward_curve,
                total_staked,
                total_issuance,
                MILLISECONDS_PER_YEAR / 4,
            );
            if emission_reward == 0 {
                break;
            }
            StakingRewards::set_new_emission_supply(remaining);
            total_reward += emission_reward;
            total_issuance += total_reward;
            total_staked += 1000;
        }

        assert!(total_reward > 0);
        assert_eq!(
            initial_emission_supply - StakingRewards::staking_emission_supply(),
            total_reward
        );
    })
}

#[test]
fn test_era_payout() {
    // Test payout for an era and emission supply decreases
    new_test_ext().execute_with(|| {
        let mut total_issuance = 100_000u64;
        let mut emission_supply = 10_000;

        StakingRewards::set_new_emission_supply(emission_supply);
        StakingRewards::set_emission_status(RawOrigin::Root.into(), true).unwrap();

        let mut total_staked = 1000;
        let mut total_validator_reward = 0;
        let mut total_treasury_reward = 0;

        // Keep the total_staked increasing or decreasing but keep within min_staked and max_staked
        let mut stake_change_direction = true;
        let max_staked = 100_000;
        let min_staked = 10_000;

        // The following loop might continue for ever
        let mut iterations = 0;
        loop {
            if iterations == 10000 {
                break;
            }
            // For running the test in reasonable time, era duration is 1/4 of a year
            let (validator_reward, treasury_reward) =
                StakingRewards::era_payout(total_staked, total_issuance, MILLISECONDS_PER_YEAR / 4);
            let total_reward = validator_reward + treasury_reward;
            emission_supply -= total_reward;

            assert_eq!(StakingRewards::staking_emission_supply(), emission_supply);
            assert_eq!(
                <Test as staking_rewards::Config>::TreasuryRewardsPct::get() * total_reward,
                treasury_reward
            );

            total_validator_reward += validator_reward;
            total_treasury_reward += treasury_reward;
            total_issuance += total_reward;

            // Stake was increasing, now decrease
            if total_staked >= max_staked && stake_change_direction {
                stake_change_direction = false;
            }

            // Stake was decreasing, now increase
            if total_staked <= min_staked && !stake_change_direction {
                stake_change_direction = true;
            }

            if stake_change_direction {
                total_staked += 1000;
            } else {
                total_staked -= 1000;
            }

            iterations += 1;
        }

        assert!(total_validator_reward > 0);
        assert!(total_treasury_reward > 0);
    })
}

#[test]
fn test_initial_emission_supply_on_runtime_upgrade() {
    // Test emission supply can be set from PoA modules. This does not check `on_runtime_upgrade` directly
    // but the function called by `on_runtime_upgrade`.
    new_test_ext().execute_with(|| {
        let initial_emission_supply = 10_000;
        assert_eq!(StakingRewards::staking_emission_supply(), 0);
        assert_eq!(PoAModule::emission_supply(), 0);

        <poa::EmissionSupply<Test>>::put(initial_emission_supply);
        assert_eq!(PoAModule::emission_supply(), initial_emission_supply);
        // No emission supply for staking
        assert_eq!(StakingRewards::staking_emission_supply(), 0);

        /*// Emission supply should be set in staking and reset in PoA
        StakingRewards::set_emission_supply_from_poa();
        assert_eq!(
            StakingRewards::staking_emission_supply(),
            initial_emission_supply
        );
        assert_eq!(PoAModule::emission_supply(), 0);

        // Setting emission supply from poa again does not change supply in staking
        StakingRewards::set_emission_supply_from_poa();
        assert_eq!(
            StakingRewards::staking_emission_supply(),
            initial_emission_supply
        );
        assert_eq!(PoAModule::emission_supply(), 0);*/
    })
}
