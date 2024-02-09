#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unused_unit)]

pub use dock_poa::BalanceOf;
use frame_support::{
    traits::Get,
    weights::{Pays, Weight},
};
use frame_system::ensure_root;
pub use pallet::*;
use pallet_staking::EraPayout;
use sp_runtime::{
    curve::PiecewiseLinear,
    traits::{Saturating, Zero},
    Perbill, Percent,
};

pub use types::*;

pub mod runtime_api;
pub mod types;

#[cfg(test)]
mod tests;

// Milliseconds per year for the Julian year (365.25 days).
pub const MILLISECONDS_PER_YEAR: u64 = 1000 * 3600 * 24 * 36525 / 100;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::{ValueQuery, *};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config + dock_poa::Config {
        /// The overarching event type.
        type Event: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::Event>
            + Into<<Self as frame_system::Config>::Event>;
        /// Optional duration in eras for high-rate rewards to be paid after the upgrade.
        /// High-rate rewards will become active at the beginning of the next sequential era.
        type PostUpgradeHighRateDuration: Get<Option<DurationInEras>>;
        /// The percentage by which remaining emission supply decreases
        type LowRateRewardDecayPct: Get<Percent>;
        /// High rate percentage by which remaining emission supply decreases. Only used during `PostUpgradeHighRateDuration`.
        type HighRateRewardDecayPct: Get<Percent>;
        /// The percentage of rewards going to treasury
        #[pallet::constant]
        type TreasuryRewardsPct: Get<Percent>;
        /// The NPoS reward curve where the first 2 points (of `points` field) correspond to the lowest
        ///and highest inflation and the subsequent points correspond to decreasing inflation
        type RewardCurve: Get<&'static PiecewiseLinear<'static>>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super)fn deposit_event)]
    pub enum Event<T: Config> {
        /// Rewards emitted and remaining
        EmissionRewards(BalanceOf<T>, BalanceOf<T>),
        /// Emission supply moved from PoA module to this module
        // TODO: This event is not getting emitted maybe because it happens during runtime upgrade
        EmissionSupplyTakenFromPoA(BalanceOf<T>),
    }

    /// Remaining emission supply. This reduces after each era as emissions happen unless
    /// emissions are disabled. Name is intentionally kept different from `EmissionSupply` from
    /// dock_poa module.
    #[pallet::storage]
    #[pallet::getter(fn staking_emission_supply)]
    pub type StakingEmissionSupply<T> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Boolean flag determining whether to generate emission rewards or not. Name is intentionally
    /// kept different from `EmissionStatus` from dock_poa module.
    #[pallet::storage]
    #[pallet::getter(fn staking_emission_status)]
    pub type StakingEmissionStatus<T> = StorageValue<_, bool, ValueQuery>;

    /// Current state of the high-rate rewards.
    #[pallet::storage]
    #[pallet::getter(fn high_rate_rewards)]
    pub type HighRateRewards<T> = StorageValue<_, HighRateRewardsState, ValueQuery>;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Enable/disable emission rewards by calling this function with true or false respectively.
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn set_emission_status(
            origin: OriginFor<T>,
            status: bool,
        ) -> DispatchResultWithPostInfo {
            ensure_root(origin)?;
            StakingEmissionStatus::<T>::put(status);

            Ok(Pays::No.into())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            if let Some(duration) = T::PostUpgradeHighRateDuration::get() {
                HighRateRewards::<T>::mutate(|rewards_state| {
                    rewards_state.inc_duration_or_init(duration)
                });

                T::DbWeight::get().reads_writes(1, 1)
            } else {
                Weight::zero()
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// This function can fetch `total_staked` and `total_issuance` from storage but that would make this pallet dependent on staking pallet
    pub fn yearly_emission(
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
    ) -> BalanceOf<T> {
        Self::get_yearly_emission_reward(
            T::RewardCurve::get(),
            total_staked,
            total_issuance,
            Self::staking_emission_supply(),
        )
    }

    pub fn max_yearly_emission() -> BalanceOf<T> {
        Self::get_max_yearly_emission(Self::staking_emission_supply())
    }

    // TODO: Needed as RPC?
    /// Compute emission reward of an era. It considers the remaining emission supply and the decay in
    /// addition to NPoS inflation. Returns the emission reward and the reduced emission supply after
    /// emitting the rewards.
    fn emission_reward_for_era(
        reward_curve: &PiecewiseLinear,
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
        era_duration_millis: u64,
    ) -> (BalanceOf<T>, BalanceOf<T>) {
        let emission_supply = Self::staking_emission_supply();
        if !Self::staking_emission_status() {
            return (BalanceOf::<T>::zero(), emission_supply);
        }

        // Emission reward for the whole year
        let yearly_rewards = Self::get_yearly_emission_reward(
            reward_curve,
            total_staked,
            total_issuance,
            emission_supply,
        );

        // Emission reward for the era
        let emission_reward =
            Self::get_emission_reward_for_era_given_yearly(era_duration_millis, yearly_rewards);

        let remaining = emission_supply.saturating_sub(emission_reward);
        (emission_reward, remaining)
    }

    // TODO: Needed as RPC?
    /// Get yearly emission reward as per NPoS and remaining emission supply. The reward is taken
    /// from remaining emission supply and is proportional to the ratio of current NPoS inflation to
    /// maximum NPoS inflation
    fn get_yearly_emission_reward(
        reward_curve: &PiecewiseLinear,
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
        emission_supply: BalanceOf<T>,
    ) -> BalanceOf<T> {
        let reward_proportion_of_max = Self::get_yearly_emission_reward_prop_as_per_npos_only(
            reward_curve,
            total_staked,
            total_issuance,
        );
        let yearly_emission = Self::get_max_yearly_emission(emission_supply);
        reward_proportion_of_max * yearly_emission
    }

    /// Get proportion of NPoS emission as per current staking rate (`total_staked` / `total_issuance`) to
    /// emission as per ideal staking rate. Doesn't consider remaining emission supply
    fn get_yearly_emission_reward_prop_as_per_npos_only(
        reward_curve: &PiecewiseLinear,
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
    ) -> Perbill {
        let reward_as_per_npos = Self::get_yearly_emission_reward_as_per_npos_only(
            reward_curve,
            total_staked,
            total_issuance,
        );

        Perbill::from_rational(reward_as_per_npos, reward_curve.maximum * total_issuance)
    }

    /// Get emission per year according to NPoS as described in token economics doc here
    /// https://research.web3.foundation/en/latest/polkadot/overview/2-token-economics.html. Doesn't
    /// consider remaining emission supply
    fn get_yearly_emission_reward_as_per_npos_only(
        reward_curve: &PiecewiseLinear,
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
    ) -> BalanceOf<T> {
        reward_curve.calculate_for_fraction_times_denominator(total_staked, total_issuance)
    }

    /// The percentage by which remaining emission supply decreases.
    pub fn reward_decay_pct() -> Percent {
        // We need to check if high-rate rewards are enabled.
        Self::high_rate_rewards()
            .is_active()
            .then(T::HighRateRewardDecayPct::get)
            .unwrap_or_else(T::LowRateRewardDecayPct::get)
    }

    /// Get maximum emission per year according to the decay percentage and given emission supply
    fn get_max_yearly_emission(emission_supply: BalanceOf<T>) -> BalanceOf<T> {
        // Emission supply decreases by "decay percentage" of the remaining emission supply per year
        Self::reward_decay_pct() * emission_supply
    }

    /// Given yearly emission rewards, calculate for an era.
    fn get_emission_reward_for_era_given_yearly(
        era_duration_millis: u64,
        yearly_rewards: BalanceOf<T>,
    ) -> BalanceOf<T> {
        // Ratio of milliseconds in an era to milliseconds in an year
        let portion = Perbill::from_rational(era_duration_millis, MILLISECONDS_PER_YEAR);
        portion * yearly_rewards
    }

    /// Set emission supply. Used to set the reduced supply after emitting rewards
    fn set_new_emission_supply(supply: BalanceOf<T>) {
        <StakingEmissionSupply<T>>::put(supply)
    }
}

impl<T: Config> EraPayout<BalanceOf<T>> for Pallet<T> {
    /// Compute era payout for validators and treasury and reduce the remaining emission supply.
    /// It is assumed and expected that this is called only when a payout of an era has to computed
    /// and isn't called twice for the same era as it has a side-effect (reducing remaining supply
    /// and transitioning the high-rate rewards state).
    /// Currently, it doesn't seem possible to avoid this side effect as there is no way for this pallet
    /// to be notified if an era payout was successfully done.
    fn era_payout(
        total_staked: BalanceOf<T>,
        total_issuance: BalanceOf<T>,
        era_duration_millis: u64,
    ) -> (BalanceOf<T>, BalanceOf<T>) {
        let reward_curve = T::RewardCurve::get();
        let (emission_reward, remaining) = Self::emission_reward_for_era(
            reward_curve,
            total_staked,
            total_issuance,
            era_duration_millis,
        );
        Self::deposit_event(Event::EmissionRewards(emission_reward, remaining));

        let result = if emission_reward.is_zero() {
            (BalanceOf::<T>::zero(), BalanceOf::<T>::zero())
        } else {
            Self::set_new_emission_supply(remaining);
            let treasury_reward = T::TreasuryRewardsPct::get() * emission_reward;
            (
                emission_reward.saturating_sub(treasury_reward),
                treasury_reward,
            )
        };

        let _ = HighRateRewards::<T>::try_mutate(HighRateRewardsState::try_next);

        result
    }
}
