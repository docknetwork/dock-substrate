#![cfg_attr(not(feature = "std"), no_std)]

use core::{fmt::Debug, num::NonZeroU32};

use frame_support::{
    decl_event, decl_module, decl_storage, dispatch,
    traits::Get,
    weights::{Pays, Weight},
};
use frame_system::{self as system, ensure_root};
use pallet_staking::EraPayout;
pub use poa::BalanceOf;
use sp_runtime::{
    curve::PiecewiseLinear,
    traits::{Saturating, Zero},
    Perbill, Percent,
};

pub mod runtime_api;

#[cfg(test)]
mod tests;

// Milliseconds per year for the Julian year (365.25 days).
const MILLISECONDS_PER_YEAR: u64 = 1000 * 3600 * 24 * 36525 / 100;

/// Non-zero amount of eras used to express duration.
#[derive(codec::Encode, codec::Decode, Eq, PartialEq, Clone, Copy, Debug)]
pub struct DurationInEras(pub NonZeroU32);

impl DurationInEras {
    /// Instantiates `DurationInEras` using supplied *non-zero* count.
    /// # Panics
    /// If the count is equal to zero.
    pub const fn new(count: u32) -> Self {
        if count == 0 {
            panic!("`DurationInEras` can't be equal to zero")
        }

        Self(unsafe { NonZeroU32::new_unchecked(count) })
    }
}

pub trait Config: system::Config + poa::Config {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;
    /// Optional duration in eras for high-rate rewards to be paid after the upgrade.
    /// High-rate rewards will become active at the beginning of the next sequential era.
    type PostUpgradeHighRateDuration: Get<Option<DurationInEras>>;
    /// The percentage by which remaining emission supply decreases
    type LowRateRewardDecayPct: Get<Percent>;
    /// High rate percentage by which remaining emission supply decreases. Only used during `PostUpgradeHighRateDuration`.
    type HighRateRewardDecayPct: Get<Percent>;
    /// The percentage of rewards going to treasury
    type TreasuryRewardsPct: Get<Percent>;
    /// The NPoS reward curve where the first 2 points (of `points` field) correspond to the lowest
    ///and highest inflation and the subsequent points correspond to decreasing inflation
    type RewardCurve: Get<&'static PiecewiseLinear<'static>>;
}

decl_storage! {
    trait Store for Module<T: Config> as StakingRewards {
        /// Remaining emission supply. This reduces after each era as emissions happen unless
        /// emissions are disabled. Name is intentionally kept different from `EmissionSupply` from
        /// poa module.
        StakingEmissionSupply get(fn staking_emission_supply): BalanceOf<T>;

        /// Boolean flag determining whether to generate emission rewards or not. Name is intentionally
        /// kept different from `EmissionStatus` from poa module.
        StakingEmissionStatus get(fn staking_emission_status): bool;

        /// Current state of the high-rate rewards.
        HighRateRewards get(fn high_rate_rewards): HighRateRewardsState;
    }
}

/// Denotes the current state of the high-rate rewards.
#[derive(codec::Encode, codec::Decode, Eq, PartialEq, Clone, Copy, Debug)]
pub enum HighRateRewardsState {
    /// High-rate rewards are disabled.
    None,
    /// High-rate rewards will start in the next era and last for `duration` eras.
    WaitingForNextEra { duration: DurationInEras },
    /// High-rate rewards are currently active and will end after `ends_after` eras.
    Active { ends_after: DurationInEras },
}

impl HighRateRewardsState {
    /// Attempts to switch `Self` to the next state returning next `Ok(Self)` on update and `Err(Self)` if nothing was changed.
    ///
    /// This function defines the following transitions:
    /// - High-rate rewards were activated.
    /// ```rust
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const TWO_ERAS: DurationInEras = DurationInEras::new(2);
    /// # assert_eq!(
    /// HighRateRewardsState::WaitingForNextEra { duration: TWO_ERAS }.try_next(), /* => */ Ok(HighRateRewardsState::Active { ends_after: TWO_ERAS })
    /// # );
    /// ```
    /// - High-rate rewards passed one more era, so the remaining amount is decreased by 1.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const TWO_ERAS: DurationInEras = DurationInEras::new(2);
    /// # const ONE_ERA: DurationInEras = DurationInEras::new(1);
    /// # assert_eq!(
    /// HighRateRewardsState::Active { ends_after: TWO_ERAS }.try_next(), /* => */ Ok(HighRateRewardsState::Active { ends_after: ONE_ERA })
    /// # );
    /// ```
    /// - High-rate rewards ended, switching back to the default state.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const ONE_ERA: DurationInEras = DurationInEras::new(1);
    /// # assert_eq!(
    /// HighRateRewardsState::Active { ends_after: ONE_ERA }.try_next(), /* => */ Ok(HighRateRewardsState::None)
    /// # );
    /// ```
    /// - No state transition for the default state.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState};
    /// # assert_eq!(
    /// HighRateRewardsState::None.try_next(), /* => */ Err(HighRateRewardsState::None)
    /// # );
    /// ```
    pub fn try_next(&mut self) -> Result<Self, Self> {
        *self = match *self {
            HighRateRewardsState::WaitingForNextEra { duration } => HighRateRewardsState::Active {
                ends_after: duration,
            },
            HighRateRewardsState::Active {
                ends_after: DurationInEras(ends_after),
            } => ends_after
                .get()
                .checked_sub(1)
                .and_then(NonZeroU32::new)
                .map(DurationInEras)
                .map_or(HighRateRewardsState::None, |ends_after| {
                    HighRateRewardsState::Active { ends_after }
                }),
            _ => return Err(*self),
        };

        Ok(*self)
    }

    /// Checks if the given `HighRateRewardsState` is in the `Active` phase.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

impl Default for HighRateRewardsState {
    fn default() -> Self {
        Self::None
    }
}

decl_event!(
    pub enum Event<T>
    where
        Balance = BalanceOf<T>,
    {
        /// Rewards emitted and remaining
        EmissionRewards(Balance, Balance),
        /// Emission supply moved from PoA module to this module
        // TODO: This event is not getting emitted maybe because it happens during runtime upgrade
        EmissionSupplyTakenFromPoA(Balance),
    }
);

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        /// The percentage of rewards going to treasury
        const TreasuryRewardsPct: Percent = T::TreasuryRewardsPct::get();

        fn deposit_event() = default;

        /// Enable/disable emission rewards by calling this function with true or false respectively.
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_emission_status(origin, status: bool) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            StakingEmissionStatus::put(status);
            Ok(Pays::No.into())
        }

        fn on_runtime_upgrade() -> Weight {
            if let Some(duration) = T::PostUpgradeHighRateDuration::get() {
                HighRateRewards::put(
                    HighRateRewardsState::WaitingForNextEra { duration }
                );

                T::DbWeight::get().writes(1)
            } else {
                Weight::zero()
            }
        }
    }
}

impl<T: Config> Module<T> {
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
        let reward_proportion_of_max =
            Perbill::from_rational(reward_as_per_npos, reward_curve.maximum * total_issuance);
        reward_proportion_of_max
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

impl<T: Config> EraPayout<BalanceOf<T>> for Module<T> {
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
        Self::deposit_event(RawEvent::EmissionRewards(emission_reward, remaining));

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

        let _ = HighRateRewards::try_mutate(HighRateRewardsState::try_next);

        result
    }
}
