use core::{fmt::Debug, num::NonZeroU16};

use scale_info::TypeInfo;

/// Non-zero amount of eras used to express duration.
#[derive(codec::Encode, codec::Decode, Eq, PartialEq, Clone, Copy, Debug, TypeInfo)]
pub struct DurationInEras(pub NonZeroU16);

impl DurationInEras {
    /// Instantiates `DurationInEras` using supplied *non-zero* count.
    /// # Panics
    /// If the count is equal to zero.
    pub const fn new_non_zero(count: u16) -> Self {
        if count == 0 {
            panic!("`DurationInEras` can't be equal to zero")
        }

        Self(unsafe { NonZeroU16::new_unchecked(count) })
    }
}

/// Denotes the current state of the high-rate rewards.
#[derive(codec::Encode, codec::Decode, Eq, PartialEq, Clone, Copy, Debug, TypeInfo)]
pub enum HighRateRewardsState {
    /// High-rate rewards are disabled.
    None,
    /// High-rate rewards will start in the next era and last for `duration` eras.
    StartingInNextEra { duration: DurationInEras },
    /// High-rate rewards are currently active and will end after `ends_after` eras.
    Active { ends_after: DurationInEras },
}

impl HighRateRewardsState {
    /// Attempts to switch `Self` to the next state returning next `Ok(Self)` on update and `Err(Self)` if nothing was changed.
    /// Returned `Self` is the copy of the final value.
    ///
    /// This function defines the following transitions:
    /// - High-rate rewards were activated.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const TWO_ERAS: DurationInEras = DurationInEras::new_non_zero(2);
    /// # assert_eq!(
    /// HighRateRewardsState::StartingInNextEra { duration: TWO_ERAS }.try_next(), /* => */ Ok(HighRateRewardsState::Active { ends_after: TWO_ERAS })
    /// # );
    /// ```
    /// - High-rate rewards passed one more era, so the remaining amount is decreased by 1.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const TWO_ERAS: DurationInEras = DurationInEras::new_non_zero(2);
    /// # const ONE_ERA: DurationInEras = DurationInEras::new_non_zero(1);
    /// # assert_eq!(
    /// HighRateRewardsState::Active { ends_after: TWO_ERAS }.try_next(), /* => */ Ok(HighRateRewardsState::Active { ends_after: ONE_ERA })
    /// # );
    /// ```
    /// - High-rate rewards ended, switching back to the default state.
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const ONE_ERA: DurationInEras = DurationInEras::new_non_zero(1);
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
            HighRateRewardsState::StartingInNextEra { duration } => HighRateRewardsState::Active {
                ends_after: duration,
            },
            HighRateRewardsState::Active {
                ends_after: DurationInEras(ends_after),
            } => ends_after
                .get()
                .checked_sub(1)
                .and_then(NonZeroU16::new)
                .map(DurationInEras)
                .map_or(HighRateRewardsState::None, |ends_after| {
                    HighRateRewardsState::Active { ends_after }
                }),
            _ => return Err(*self),
        };

        Ok(*self)
    }

    /// Increments duration of `Self` using supplied amount returning copied `Self`.
    /// If `Self` is `None`, it will be replaced by `StartingInNextEra` with the given duration.
    /// Overflow will be adjusted to the upper bound - `u16::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use staking_rewards::{HighRateRewardsState, DurationInEras};
    /// # const THREE_ERAS: DurationInEras = DurationInEras::new_non_zero(3);
    /// # const TWO_ERAS: DurationInEras = DurationInEras::new_non_zero(2);
    /// # const ONE_ERA: DurationInEras = DurationInEras::new_non_zero(1);
    /// # assert_eq!(
    /// HighRateRewardsState::StartingInNextEra { duration: ONE_ERA }.inc_duration_or_init(TWO_ERAS), /* => */ HighRateRewardsState::StartingInNextEra { duration: THREE_ERAS }
    /// # );
    ///
    /// # assert_eq!(
    /// HighRateRewardsState::Active { ends_after: ONE_ERA }.inc_duration_or_init(TWO_ERAS), /* => */ HighRateRewardsState::Active { ends_after: THREE_ERAS }
    /// # );
    ///
    /// # assert_eq!(
    /// HighRateRewardsState::None.inc_duration_or_init(TWO_ERAS), /* => */ HighRateRewardsState::StartingInNextEra { duration: TWO_ERAS }
    /// # );
    /// ```
    pub fn inc_duration_or_init(&mut self, inc_duration: DurationInEras) -> Self {
        match self {
            HighRateRewardsState::StartingInNextEra {
                duration: DurationInEras(duration),
            }
            | HighRateRewardsState::Active {
                ends_after: DurationInEras(duration),
            } => {
                let DurationInEras(increment) = inc_duration;
                *duration = duration.saturating_add(increment.get());
            }
            HighRateRewardsState::None => {
                *self = HighRateRewardsState::StartingInNextEra {
                    duration: inc_duration,
                }
            }
        }
        *self
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
