use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowId(u64);

impl WindowId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<WindowId> for u64 {
    fn from(value: WindowId) -> Self {
        value.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundId(u32);

impl RoundId {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRoundId;

impl fmt::Display for InvalidRoundId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("round ID must be greater than zero")
    }
}

impl Error for InvalidRoundId {}

impl TryFrom<u32> for RoundId {
    type Error = InvalidRoundId;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(InvalidRoundId);
        }

        Ok(Self(value))
    }
}

impl From<RoundId> for u32 {
    fn from(value: RoundId) -> Self {
        value.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MainRoundContext {
    window: WindowId,
    round: RoundId,
}

impl MainRoundContext {
    pub const fn new(window: WindowId, round: RoundId) -> Self {
        Self { window, round }
    }

    pub const fn window(self) -> WindowId {
        self.window
    }

    pub const fn round(self) -> RoundId {
        self.round
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundStatus {
    Open,
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundLifecycleError {
    UnexpectedContext {
        expected: MainRoundContext,
        received: MainRoundContext,
    },
    AlreadyFinalized(MainRoundContext),
    RoundStillOpen(MainRoundContext),
    NonIncreasingContext {
        current: MainRoundContext,
        next: MainRoundContext,
    },
}

impl fmt::Display for RoundLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedContext { expected, received } => write!(
                formatter,
                "received context {:?}, expected {:?}",
                received, expected
            ),
            Self::AlreadyFinalized(context) => {
                write!(formatter, "round {:?} is already finalized", context)
            }
            Self::RoundStillOpen(context) => {
                write!(formatter, "round {:?} is still open", context)
            }
            Self::NonIncreasingContext { current, next } => write!(
                formatter,
                "next context {:?} must be later than current context {:?}",
                next, current
            ),
        }
    }
}

impl Error for RoundLifecycleError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoundLifecycle {
    current: MainRoundContext,
    status: RoundStatus,
}

impl RoundLifecycle {
    pub const fn new(current: MainRoundContext) -> Self {
        Self {
            current,
            status: RoundStatus::Open,
        }
    }

    pub const fn current(self) -> MainRoundContext {
        self.current
    }

    pub const fn status(self) -> RoundStatus {
        self.status
    }

    pub fn ensure_open(&self, received: MainRoundContext) -> Result<(), RoundLifecycleError> {
        if received != self.current {
            return Err(RoundLifecycleError::UnexpectedContext {
                expected: self.current,
                received,
            });
        }

        if self.status == RoundStatus::Finalized {
            return Err(RoundLifecycleError::AlreadyFinalized(self.current));
        }

        Ok(())
    }

    pub fn finalize(&mut self, received: MainRoundContext) -> Result<(), RoundLifecycleError> {
        self.ensure_open(received)?;
        self.status = RoundStatus::Finalized;
        Ok(())
    }

    pub fn advance_to(&mut self, next: MainRoundContext) -> Result<(), RoundLifecycleError> {
        if self.status == RoundStatus::Open {
            return Err(RoundLifecycleError::RoundStillOpen(self.current));
        }

        if next <= self.current {
            return Err(RoundLifecycleError::NonIncreasingContext {
                current: self.current,
                next,
            });
        }

        self.current = next;
        self.status = RoundStatus::Open;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(window: u64, round: u32) -> MainRoundContext {
        MainRoundContext::new(WindowId::new(window), RoundId::try_from(round).unwrap())
    }

    #[test]
    fn window_id_preserves_its_value() {
        let window = WindowId::new(12);

        assert_eq!(window.get(), 12);
        assert_eq!(u64::from(window), 12);
    }

    #[test]
    fn round_id_accepts_positive_values() {
        let round = RoundId::try_from(7).unwrap();

        assert_eq!(round.get(), 7);
        assert_eq!(u32::from(round), 7);
    }

    #[test]
    fn round_id_rejects_zero() {
        assert_eq!(RoundId::try_from(0), Err(InvalidRoundId));
    }

    #[test]
    fn main_round_context_keeps_window_and_round_together() {
        let window = WindowId::new(12);
        let round = RoundId::try_from(3).unwrap();

        let context = MainRoundContext::new(window, round);

        assert_eq!(context.window(), window);
        assert_eq!(context.round(), round);
    }

    #[test]
    fn lifecycle_starts_open() {
        let current = context(1, 1);
        let lifecycle = RoundLifecycle::new(current);

        assert_eq!(lifecycle.current(), current);
        assert_eq!(lifecycle.status(), RoundStatus::Open);
        assert_eq!(lifecycle.ensure_open(current), Ok(()));
    }

    #[test]
    fn lifecycle_rejects_another_context() {
        let lifecycle = RoundLifecycle::new(context(1, 2));

        assert_eq!(
            lifecycle.ensure_open(context(1, 1)),
            Err(RoundLifecycleError::UnexpectedContext {
                expected: context(1, 2),
                received: context(1, 1),
            })
        );

        assert_eq!(
            lifecycle.ensure_open(context(1, 3)),
            Err(RoundLifecycleError::UnexpectedContext {
                expected: context(1, 2),
                received: context(1, 3),
            })
        );
    }

    #[test]
    fn lifecycle_finalizes_a_round_only_once() {
        let current = context(1, 1);
        let mut lifecycle = RoundLifecycle::new(current);

        assert_eq!(lifecycle.finalize(current), Ok(()));
        assert_eq!(lifecycle.status(), RoundStatus::Finalized);

        assert_eq!(
            lifecycle.finalize(current),
            Err(RoundLifecycleError::AlreadyFinalized(current))
        );
    }

    #[test]
    fn lifecycle_cannot_advance_while_current_round_is_open() {
        let current = context(1, 1);
        let mut lifecycle = RoundLifecycle::new(current);

        assert_eq!(
            lifecycle.advance_to(context(1, 2)),
            Err(RoundLifecycleError::RoundStillOpen(current))
        );
    }

    #[test]
    fn lifecycle_can_advance_after_finalization() {
        let current = context(1, 1);
        let next = context(1, 2);
        let mut lifecycle = RoundLifecycle::new(current);

        lifecycle.finalize(current).unwrap();
        lifecycle.advance_to(next).unwrap();

        assert_eq!(lifecycle.current(), next);
        assert_eq!(lifecycle.status(), RoundStatus::Open);
        assert_eq!(lifecycle.ensure_open(next), Ok(()));
    }

    #[test]
    fn lifecycle_rejects_reusing_an_old_context() {
        let current = context(1, 2);
        let mut lifecycle = RoundLifecycle::new(current);

        lifecycle.finalize(current).unwrap();

        assert_eq!(
            lifecycle.advance_to(context(1, 1)),
            Err(RoundLifecycleError::NonIncreasingContext {
                current,
                next: context(1, 1),
            })
        );
    }

    #[test]
    fn lifecycle_can_enter_a_new_window_at_round_one() {
        let current = context(1, 6);
        let next = context(2, 1);
        let mut lifecycle = RoundLifecycle::new(current);

        lifecycle.finalize(current).unwrap();
        lifecycle.advance_to(next).unwrap();

        assert_eq!(lifecycle.current(), next);
        assert_eq!(lifecycle.status(), RoundStatus::Open);
    }
}
