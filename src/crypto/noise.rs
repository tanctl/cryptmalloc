use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::error::CryptoError;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseState {
    consumed: usize,
    capacity: usize,
}

impl NoiseState {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            consumed: 0,
            capacity,
        }
    }

    #[must_use]
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.consumed)
    }

    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn consume(&mut self, amount: usize) -> Result<(), CryptoError> {
        if amount == 0 {
            return Ok(());
        }

        let required = self.consumed.saturating_add(amount);
        if required > self.capacity {
            return Err(CryptoError::NoiseBudgetExceeded {
                consumed: self.consumed,
                capacity: self.capacity,
                required: amount,
            });
        }

        self.consumed = required;
        Ok(())
    }

    pub fn merge(lhs: &Self, rhs: &Self, cost: usize) -> Result<Self, CryptoError> {
        if lhs.capacity != rhs.capacity {
            return Err(CryptoError::NoiseBudgetExceeded {
                consumed: lhs.consumed.max(rhs.consumed),
                capacity: lhs.capacity.min(rhs.capacity),
                required: cost,
            });
        }

        let mut merged = Self {
            consumed: lhs.consumed.max(rhs.consumed),
            capacity: lhs.capacity,
        };
        merged.consume(cost)?;
        Ok(merged)
    }
}

impl fmt::Debug for NoiseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseState")
            .field("consumed", &self.consumed)
            .field("capacity", &self.capacity)
            .field("remaining", &self.remaining())
            .finish()
    }
}

impl fmt::Display for NoiseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} / {} (remaining: {})",
            self.consumed,
            self.capacity,
            self.remaining()
        )
    }
}
