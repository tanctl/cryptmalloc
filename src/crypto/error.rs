use thiserror::Error;

use crate::crypto::tfhe_context::TfheContextError;

#[derive(Debug, Error, Clone)]
#[error("overflow during {operation}")]
pub struct OverflowError {
    pub operation: &'static str,
}

impl OverflowError {
    pub const fn new(operation: &'static str) -> Self {
        Self { operation }
    }
}

#[derive(Debug, Error, Clone)]
#[error("invalid operation: {reason}")]
pub struct InvalidOperationError {
    pub reason: &'static str,
}

impl InvalidOperationError {
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

#[derive(Debug, Error, Clone)]
pub enum CryptoError {
    #[error("ciphertexts originate from different contexts")]
    ContextMismatch,
    #[error("noise budget exceeded: consumed {consumed} of {capacity}, requires {required}")]
    NoiseBudgetExceeded {
        consumed: usize,
        capacity: usize,
        required: usize,
    },
    #[error(transparent)]
    Overflow(#[from] OverflowError),
    #[error(transparent)]
    InvalidOperation(#[from] InvalidOperationError),
    #[error("serialization failure: {0}")]
    Serialization(String),
    #[error(transparent)]
    Context(#[from] TfheContextError),
}
