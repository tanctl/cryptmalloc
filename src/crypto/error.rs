use std::fmt;

use crate::crypto::tfhe_context::TfheContextError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    ContextMismatch,
    NoiseBudgetExceeded {
        consumed: usize,
        capacity: usize,
        required: usize,
    },
    Overflow {
        operation: &'static str,
    },
    InvalidCiphertext(&'static str),
    Context(TfheContextError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextMismatch => write!(f, "ciphertexts originate from different contexts"),
            Self::NoiseBudgetExceeded {
                consumed,
                capacity,
                required,
            } => write!(
                f,
                "noise budget exceeded: consumed {consumed} of {capacity}, requires {required}"
            ),
            Self::Overflow { operation } => {
                write!(f, "{operation} would overflow the ciphertext modulus")
            }
            Self::InvalidCiphertext(msg) => write!(f, "invalid ciphertext: {msg}"),
            Self::Context(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<TfheContextError> for CryptoError {
    fn from(value: TfheContextError) -> Self {
        Self::Context(value)
    }
}
