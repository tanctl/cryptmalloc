use serde::{Deserialize, Serialize};
use std::fmt;

use tfhe::FheBool;

use crate::crypto::error::CryptoError;
use crate::crypto::noise::NoiseState;
use crate::crypto::tfhe_context::{TfheContext, TfheContextError};

fn default_context() -> TfheContext {
    TfheContext::balanced().expect("context initialization")
}

fn zero_noise() -> NoiseState {
    NoiseState::zero()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedBool {
    inner: FheBool,
    #[serde(skip, default = "default_context")]
    context: TfheContext,
    #[serde(skip, default = "zero_noise")]
    noise: NoiseState,
}

impl EncryptedBool {
    pub fn encrypt(value: bool, context: &TfheContext) -> Result<Self, TfheContextError> {
        let inner = context.encrypt_bool(value)?;
        let capacity = context.noise_capacity()?;
        Ok(Self {
            inner,
            context: context.clone(),
            noise: NoiseState::new(capacity),
        })
    }

    pub(crate) fn from_parts(inner: FheBool, context: &TfheContext, noise: NoiseState) -> Self {
        Self {
            inner,
            context: context.clone(),
            noise,
        }
    }

    pub(crate) fn noise(&self) -> &NoiseState {
        &self.noise
    }

    #[must_use]
    pub fn context(&self) -> &TfheContext {
        &self.context
    }

    #[must_use]
    pub fn noise_state(&self) -> NoiseState {
        self.noise
    }

    pub fn decrypt(&self) -> Result<bool, TfheContextError> {
        self.context.decrypt_bool(&self.inner)
    }

    pub fn decrypt_with(&self, context: &TfheContext) -> Result<bool, TfheContextError> {
        context.decrypt_bool(&self.inner)
    }

    #[must_use]
    pub fn inner(&self) -> &FheBool {
        &self.inner
    }

    #[must_use]
    pub fn into_inner(self) -> FheBool {
        self.inner
    }

    pub(crate) fn ensure_same_context(&self, other: &Self) -> Result<(), CryptoError> {
        if self.context.ptr_eq(&other.context) {
            Ok(())
        } else {
            Err(CryptoError::ContextMismatch)
        }
    }
}

impl fmt::Debug for EncryptedBool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedBool")
            .field("noise", &self.noise)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EncryptedBool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedBool(noise={})", self.noise)
    }
}
