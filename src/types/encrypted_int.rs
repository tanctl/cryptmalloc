use std::fmt;

use tfhe::{FheUint16, FheUint32, FheUint8};

use crate::crypto::error::CryptoError;
use crate::crypto::noise::NoiseState;
use crate::crypto::tfhe_context::{TfheContext, TfheContextError};

macro_rules! encrypted_uint {
    (
        $wrapper:ident,
        $cipher:ty,
        $value:ty,
        $encrypt_method:ident,
        $decrypt_method:ident
    ) => {
        #[derive(Clone)]
        pub struct $wrapper {
            inner: $cipher,
            context: TfheContext,
            noise: NoiseState,
        }

        impl $wrapper {
            pub fn encrypt(value: $value, context: &TfheContext) -> Result<Self, TfheContextError> {
                let cipher = context.$encrypt_method(value)?;
                let capacity = context.noise_capacity()?;

                Ok(Self {
                    inner: cipher,
                    context: context.clone(),
                    noise: NoiseState::new(capacity),
                })
            }

            pub(crate) fn from_parts(
                inner: $cipher,
                context: &TfheContext,
                noise: NoiseState,
            ) -> Self {
                Self {
                    inner,
                    context: context.clone(),
                    noise,
                }
            }

            pub(crate) fn noise(&self) -> &NoiseState {
                &self.noise
            }

            pub(crate) fn set_noise(&mut self, noise: NoiseState) {
                self.noise = noise;
            }

            #[must_use]
            pub fn context(&self) -> &TfheContext {
                &self.context
            }

            #[must_use]
            pub fn noise_state(&self) -> NoiseState {
                self.noise
            }

            pub fn decrypt(&self) -> Result<$value, TfheContextError> {
                self.context.$decrypt_method(&self.inner)
            }

            pub fn decrypt_with(&self, context: &TfheContext) -> Result<$value, TfheContextError> {
                context.$decrypt_method(&self.inner)
            }

            #[must_use]
            pub fn inner(&self) -> &$cipher {
                &self.inner
            }

            #[must_use]
            pub fn into_inner(self) -> $cipher {
                self.inner
            }

            #[must_use]
            pub const fn bit_width() -> u32 {
                <$value>::BITS
            }

            #[must_use]
            pub const fn max_value() -> $value {
                <$value>::MAX
            }
        }

        impl fmt::Debug for $wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($wrapper))
                    .field("bit_width", &Self::bit_width())
                    .field("noise", &self.noise)
                    .finish_non_exhaustive()
            }
        }

        impl fmt::Display for $wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "{}(bits={}, noise={})",
                    stringify!($wrapper),
                    Self::bit_width(),
                    self.noise
                )
            }
        }

        impl std::ops::Deref for $wrapper {
            type Target = $cipher;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl $wrapper {
            pub(crate) fn ensure_same_context(&self, other: &Self) -> Result<(), CryptoError> {
                if self.context.ptr_eq(&other.context) {
                    Ok(())
                } else {
                    Err(CryptoError::ContextMismatch)
                }
            }
        }
    };
}

encrypted_uint!(EncryptedUint8, FheUint8, u8, encrypt_u8, decrypt_u8);
encrypted_uint!(EncryptedUint16, FheUint16, u16, encrypt_u16, decrypt_u16);
encrypted_uint!(EncryptedUint32, FheUint32, u32, encrypt_u32, decrypt_u32);
