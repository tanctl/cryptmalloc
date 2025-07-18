use std::ops::{Add, Mul, Sub};

use tfhe::{FheBool, FheUint16, FheUint32, FheUint8};

use crate::crypto::error::{CryptoError, OverflowError};
use crate::crypto::noise::NoiseState;
use crate::types::encrypted::{EncryptedBool, EncryptedUint16, EncryptedUint32, EncryptedUint8};

// operation costs model the relative noise growth for planning heuristics
const COST_ADDITION: usize = 4;
const COST_SUBTRACTION: usize = 4;
const COST_MULTIPLICATION: usize = 12;

macro_rules! impl_integer_ops {
    ($wrapper:ident, $cipher:ty, $clear:ty, $checked_tag:literal) => {
        impl $wrapper {
            fn binary_op<F>(&self, rhs: &Self, cost: usize, op: F) -> Result<Self, CryptoError>
            where
                F: Fn(&$cipher, &$cipher) -> $cipher,
            {
                self.ensure_same_context(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;

                let cipher = op(self.inner(), rhs.inner());
                let noise = NoiseState::merge(self.noise(), rhs.noise(), cost)?;
                Ok(Self::from_parts(cipher, self.context(), noise))
            }

            pub fn wrapping_add(&self, rhs: &Self) -> Result<Self, CryptoError> {
                self.binary_op(rhs, COST_ADDITION, |l, r| l + r)
            }

            pub fn checked_add(&self, rhs: &Self) -> Result<Self, CryptoError> {
                // decrypting here assumes the caller runs on the trusted side when overflow checks are needed
                let lhs_clear: u128 = self.decrypt().map_err(CryptoError::from)?.into();
                let rhs_clear: u128 = rhs.decrypt().map_err(CryptoError::from)?.into();
                let max: u128 = Self::max_value().into();

                if lhs_clear.saturating_add(rhs_clear) > max {
                    return Err(OverflowError::new("checked_add").into());
                }

                self.wrapping_add(rhs)
            }

            pub fn saturating_add(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let lhs_clear: u128 = self.decrypt().map_err(CryptoError::from)?.into();
                let rhs_clear: u128 = rhs.decrypt().map_err(CryptoError::from)?.into();
                let max: u128 = Self::max_value().into();

                if lhs_clear.saturating_add(rhs_clear) > max {
                    let mut saturated = Self::encrypt(Self::max_value(), self.context())
                        .map_err(CryptoError::from)?;
                    let capacity = self.context().noise_capacity().map_err(CryptoError::from)?;
                    saturated.set_noise(NoiseState::new(capacity));
                    Ok(saturated)
                } else {
                    self.wrapping_add(rhs)
                }
            }

            pub fn wrapping_sub(&self, rhs: &Self) -> Result<Self, CryptoError> {
                self.binary_op(rhs, COST_SUBTRACTION, |l, r| l - r)
            }

            pub fn checked_sub(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let lhs_clear: u128 = self.decrypt().map_err(CryptoError::from)?.into();
                let rhs_clear: u128 = rhs.decrypt().map_err(CryptoError::from)?.into();

                if lhs_clear < rhs_clear {
                    return Err(OverflowError::new("checked_sub").into());
                }

                self.wrapping_sub(rhs)
            }

            pub fn wrapping_mul(&self, rhs: &Self) -> Result<Self, CryptoError> {
                self.binary_op(rhs, COST_MULTIPLICATION, |l, r| l * r)
            }

            pub fn checked_mul(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let lhs_clear: u128 = self.decrypt().map_err(CryptoError::from)?.into();
                let rhs_clear: u128 = rhs.decrypt().map_err(CryptoError::from)?.into();
                let max: u128 = Self::max_value().into();

                if lhs_clear.saturating_mul(rhs_clear) > max {
                    return Err(OverflowError::new("checked_mul").into());
                }

                self.wrapping_mul(rhs)
            }

            pub fn saturating_mul(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let lhs_clear: u128 = self.decrypt().map_err(CryptoError::from)?.into();
                let rhs_clear: u128 = rhs.decrypt().map_err(CryptoError::from)?.into();
                let max: u128 = Self::max_value().into();

                if lhs_clear.saturating_mul(rhs_clear) > max {
                    let mut saturated = Self::encrypt(Self::max_value(), self.context())
                        .map_err(CryptoError::from)?;
                    let capacity = self.context().noise_capacity().map_err(CryptoError::from)?;
                    saturated.set_noise(NoiseState::new(capacity));
                    Ok(saturated)
                } else {
                    self.wrapping_mul(rhs)
                }
            }

            pub fn batch_add<'a>(
                inputs: &[(&'a Self, &'a Self)],
            ) -> Result<Vec<Self>, CryptoError> {
                inputs
                    .iter()
                    .map(|(lhs, rhs)| lhs.wrapping_add(rhs))
                    .collect()
            }

            pub fn batch_sub<'a>(
                inputs: &[(&'a Self, &'a Self)],
            ) -> Result<Vec<Self>, CryptoError> {
                inputs
                    .iter()
                    .map(|(lhs, rhs)| lhs.wrapping_sub(rhs))
                    .collect()
            }

            pub fn batch_mul<'a>(
                inputs: &[(&'a Self, &'a Self)],
            ) -> Result<Vec<Self>, CryptoError> {
                inputs
                    .iter()
                    .map(|(lhs, rhs)| lhs.wrapping_mul(rhs))
                    .collect()
            }
        }

        impl<'a, 'b> Add<&'b $wrapper> for &'a $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn add(self, rhs: &'b $wrapper) -> Self::Output {
                self.wrapping_add(rhs)
            }
        }

        impl Add<$wrapper> for $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn add(self, rhs: $wrapper) -> Self::Output {
                (&self).wrapping_add(&rhs)
            }
        }

        impl<'a, 'b> Sub<&'b $wrapper> for &'a $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn sub(self, rhs: &'b $wrapper) -> Self::Output {
                self.wrapping_sub(rhs)
            }
        }

        impl Sub<$wrapper> for $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn sub(self, rhs: $wrapper) -> Self::Output {
                (&self).wrapping_sub(&rhs)
            }
        }

        impl<'a, 'b> Mul<&'b $wrapper> for &'a $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn mul(self, rhs: &'b $wrapper) -> Self::Output {
                self.wrapping_mul(rhs)
            }
        }

        impl Mul<$wrapper> for $wrapper {
            type Output = Result<$wrapper, CryptoError>;

            fn mul(self, rhs: $wrapper) -> Self::Output {
                (&self).wrapping_mul(&rhs)
            }
        }
    };
}

impl_integer_ops!(EncryptedUint8, FheUint8, u8, "u8");
impl_integer_ops!(EncryptedUint16, FheUint16, u16, "u16");
impl_integer_ops!(EncryptedUint32, FheUint32, u32, "u32");

impl EncryptedBool {
    fn binary_op<F>(&self, rhs: &Self, op: F) -> Result<Self, CryptoError>
    where
        F: Fn(&FheBool, &FheBool) -> FheBool,
    {
        self.ensure_same_context(rhs)?;
        self.context()
            .install_server_key()
            .map_err(CryptoError::from)?;
        let cipher = op(self.inner(), rhs.inner());
        let noise = NoiseState::merge(self.noise(), rhs.noise(), COST_ADDITION)?;
        Ok(Self::from_parts(cipher, self.context(), noise))
    }

    pub fn and(&self, rhs: &Self) -> Result<Self, CryptoError> {
        self.binary_op(rhs, |l, r| l & r)
    }

    pub fn or(&self, rhs: &Self) -> Result<Self, CryptoError> {
        self.binary_op(rhs, |l, r| l | r)
    }

    pub fn xor(&self, rhs: &Self) -> Result<Self, CryptoError> {
        self.binary_op(rhs, |l, r| l ^ r)
    }

    #[must_use]
    pub fn not(&self) -> Self {
        let cipher = !self.inner();
        Self::from_parts(cipher, self.context(), *self.noise())
    }
}

#[derive(Clone, Debug)]
pub struct ComparisonOperands<T> {
    pub lhs: T,
    pub rhs: T,
}

macro_rules! prepare_comparison {
    ($fn_name:ident, $wrapper:ty) => {
        pub fn $fn_name(
            lhs: &$wrapper,
            rhs: &$wrapper,
        ) -> Result<ComparisonOperands<$wrapper>, CryptoError> {
            lhs.ensure_same_context(rhs)?;
            Ok(ComparisonOperands {
                lhs: lhs.clone(),
                rhs: rhs.clone(),
            })
        }
    };
}

prepare_comparison!(prepare_comparison_u8, EncryptedUint8);
prepare_comparison!(prepare_comparison_u16, EncryptedUint16);
prepare_comparison!(prepare_comparison_u32, EncryptedUint32);
