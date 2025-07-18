use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};

use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, InvalidOperationError};
use crate::crypto::tfhe_context::TfheContext;
use crate::types::comparison::{select_integer, select_option};
use crate::types::encrypted::{EncryptedBool, EncryptedUint32, EncryptedUint64};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedSize {
    value: EncryptedUint32,
}

impl EncryptedSize {
    pub fn encrypt(value: u32, context: &TfheContext) -> Result<Self, CryptoError> {
        EncryptedUint32::encrypt(value, context)
            .map(Self::from_encrypted)
            .map_err(CryptoError::from)
    }

    pub(crate) fn from_encrypted(value: EncryptedUint32) -> Self {
        Self { value }
    }

    #[must_use]
    pub fn context(&self) -> &TfheContext {
        self.value.context()
    }

    pub fn decrypt(&self) -> Result<u32, CryptoError> {
        self.value.decrypt().map_err(CryptoError::from)
    }

    #[must_use]
    pub fn inner(&self) -> &EncryptedUint32 {
        &self.value
    }

    pub fn wrapping_add(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.wrapping_add(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn wrapping_sub(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.wrapping_sub(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn wrapping_mul(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.wrapping_mul(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn checked_add(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.checked_add(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.checked_sub(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn checked_mul(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.checked_mul(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn min_cipher(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.min_cipher(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    pub fn max_cipher(&self, rhs: &Self) -> Result<Self, CryptoError> {
        let value = self.value.max_cipher(rhs.inner())?;
        Ok(Self::from_encrypted(value))
    }

    // plaintext alignment keeps allocator layout consistent until fhe-friendly rounding lands
    pub fn align_up_plain(&self, alignment: u32) -> Result<Self, CryptoError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(InvalidOperationError::new("alignment must be a power of two").into());
        }
        let value = self.decrypt()?;
        let mask = alignment - 1;
        let aligned = (value + mask) & !mask;
        Self::encrypt(aligned, self.context())
    }

    // plaintext alignment keeps allocator layout consistent until fhe-friendly rounding lands
    pub fn align_down_plain(&self, alignment: u32) -> Result<Self, CryptoError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(InvalidOperationError::new("alignment must be a power of two").into());
        }
        let value = self.decrypt()?;
        let mask = alignment - 1;
        let aligned = value & !mask;
        Self::encrypt(aligned, self.context())
    }
}

impl<'a, 'b> Add<&'b EncryptedSize> for &'a EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn add(self, rhs: &'b EncryptedSize) -> Self::Output {
        self.wrapping_add(rhs)
    }
}

impl Add<EncryptedSize> for EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn add(self, rhs: EncryptedSize) -> Self::Output {
        (&self).wrapping_add(&rhs)
    }
}

impl<'a, 'b> Sub<&'b EncryptedSize> for &'a EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn sub(self, rhs: &'b EncryptedSize) -> Self::Output {
        self.wrapping_sub(rhs)
    }
}

impl Sub<EncryptedSize> for EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn sub(self, rhs: EncryptedSize) -> Self::Output {
        (&self).wrapping_sub(&rhs)
    }
}

impl<'a, 'b> Mul<&'b EncryptedSize> for &'a EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn mul(self, rhs: &'b EncryptedSize) -> Self::Output {
        self.wrapping_mul(rhs)
    }
}

impl Mul<EncryptedSize> for EncryptedSize {
    type Output = Result<EncryptedSize, CryptoError>;

    fn mul(self, rhs: EncryptedSize) -> Self::Output {
        (&self).wrapping_mul(&rhs)
    }
}

impl PartialEq for EncryptedSize {
    fn eq(&self, other: &Self) -> bool {
        match (self.decrypt(), other.decrypt()) {
            (Ok(lhs), Ok(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

impl Eq for EncryptedSize {}

impl PartialOrd for EncryptedSize {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.decrypt(), other.decrypt()) {
            (Ok(lhs), Ok(rhs)) => lhs.partial_cmp(&rhs),
            _ => None,
        }
    }
}

impl Display for EncryptedSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.decrypt() {
            Ok(value) => write!(f, "{value} bytes"),
            Err(_) => write!(f, "<opaque size>"),
        }
    }
}

impl TryFrom<(u32, &TfheContext)> for EncryptedSize {
    type Error = CryptoError;

    fn try_from(value: (u32, &TfheContext)) -> Result<Self, Self::Error> {
        Self::encrypt(value.0, value.1)
    }
}

impl TryFrom<&EncryptedUint32> for EncryptedSize {
    type Error = CryptoError;

    fn try_from(value: &EncryptedUint32) -> Result<Self, Self::Error> {
        Ok(Self::from_encrypted(value.clone()))
    }
}

impl TryFrom<EncryptedUint32> for EncryptedSize {
    type Error = CryptoError;

    fn try_from(value: EncryptedUint32) -> Result<Self, Self::Error> {
        Ok(Self::from_encrypted(value))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedAddress {
    value: EncryptedUint64,
}

impl EncryptedAddress {
    pub fn encrypt(value: u64, context: &TfheContext) -> Result<Self, CryptoError> {
        EncryptedUint64::encrypt(value, context)
            .map(Self::from_encrypted)
            .map_err(CryptoError::from)
    }

    pub(crate) fn from_encrypted(value: EncryptedUint64) -> Self {
        Self { value }
    }

    #[must_use]
    pub fn context(&self) -> &TfheContext {
        self.value.context()
    }

    pub fn decrypt(&self) -> Result<u64, CryptoError> {
        self.value.decrypt().map_err(CryptoError::from)
    }

    #[must_use]
    pub fn inner(&self) -> &EncryptedUint64 {
        &self.value
    }

    pub fn align_up_plain(&self, alignment: u64) -> Result<Self, CryptoError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(InvalidOperationError::new("alignment must be a power of two").into());
        }
        let value = self.decrypt()?;
        let mask = alignment - 1;
        let aligned = (value + mask) & !mask;
        Self::encrypt(aligned, self.context())
    }
}

impl PartialEq for EncryptedAddress {
    fn eq(&self, other: &Self) -> bool {
        match (self.decrypt(), other.decrypt()) {
            (Ok(lhs), Ok(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

impl Eq for EncryptedAddress {}

impl PartialOrd for EncryptedAddress {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.decrypt(), other.decrypt()) {
            (Ok(lhs), Ok(rhs)) => lhs.partial_cmp(&rhs),
            _ => None,
        }
    }
}

impl Display for EncryptedAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.decrypt() {
            Ok(value) => write!(f, "0x{value:016x}"),
            Err(_) => write!(f, "<opaque address>"),
        }
    }
}

impl TryFrom<(u64, &TfheContext)> for EncryptedAddress {
    type Error = CryptoError;

    fn try_from(value: (u64, &TfheContext)) -> Result<Self, Self::Error> {
        Self::encrypt(value.0, value.1)
    }
}

impl TryFrom<&EncryptedUint64> for EncryptedAddress {
    type Error = CryptoError;

    fn try_from(value: &EncryptedUint64) -> Result<Self, Self::Error> {
        Ok(Self::from_encrypted(value.clone()))
    }
}

impl TryFrom<EncryptedUint64> for EncryptedAddress {
    type Error = CryptoError;

    fn try_from(value: EncryptedUint64) -> Result<Self, Self::Error> {
        Ok(Self::from_encrypted(value))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EncryptedPointer<T> {
    address: EncryptedAddress,
    span: Option<EncryptedSize>,
    valid: EncryptedBool,
    #[serde(skip)]
    marker: PhantomData<T>,
}

impl<T> EncryptedPointer<T> {
    pub fn new(
        address: EncryptedAddress,
        span: Option<EncryptedSize>,
        valid: EncryptedBool,
    ) -> Result<Self, CryptoError> {
        if !address.context().ptr_eq(valid.context()) {
            return Err(CryptoError::ContextMismatch);
        }
        if let Some(span_ref) = &span {
            if !address.context().ptr_eq(span_ref.context()) {
                return Err(CryptoError::ContextMismatch);
            }
        }
        Ok(Self {
            address,
            span,
            valid,
            marker: PhantomData,
        })
    }

    #[must_use]
    pub fn context(&self) -> &TfheContext {
        self.address.context()
    }

    #[must_use]
    pub fn address(&self) -> &EncryptedAddress {
        &self.address
    }

    #[must_use]
    pub fn span(&self) -> Option<&EncryptedSize> {
        self.span.as_ref()
    }

    #[must_use]
    pub fn valid(&self) -> &EncryptedBool {
        &self.valid
    }

    pub fn ensure_same_context(&self, other: &Self) -> Result<(), CryptoError> {
        if !self.address.context().ptr_eq(other.address.context()) {
            return Err(CryptoError::ContextMismatch);
        }
        if let (Some(lhs_span), Some(rhs_span)) = (&self.span, &other.span) {
            lhs_span.inner().ensure_same_context(rhs_span.inner())?;
        }
        self.valid.ensure_same_context(other.valid())
    }

    // plaintext alignment keeps allocator layout consistent until fhe-friendly rounding lands
    pub fn align_to(&self, alignment: u64) -> Result<Self, CryptoError> {
        let address = self.address.align_up_plain(alignment)?;
        Self::new(address, self.span.clone(), self.valid.clone())
    }

    pub fn guard(&self, predicate: &EncryptedBool) -> Result<Self, CryptoError> {
        self.valid.ensure_same_context(predicate)?;
        let gated = self.valid.and(predicate)?;
        Self::new(self.address.clone(), self.span.clone(), gated)
    }

    pub fn select(
        condition: &EncryptedBool,
        when_true: &Self,
        when_false: &Self,
    ) -> Result<Self, CryptoError> {
        when_true.ensure_same_context(when_false)?;
        if !condition.context().ptr_eq(when_true.context())
            || !condition.context().ptr_eq(when_false.context())
        {
            return Err(CryptoError::ContextMismatch);
        }
        condition.ensure_same_context(when_true.valid())?;
        condition.ensure_same_context(when_false.valid())?;

        let address_cipher = select_integer(
            condition,
            when_true.address.inner(),
            when_false.address.inner(),
        )?;
        let address = EncryptedAddress::from_encrypted(address_cipher);

        let true_span = when_true.span().map(EncryptedSize::inner);
        let false_span = when_false.span().map(EncryptedSize::inner);
        let span_cipher = select_option(condition, true_span, false_span)?;
        let span = span_cipher.map(EncryptedSize::from_encrypted);

        let true_valid = condition.and(when_true.valid())?;
        let not_condition = condition.not();
        let false_valid = not_condition.and(when_false.valid())?;
        let valid = true_valid.or(&false_valid)?;

        Self::new(address, span, valid)
    }
}

impl<T> PartialEq for EncryptedPointer<T> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.span == other.span
    }
}

impl<T> Display for EncryptedPointer<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ptr({}", self.address)?;
        if let Some(span) = &self.span {
            write!(f, ", span: {}", span)?;
        }
        match self.valid.decrypt() {
            Ok(flag) => write!(f, ", valid: {})", flag),
            Err(_) => write!(f, ", valid: <opaque>)"),
        }
    }
}

pub fn align_request(size: &EncryptedSize, alignment: u32) -> Result<EncryptedSize, CryptoError> {
    size.align_up_plain(alignment)
}

pub fn min_size_array<const N: usize>(
    inputs: [&EncryptedSize; N],
) -> Result<EncryptedSize, CryptoError> {
    if N == 0 {
        return Err(InvalidOperationError::new("size array must not be empty").into());
    }
    let mut current = inputs[0].clone();
    for value in inputs.iter().skip(1) {
        current = current.min_cipher(value)?;
    }
    Ok(current)
}

pub fn choose_smallest(sizes: &[EncryptedSize]) -> Result<EncryptedSize, CryptoError> {
    let mut iter = sizes.iter();
    let first = iter
        .next()
        .cloned()
        .ok_or_else(|| InvalidOperationError::new("empty size list"))?;
    let mut current = first;
    for candidate in iter {
        current = current.min_cipher(candidate)?;
    }
    Ok(current)
}
