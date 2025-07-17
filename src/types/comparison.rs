use std::cmp::Ordering;
use tfhe::prelude::{FheEq, FheOrd, IfThenElse};
use tfhe::{FheBool, FheUint16, FheUint32, FheUint8};

use crate::crypto::error::CryptoError;
use crate::crypto::noise::NoiseState;
use crate::types::encrypted::{EncryptedBool, EncryptedUint16, EncryptedUint32, EncryptedUint8};

const COST_COMPARISON: usize = 6;
const COST_SELECT_BRANCH: usize = 3;
const COST_SELECT_CONTROL: usize = 2;

macro_rules! comparison_impls {
    ($type:ty, $le_fn:ident, $lt_fn:ident, $gt_fn:ident, $ge_fn:ident, $eq_fn:ident) => {
        impl $type {
            fn prepare_pair(&self, rhs: &Self) -> Result<(), CryptoError> {
                self.ensure_same_context(rhs)
            }

            fn merge_noise(&self, rhs: &Self, cost: usize) -> Result<NoiseState, CryptoError> {
                NoiseState::merge(self.noise(), rhs.noise(), cost)
            }

            pub fn eq_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                self.prepare_pair(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;
                let cipher = self.inner().$eq_fn(rhs.inner());
                let noise = self.merge_noise(rhs, COST_COMPARISON)?;
                Ok(EncryptedBool::from_parts(cipher, self.context(), noise))
            }

            pub fn ne_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                let eq = self.eq_cipher(rhs)?;
                Ok(eq.not())
            }

            pub fn lt_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                self.prepare_pair(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;
                let cipher = self.inner().$lt_fn(rhs.inner());
                let noise = self.merge_noise(rhs, COST_COMPARISON)?;
                Ok(EncryptedBool::from_parts(cipher, self.context(), noise))
            }

            pub fn le_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                self.prepare_pair(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;
                let cipher = self.inner().$le_fn(rhs.inner());
                let noise = self.merge_noise(rhs, COST_COMPARISON)?;
                Ok(EncryptedBool::from_parts(cipher, self.context(), noise))
            }

            pub fn gt_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                self.prepare_pair(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;
                let cipher = self.inner().$gt_fn(rhs.inner());
                let noise = self.merge_noise(rhs, COST_COMPARISON)?;
                Ok(EncryptedBool::from_parts(cipher, self.context(), noise))
            }

            pub fn ge_cipher(&self, rhs: &Self) -> Result<EncryptedBool, CryptoError> {
                self.prepare_pair(rhs)?;
                self.context()
                    .install_server_key()
                    .map_err(CryptoError::from)?;
                let cipher = self.inner().$ge_fn(rhs.inner());
                let noise = self.merge_noise(rhs, COST_COMPARISON)?;
                Ok(EncryptedBool::from_parts(cipher, self.context(), noise))
            }

            pub fn min_cipher(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let selector = self.le_cipher(rhs)?;
                select_integer(&selector, self, rhs)
            }

            pub fn max_cipher(&self, rhs: &Self) -> Result<Self, CryptoError> {
                let selector = self.ge_cipher(rhs)?;
                select_integer(&selector, self, rhs)
            }
        }

        impl PartialEq for $type {
            fn eq(&self, other: &Self) -> bool {
                self.decrypt()
                    .and_then(|lhs| other.decrypt().map(|rhs| lhs == rhs))
                    .unwrap_or(false)
            }
        }

        impl Eq for $type {}

        impl PartialOrd for $type {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                match (self.decrypt(), other.decrypt()) {
                    (Ok(lhs), Ok(rhs)) => lhs.partial_cmp(&rhs),
                    _ => None,
                }
            }
        }
    };
}

comparison_impls!(EncryptedUint8, le, lt, gt, ge, eq);
comparison_impls!(EncryptedUint16, le, lt, gt, ge, eq);
comparison_impls!(EncryptedUint32, le, lt, gt, ge, eq);

fn merge_condition_noise(
    condition: &EncryptedBool,
    lhs: &NoiseState,
    rhs: &NoiseState,
) -> Result<NoiseState, CryptoError> {
    let branch_noise = NoiseState::merge(lhs, rhs, COST_SELECT_BRANCH)?;
    NoiseState::merge(condition.noise(), &branch_noise, COST_SELECT_CONTROL)
}

pub fn select_integer<T>(
    condition: &EncryptedBool,
    when_true: &T,
    when_false: &T,
) -> Result<T, CryptoError>
where
    T: SelectableInteger,
    FheBool: IfThenElse<<T as SelectableInteger>::Cipher>,
{
    if !condition.context().ptr_eq(when_true.context())
        || !condition.context().ptr_eq(when_false.context())
    {
        return Err(CryptoError::ContextMismatch);
    }
    condition
        .context()
        .install_server_key()
        .map_err(CryptoError::from)?;

    // tfhe executes if_then_else with data-independent timing, keeping this branch constant time
    let cipher = condition
        .inner()
        .if_then_else(when_true.inner(), when_false.inner());

    let noise = merge_condition_noise(condition, when_true.noise(), when_false.noise())?;
    Ok(T::from_parts(cipher, when_true.context(), noise))
}

pub fn select_option<T>(
    condition: &EncryptedBool,
    when_true: Option<&T>,
    when_false: Option<&T>,
) -> Result<Option<T>, CryptoError>
where
    T: SelectableInteger,
    FheBool: IfThenElse<<T as SelectableInteger>::Cipher>,
{
    match (when_true, when_false) {
        (Some(t), Some(f)) => {
            if !condition.context().ptr_eq(t.context()) || !condition.context().ptr_eq(f.context())
            {
                return Err(CryptoError::ContextMismatch);
            }
            select_integer(condition, t, f).map(Some)
        }
        (Some(t), None) => {
            if !condition.context().ptr_eq(t.context()) {
                return Err(CryptoError::ContextMismatch);
            }
            let predicate = condition.decrypt().map_err(CryptoError::from)?;
            if predicate {
                Ok(Some(t.clone()))
            } else {
                Ok(None)
            }
        }
        (None, Some(f)) => {
            if !condition.context().ptr_eq(f.context()) {
                return Err(CryptoError::ContextMismatch);
            }
            let predicate = condition.decrypt().map_err(CryptoError::from)?;
            if predicate {
                Ok(Some(f.clone()))
            } else {
                Ok(None)
            }
        }
        (None, None) => Ok(None),
    }
}

pub trait SelectableInteger: Sized + Clone {
    type Cipher;

    fn inner(&self) -> &Self::Cipher;
    fn context(&self) -> &crate::crypto::tfhe_context::TfheContext;
    fn noise(&self) -> &NoiseState;
    fn from_parts(
        cipher: Self::Cipher,
        context: &crate::crypto::tfhe_context::TfheContext,
        noise: NoiseState,
    ) -> Self;
}

macro_rules! selectable_impl {
    ($type:ty, $cipher:ty) => {
        impl SelectableInteger for $type {
            type Cipher = $cipher;

            fn inner(&self) -> &Self::Cipher {
                <$type>::inner(self)
            }

            fn context(&self) -> &crate::crypto::tfhe_context::TfheContext {
                <$type>::context(self)
            }

            fn noise(&self) -> &NoiseState {
                <$type>::noise(self)
            }

            fn from_parts(
                cipher: Self::Cipher,
                context: &crate::crypto::tfhe_context::TfheContext,
                noise: NoiseState,
            ) -> Self {
                <$type>::from_parts(cipher, context, noise)
            }
        }
    };
}

selectable_impl!(EncryptedUint8, FheUint8);
selectable_impl!(EncryptedUint16, FheUint16);
selectable_impl!(EncryptedUint32, FheUint32);

pub fn min_array_u8<const N: usize>(
    inputs: [&EncryptedUint8; N],
) -> Result<EncryptedUint8, CryptoError> {
    assert!(N > 0, "array must contain at least one value");
    let mut current = inputs[0].clone();
    for value in inputs.iter().skip(1) {
        current = current.min_cipher(value)?;
    }
    Ok(current)
}

pub fn max_option_list(
    values: &[Option<EncryptedUint8>],
) -> Result<Option<EncryptedUint8>, CryptoError> {
    let mut best: Option<EncryptedUint8> = None;
    for value in values.iter().flatten() {
        let value = value.clone();
        match &best {
            Some(current) => {
                let is_ge = current.ge_cipher(&value)?;
                let chosen = select_integer(&is_ge, current, &value)?;
                best = Some(chosen);
            }
            None => best = Some(value),
        }
    }
    Ok(best)
}
