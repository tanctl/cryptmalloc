//! EncryptedOption is the struct-based option variant used for constant-time folding; `is_some` is an encrypted flag, `value` is the ciphertext payload.
//! `combine_with` relies on `cond.if_then_else(&then, &else)` plus encrypted-or, so no plaintext control flow ever decides which branch wins.
//! Callers feed it payloads that are cmux-able by value (FHE integers, booleans, EncryptedPtr) and let the selector move ciphertext handles without exposing them.

use crate::{encrypted_ptr::EncryptedPtr, keys::clone_global_server_key};
use core::fmt;
use tfhe::{prelude::IfThenElse, set_server_key, FheBool, FheUint32, FheUint64};

fn reseat_server_key() {
    if let Some(server_key) = clone_global_server_key() {
        set_server_key(server_key);
    }
}

#[derive(Clone)]
pub struct EncryptedOption<T: Clone> {
    pub value: T,
    pub is_some: FheBool,
}

impl<T: Clone> fmt::Debug for EncryptedOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedOption")
            .field("value", &"<ciphertext>")
            .field("is_some", &"<ciphertext>")
            .finish()
    }
}

impl<T: Clone> EncryptedOption<T> {
    pub fn some(value: T, enc_true: FheBool) -> Self {
        reseat_server_key();
        Self {
            value,
            is_some: enc_true,
        }
    }

    pub fn none(dummy_value: T, enc_false: FheBool) -> Self {
        reseat_server_key();
        Self {
            value: dummy_value,
            is_some: enc_false,
        }
    }
}

impl<T> EncryptedOption<T>
where
    T: Clone + CipherSelectable,
{
    pub fn combine_with(&self, other: &Self) -> Self {
        reseat_server_key();
        let combined_value = T::select(&other.is_some, &other.value, &self.value);
        let combined_flag = self.is_some.clone() | other.is_some.clone();
        Self {
            value: combined_value,
            is_some: combined_flag,
        }
    }
}

pub trait CipherSelectable: Clone {
    fn select(cond: &FheBool, when_true: &Self, when_false: &Self) -> Self;
}

impl CipherSelectable for FheBool {
    fn select(cond: &FheBool, when_true: &Self, when_false: &Self) -> Self {
        reseat_server_key();
        cond.if_then_else(when_true, when_false)
    }
}

impl CipherSelectable for FheUint32 {
    fn select(cond: &FheBool, when_true: &Self, when_false: &Self) -> Self {
        reseat_server_key();
        cond.if_then_else(when_true, when_false)
    }
}

impl CipherSelectable for FheUint64 {
    fn select(cond: &FheBool, when_true: &Self, when_false: &Self) -> Self {
        reseat_server_key();
        cond.if_then_else(when_true, when_false)
    }
}

impl CipherSelectable for EncryptedPtr {
    fn select(cond: &FheBool, when_true: &Self, when_false: &Self) -> Self {
        reseat_server_key();
        let chosen_offset = cond.if_then_else(&when_true.0, &when_false.0);
        EncryptedPtr::new(chosen_offset)
    }
}
