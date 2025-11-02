//! Arena is the encrypted bump allocator backing large (>256 byte) requests; it advances a ciphertext cursor between encrypted `start` and `end` bounds, never frees individual chunks, and only resets wholesale.

use crate::{encrypted_option::EncryptedOption, encrypted_ptr::EncryptedPtr};
use std::ops::Not;
use tfhe::{prelude::*, set_server_key, FheBool, FheUint64, ServerKey};

#[derive(Clone)]
pub struct Arena {
    start: FheUint64,
    end: FheUint64,
    cursor: FheUint64,
    server_key: ServerKey,
    enc_false: FheBool,
    enc_zero_u64: FheUint64,
}

impl core::fmt::Debug for Arena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Arena")
            .field("start", &"<ciphertext>")
            .field("end", &"<ciphertext>")
            .field("cursor", &"<ciphertext>")
            .finish()
    }
}

impl Arena {
    pub fn new(
        start: FheUint64,
        end: FheUint64,
        server_key: ServerKey,
        enc_false: FheBool,
        enc_zero_u64: FheUint64,
    ) -> Self {
        set_server_key(server_key.clone());
        Self {
            start: start.clone(),
            end,
            cursor: start,
            server_key,
            enc_false,
            enc_zero_u64,
        }
    }

    pub fn allocate(&mut self, size: FheUint64) -> EncryptedOption<EncryptedPtr> {
        set_server_key(self.server_key.clone());

        let new_cursor = &self.cursor + &size;
        let has_space = new_cursor.le(&self.end);
        let wrapped = new_cursor.lt(&self.cursor);
        let ok = (&has_space) & (&wrapped.not());

        let ptr_val = ok.if_then_else(&self.cursor, &self.enc_zero_u64);
        self.cursor = ok.if_then_else(&new_cursor, &self.cursor);

        EncryptedOption {
            value: EncryptedPtr::new(ptr_val),
            is_some: ok,
        }
    }

    pub fn reset(&mut self) {
        set_server_key(self.server_key.clone());
        self.cursor = self.start.clone();
    }

    pub fn start(&self) -> &FheUint64 {
        set_server_key(self.server_key.clone());
        &self.start
    }

    pub fn end(&self) -> &FheUint64 {
        set_server_key(self.server_key.clone());
        &self.end
    }

    pub fn cursor(&self) -> &FheUint64 {
        set_server_key(self.server_key.clone());
        &self.cursor
    }

    pub fn enc_false(&self) -> &FheBool {
        set_server_key(self.server_key.clone());
        &self.enc_false
    }
}
