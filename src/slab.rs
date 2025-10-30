//! SlabClass models a fixed block allocator tier; `bitmap[i] = enc_true` marks an allocated block and `enc_false` marks free, so the canonical invariant stays purely encrypted.
//! Block sizing metadata remains plaintext, but every allocation decision uses the injected server key plus pre-encrypted index/offset tables supplied by the caller.

use crate::{encrypted_option::EncryptedOption, encrypted_ptr::EncryptedPtr};
use core::fmt;
use std::ops::Not;
use tfhe::{prelude::*, set_server_key, FheBool, FheUint32, FheUint64, ServerKey};

#[derive(Clone)]
pub struct SlabClass {
    block_size: usize,
    num_blocks: usize,
    bitmap: Vec<FheBool>,
    base_offset: FheUint64,
    server_key: ServerKey,
    enc_false: FheBool,
    enc_true: FheBool,
    enc_zero_u32: FheUint32,
    enc_zero_u64: FheUint64,
    enc_indices_u32: Vec<FheUint32>,
    enc_offsets_u64: Vec<FheUint64>,
}

impl fmt::Debug for SlabClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabClass")
            .field("block_size", &self.block_size)
            .field("num_blocks", &self.num_blocks)
            .field("bitmap_len", &self.bitmap.len())
            .field("base_offset", &"<ciphertext>")
            .finish()
    }
}

impl SlabClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_size: usize,
        num_blocks: usize,
        base_offset: FheUint64,
        server_key: ServerKey,
        enc_false: FheBool,
        enc_true: FheBool,
        enc_zero_u32: FheUint32,
        enc_zero_u64: FheUint64,
        enc_indices_u32: Vec<FheUint32>,
        enc_offsets_u64: Vec<FheUint64>,
    ) -> Self {
        set_server_key(server_key.clone());
        let mut bitmap = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            bitmap.push(enc_false.clone());
        }

        Self {
            block_size,
            num_blocks,
            bitmap,
            base_offset,
            server_key,
            enc_false,
            enc_true,
            enc_zero_u32,
            enc_zero_u64,
            enc_indices_u32,
            enc_offsets_u64,
        }
    }

    pub fn block_size(&self) -> usize {
        set_server_key(self.server_key.clone());
        self.block_size
    }

    pub fn num_blocks(&self) -> usize {
        set_server_key(self.server_key.clone());
        self.num_blocks
    }

    pub fn bitmap(&self) -> &[FheBool] {
        set_server_key(self.server_key.clone());
        &self.bitmap
    }

    pub fn base_offset(&self) -> &FheUint64 {
        set_server_key(self.server_key.clone());
        &self.base_offset
    }

    pub fn enc_false(&self) -> &FheBool {
        set_server_key(self.server_key.clone());
        &self.enc_false
    }

    pub fn enc_true(&self) -> &FheBool {
        set_server_key(self.server_key.clone());
        &self.enc_true
    }

    pub fn enc_zero_u32(&self) -> &FheUint32 {
        set_server_key(self.server_key.clone());
        &self.enc_zero_u32
    }

    pub fn enc_zero_u64(&self) -> &FheUint64 {
        set_server_key(self.server_key.clone());
        &self.enc_zero_u64
    }

    pub fn enc_indices_u32(&self) -> &[FheUint32] {
        set_server_key(self.server_key.clone());
        &self.enc_indices_u32
    }

    pub fn enc_offsets_u64(&self) -> &[FheUint64] {
        set_server_key(self.server_key.clone());
        &self.enc_offsets_u64
    }

    /// Performs the constant-time masked allocation scan described in Spec 3.2; `requested_mask` is a one-hot selector from the routing layer, every block is scanned, and write-back runs a second full pass so no early exits occur.
    pub fn allocate_masked(&mut self, requested_mask: FheBool) -> EncryptedOption<EncryptedPtr> {
        set_server_key(self.server_key.clone());

        let mut selected = self.enc_false.clone();
        let mut selected_index = self.enc_zero_u32.clone();
        let mut selected_ptrval = self.enc_zero_u64.clone();

        for i in 0..self.num_blocks {
            let is_allocated = self.bitmap[i].clone();
            let is_free = is_allocated.not();
            let not_selected = selected.clone().not();
            let can_select = (&is_free) & (&not_selected);
            let should_sel = (&can_select) & (&requested_mask);
            let candidate = &self.base_offset + &self.enc_offsets_u64[i];

            selected_ptrval = should_sel.if_then_else(&candidate, &selected_ptrval);
            selected_index = should_sel.if_then_else(&self.enc_indices_u32[i], &selected_index);
            selected = (&selected) | (&should_sel);
        }

        let selected_mask = (&selected) & (&requested_mask);

        for j in 0..self.num_blocks {
            let is_target = self.enc_indices_u32[j].eq(&selected_index);
            let should_mark = (&is_target) & (&selected_mask);
            let current = self.bitmap[j].clone();
            let updated = should_mark.if_then_else(&self.enc_true, &current);
            self.bitmap[j] = updated;
        }

        EncryptedOption {
            value: EncryptedPtr::new(selected_ptrval),
            is_some: selected_mask,
        }
    }

    /// frees a pointer by equality only; the entire slab scans once, compares each encrypted offset, and writes `enc_false` into matching bitmap cells with no early exit, so ciphertexts that never belonged to this tier simply leave the bitmap unchanged.
    pub fn free(&mut self, ptr: &EncryptedPtr) {
        set_server_key(self.server_key.clone());

        for i in 0..self.num_blocks {
            let candidate = &self.base_offset + &self.enc_offsets_u64[i];
            let is_match = candidate.eq(&ptr.0);
            let current = self.bitmap[i].clone();
            let updated = is_match.if_then_else(&self.enc_false, &current);
            self.bitmap[i] = updated;
        }
    }
}
