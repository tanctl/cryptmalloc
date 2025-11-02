use core::fmt;
use crate::{
    arena::Arena,
    encrypted_option::EncryptedOption,
    encrypted_ptr::EncryptedPtr,
    keys::Keys,
    slab::SlabClass,
};
use std::ops::Not;
use tfhe::{prelude::*, set_server_key, FheBool, FheUint64};

pub struct CryptMalloc {
    keys: Keys,
    slabs: Vec<SlabClass>,
    arena: Arena,
    enc_false: FheBool,
    enc_zero_u64: FheUint64,
    size_bounds: [FheUint64; 5],
}

impl fmt::Debug for CryptMalloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptMalloc")
            .field("slab_count", &self.slabs.len())
            .field("arena", &self.arena)
            .finish()
    }
}

impl CryptMalloc {
    /// cryptmalloc wires together the strict top-level allocator: it alone owns the client key, manufactures the encrypted constants plus lookup tables, and lays out the slab tiers contiguously before the arena.
    pub fn new(arena_size: u64) -> Self {
        let keys = Keys::new();
        let server_key = keys.server_key();
        set_server_key(server_key.clone());

        let enc_false = keys.enc_false();
        let enc_true = keys.enc_true();
        let enc_zero_u32 = keys.enc_zero_u32();
        let enc_zero_u64 = keys.enc_zero_u64();
        let size_bounds = [
            keys.enc_u64(16),
            keys.enc_u64(32),
            keys.enc_u64(64),
            keys.enc_u64(128),
            keys.enc_u64(256),
        ];

        let slab_configs = [
            (16usize, 1024usize),
            (32usize, 512usize),
            (64usize, 256usize),
            (128usize, 128usize),
            (256usize, 64usize),
        ];

        let mut slabs = Vec::with_capacity(slab_configs.len());
        let mut running_offset = 0u64;

        for (block_size, num_blocks) in slab_configs.iter() {
            let base_offset_plain = running_offset;
            running_offset += (*block_size as u64) * (*num_blocks as u64);

            let base_offset = keys.enc_u64(base_offset_plain);
            let enc_indices_u32 = keys.build_enc_indices_u32(*num_blocks);
            let enc_offsets_u64 = keys.build_enc_offsets_u64(*num_blocks, *block_size);

            let slab = SlabClass::new(
                *block_size,
                *num_blocks,
                base_offset,
                server_key.clone(),
                enc_false.clone(),
                enc_true.clone(),
                enc_zero_u32.clone(),
                enc_zero_u64.clone(),
                enc_indices_u32,
                enc_offsets_u64,
            );

            slabs.push(slab);
        }

        let arena_start_plain = running_offset;
        let arena_end_plain = arena_start_plain + arena_size;
        let arena_start = keys.enc_u64(arena_start_plain);
        let arena_end = keys.enc_u64(arena_end_plain);
        let arena_enc_false = enc_false.clone();
        let arena_enc_zero = enc_zero_u64.clone();

        let arena = Arena::new(
            arena_start,
            arena_end,
            server_key.clone(),
            arena_enc_false,
            arena_enc_zero,
        );

        Self {
            keys,
            slabs,
            arena,
            enc_false,
            enc_zero_u64,
            size_bounds,
        }
    }

    /// routes encrypted size requests through every slab class plus the arena in constant time; sizes up to 256 bytes never spill into the arena, and zero length requests are coerced to 16 bytes before routing
    pub fn allocate(&mut self, size: FheUint64) -> EncryptedOption<EncryptedPtr> {
        set_server_key(self.keys.server_key());

        let enc_false = self.enc_false.clone();
        let enc_zero = self.enc_zero_u64.clone();
        let enc_16 = self.size_bounds[0].clone();
        let enc_32 = self.size_bounds[1].clone();
        let enc_64 = self.size_bounds[2].clone();
        let enc_128 = self.size_bounds[3].clone();
        let enc_256 = self.size_bounds[4].clone();

        let is_zero = size.eq(&enc_zero);
        let lt_16 = size.lt(&enc_16);
        let force_16 = (&is_zero) | (&lt_16);
        let size_ct = force_16.if_then_else(&enc_16, &size);

        let fits16 = size_ct.le(&enc_16);
        let fits32 = size_ct.le(&enc_32);
        let fits64 = size_ct.le(&enc_64);
        let fits128 = size_ct.le(&enc_128);
        let fits256 = size_ct.le(&enc_256);

        let mask0 = fits16.clone();
        let mask1 = fits32.clone() & fits16.clone().not();
        let used01 = fits16.clone() | fits32.clone();
        let mask2 = fits64.clone() & used01.clone().not();
        let used012 = used01.clone() | fits64.clone();
        let mask3 = fits128.clone() & used012.clone().not();
        let used0123 = used012.clone() | fits128.clone();
        let mask4 = fits256.clone() & used0123.clone().not();

        let masks = [mask0, mask1, mask2, mask3, mask4];

        let mut slab_results = Vec::with_capacity(self.slabs.len());
        for (slab, sel) in self.slabs.iter_mut().zip(masks.iter()) {
            slab_results.push(slab.allocate_masked(sel.clone()));
        }

        let use_arena = size_ct.gt(&enc_256);
        let arena_size = use_arena.if_then_else(&size_ct, &enc_zero.clone());
        let arena_raw = self.arena.allocate(arena_size);
        let arena_masked = EncryptedOption {
            value: arena_raw.value,
            is_some: arena_raw.is_some & use_arena.clone(),
        };

        let mut result = EncryptedOption::none(EncryptedPtr(enc_zero.clone()), enc_false.clone());
        for slab_result in slab_results.iter() {
            result = result.combine_with(slab_result);
        }
        result = result.combine_with(&arena_masked);
        result
    }

    pub fn arena(&self) -> &Arena {
        set_server_key(self.keys.server_key());
        &self.arena
    }

    pub fn slabs(&self) -> &[SlabClass] {
        set_server_key(self.keys.server_key());
        &self.slabs
    }

    pub fn keys(&self) -> &Keys {
        set_server_key(self.keys.server_key());
        &self.keys
    }

    // frees pointers by scanning every slab in constant time; arena chunks are not freed individually and null/invalid ciphertexts are harmless no-ops.
    pub fn free(&mut self, ptr: &EncryptedPtr) {
        set_server_key(self.keys.server_key());

        for slab in self.slabs.iter_mut() {
            slab.free(ptr);
        }
    }
}
