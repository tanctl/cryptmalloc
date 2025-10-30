use cryptmalloc::{Arena, CryptMalloc, Keys, SlabClass};

#[test]
fn allocator_smoke_test() {
    let keys = Keys::new();
    let block_size = 64;
    let num_blocks = 32;
    let base_offset = keys.enc_zero_u64();
    let slab_server_key = keys.server_key();
    let enc_false = keys.enc_false();
    let enc_true = keys.enc_true();
    let enc_zero_u32 = keys.enc_zero_u32();
    let enc_zero_u64 = base_offset.clone();
    let enc_indices_u32 = keys.build_enc_indices_u32(num_blocks);
    let enc_offsets_u64 = keys.build_enc_offsets_u64(num_blocks, block_size);

    let mut _slab = SlabClass::new(
        block_size,
        num_blocks,
        base_offset,
        slab_server_key,
        enc_false,
        enc_true,
        enc_zero_u32,
        enc_zero_u64,
        enc_indices_u32,
        enc_offsets_u64,
    );

    let arena_start = keys.enc_zero_u64();
    let arena_end = keys.enc_u64(4096);
    let arena_server_key = keys.server_key();
    let arena_enc_false = keys.enc_false();
    let arena_enc_zero = keys.enc_zero_u64();
    let arena = Arena::new(
        arena_start,
        arena_end,
        arena_server_key,
        arena_enc_false,
        arena_enc_zero,
    );

    let allocator = CryptMalloc::new(keys, arena);
    let _ptr = allocator.allocate();
    allocator.arena().cursor();
}
