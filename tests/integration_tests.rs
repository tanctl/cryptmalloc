use cryptmalloc::{Arena, CryptMalloc, Keys, SlabClass};

#[test]
fn allocator_smoke_test() {
    let keys = Keys::new();
    let mut arena = Arena::new();
    let block_size = 64;
    let num_blocks = 32;
    let base_offset = keys.enc_zero_u64();
    let server_key = keys.server_key();
    let enc_false = keys.enc_false();
    let enc_true = keys.enc_true();
    let enc_zero_u32 = keys.enc_zero_u32();
    let enc_zero_u64 = base_offset.clone();
    let enc_indices_u32 = keys.build_enc_indices_u32(num_blocks);
    let enc_offsets_u64 = keys.build_enc_offsets_u64(num_blocks, block_size);

    arena.register_class(SlabClass::new(
        block_size,
        num_blocks,
        base_offset,
        server_key,
        enc_false,
        enc_true,
        enc_zero_u32,
        enc_zero_u64,
        enc_indices_u32,
        enc_offsets_u64,
    ));

    let allocator = CryptMalloc::new(keys, arena);
    let _ptr = allocator.allocate();
    assert_eq!(allocator.arena().classes().len(), 1);
}
