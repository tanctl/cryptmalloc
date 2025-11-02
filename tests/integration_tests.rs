use cryptmalloc::CryptMalloc;

#[test]
fn allocator_smoke_test() {
    let mut allocator = CryptMalloc::new(4096);
    assert_eq!(allocator.slabs().len(), 5);

    let expected_block_sizes = [16usize, 32, 64, 128, 256];
    for (slab, expected) in allocator.slabs().iter().zip(expected_block_sizes.iter()) {
        assert_eq!(slab.block_size(), *expected);
    }

    let small = allocator.keys().enc_u64(32);
    let _small = allocator.allocate(small);
    allocator.arena().cursor();
}
