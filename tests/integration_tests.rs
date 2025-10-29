use cryptmalloc::{Arena, CryptMalloc, Keys, SlabClass};

#[test]
fn allocator_smoke_test() {
    let keys = Keys::new();
    let mut arena = Arena::new();
    arena.register_class(SlabClass::new(64, 32));

    let allocator = CryptMalloc::new(keys, arena);
    let _ptr = allocator.allocate();
    assert_eq!(allocator.arena().classes().len(), 1);
}
