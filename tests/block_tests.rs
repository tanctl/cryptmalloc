use cryptmalloc::allocator::block::EncryptedMemoryBlock;
use cryptmalloc::types::structures::EncryptedSize;
use cryptmalloc::{SecurityLevel, TfheContext};

fn encrypt_size(value: u32, context: &TfheContext) -> EncryptedSize {
    EncryptedSize::encrypt(value, context).expect("encrypt size")
}

#[test]
fn block_creation_and_validation() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block =
        EncryptedMemoryBlock::with_layout(&context, 0x1000, 128, 1).expect("create block");
    block.set_prev(None, None).expect("clear prev");
    block.set_next(None, None).expect("clear next");
    assert!(block.validate_integrity().expect("validate"));
    assert_eq!(block.address_plain().expect("address"), 0x1000);
    assert_eq!(block.size_plain().expect("size"), 128);
    assert!(!block.is_allocated().expect("allocated flag"));
}

#[test]
fn block_split_wires_links() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block =
        EncryptedMemoryBlock::with_layout(&context, 0x2000, 256, 10).expect("create block");
    let trailing = block
        .split_block(encrypt_size(128, &context), 11, 0x2000 + 128u64)
        .expect("split block");

    assert_eq!(block.size_plain().expect("size lhs"), 128);
    assert_eq!(trailing.size_plain().expect("size rhs"), 128);
    assert_eq!(block.next_handle(), Some(11));
    assert_eq!(trailing.prev_handle(), Some(10));
    assert_eq!(
        block.next_address_plain().expect("next address"),
        Some(trailing.address_plain().expect("trailing address"))
    );
    assert!(block.validate_integrity().expect("validate lhs"));
    assert!(trailing.validate_integrity().expect("validate rhs"));
}

#[test]
fn block_merge_relinks_neighbors() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block =
        EncryptedMemoryBlock::with_layout(&context, 0x3000, 96, 21).expect("create block");
    block.set_next(Some(22), Some(0x3060)).expect("set next");
    let mut trailing =
        EncryptedMemoryBlock::with_layout(&context, 0x3060, 96, 22).expect("create trailing");
    trailing.set_prev(Some(21), Some(0x3000)).expect("set prev");
    let merged = EncryptedMemoryBlock::merge_blocks(block, trailing).expect("merge blocks");
    assert_eq!(merged.size_plain().expect("merged size"), 192);
    assert_eq!(merged.next_handle(), None);
    assert!(merged.validate_integrity().expect("validate merged"));
}

#[test]
fn block_serialization_roundtrip() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block =
        EncryptedMemoryBlock::with_layout(&context, 0x4000, 96, 31).expect("create block");
    block.set_prev(Some(30), Some(0x3fa0)).expect("set prev");
    block.set_next(Some(32), Some(0x4060)).expect("set next");
    block.mark_allocated().expect("mark allocated");

    let payload = block.serialize().expect("serialize block");
    let mut restored =
        EncryptedMemoryBlock::deserialize(&payload, &context).expect("deserialize block");
    restored.set_self_handle(31).expect("restore handle");
    restored
        .set_prev(Some(30), Some(0x3fa0))
        .expect("restore prev");
    restored
        .set_next(Some(32), Some(0x4060))
        .expect("restore next");

    assert!(restored.validate_integrity().expect("validate restored"));
    assert_eq!(restored.handle(), Some(31));
    assert_eq!(restored.prev_handle(), Some(30));
    assert_eq!(restored.next_handle(), Some(32));
    assert!(restored.is_allocated().expect("allocated flag"));
}

#[test]
fn block_detects_corruption() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block =
        EncryptedMemoryBlock::with_layout(&context, 0x5000, 64, 40).expect("create block");
    block.corrupt_checksum().expect("corrupt checksum");
    assert!(!block.validate_integrity().expect("validate corruption"));
}

#[test]
fn block_tamper_prev_handle_detected() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut left = EncryptedMemoryBlock::with_layout(&context, 0x6000, 64, 50).expect("left");
    let mut right = EncryptedMemoryBlock::with_layout(&context, 0x6040, 64, 51).expect("right");
    left.set_next(Some(51), Some(0x6040)).expect("set next");
    right.set_prev(Some(50), Some(0x6000)).expect("set prev");
    assert!(right.validate_integrity().expect("validate baseline"));
    right
        .corrupt_prev_handle_cipher()
        .expect("corrupt prev handle");
    assert!(!right.validate_integrity().expect("validate corruption"));
}

#[test]
fn block_tamper_next_pointer_detected() {
    let context = TfheContext::with_security_level(SecurityLevel::Performance).expect("context");
    let mut block = EncryptedMemoryBlock::with_layout(&context, 0x6100, 64, 60).expect("block");
    block.set_next(Some(61), Some(0x6140)).expect("set next");
    assert!(block.validate_integrity().expect("validate baseline"));
    block
        .corrupt_next_pointer_cipher()
        .expect("corrupt next pointer");
    assert!(!block.validate_integrity().expect("detect"));
}
