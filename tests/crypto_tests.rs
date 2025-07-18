use cryptmalloc::allocator::core::EncryptedAllocator;
use cryptmalloc::types::encrypted::{
    EncryptedBool, EncryptedUint16, EncryptedUint32, EncryptedUint8,
};
use cryptmalloc::types::{
    align_request, choose_smallest, max_option_list, min_array_u8, min_size_array, select_integer,
    EncryptedAddress, EncryptedPointer, EncryptedSize,
};
use cryptmalloc::TfheContext;

#[test]
fn boolean_roundtrip_and_logic() {
    let context = TfheContext::balanced().expect("context initialization");
    let lhs = EncryptedBool::encrypt(true, &context).expect("encrypt lhs");
    let rhs = EncryptedBool::encrypt(false, &context).expect("encrypt rhs");

    let and_cipher = lhs.and(&rhs).expect("and");
    assert!(!and_cipher.decrypt().expect("decrypt and"));

    let xor_cipher = lhs.xor(&rhs).expect("xor");
    assert!(xor_cipher.decrypt().expect("decrypt xor"));

    let negated = lhs.not();
    assert!(!negated.decrypt().expect("decrypt not"));
}

#[test]
fn allocator_trait_signature_compiles() {
    use std::cell::RefCell;

    struct DummyAllocator {
        storage: RefCell<Vec<Vec<EncryptedUint8>>>,
    }

    impl DummyAllocator {
        fn new() -> Self {
            Self {
                storage: RefCell::new(Vec::new()),
            }
        }
    }

    impl EncryptedAllocator for DummyAllocator {
        type Handle = usize;

        fn allocate(&self, ciphertext: &[EncryptedUint8]) -> Self::Handle {
            let mut storage = self.storage.borrow_mut();
            storage.push(ciphertext.to_vec());
            storage.len() - 1
        }

        fn load(&self, handle: &Self::Handle) -> Vec<EncryptedUint8> {
            self.storage
                .borrow()
                .get(*handle)
                .cloned()
                .unwrap_or_default()
        }

        fn deallocate(&self, handle: Self::Handle) {
            if let Some(entry) = self.storage.borrow_mut().get_mut(handle) {
                entry.clear();
            }
        }
    }

    let allocator = DummyAllocator::new();
    let context = TfheContext::balanced().expect("context initialization");
    let payload = vec![EncryptedUint8::encrypt(1, &context).expect("encrypt value")];
    let handle = allocator.allocate(&payload);
    let loaded = allocator.load(&handle);
    assert_eq!(loaded.len(), payload.len());
    allocator.deallocate(handle);
    assert!(allocator.load(&handle).is_empty());
}

#[test]
fn encrypted_integer_arithmetic_behaviour() {
    let context = TfheContext::balanced().expect("context initialization");

    // u8 edge cases
    let a8 = EncryptedUint8::encrypt(200, &context).expect("encrypt a8");
    let b8 = EncryptedUint8::encrypt(100, &context).expect("encrypt b8");
    // comparisons rely on tfhe circuits for constant-time behaviour
    let cmp_a = EncryptedUint8::encrypt(32, &context).expect("encrypt cmp a");
    let cmp_b = EncryptedUint8::encrypt(64, &context).expect("encrypt cmp b");
    let eq_result = cmp_a.eq_cipher(&cmp_b).expect("eq cipher");
    assert!(!eq_result.decrypt().expect("decrypt eq"));
    let lt_result = cmp_a.lt_cipher(&cmp_b).expect("lt cipher");
    assert!(lt_result.decrypt().expect("decrypt lt"));
    let gt_result = cmp_b.gt_cipher(&cmp_a).expect("gt cipher");
    assert!(gt_result.decrypt().expect("decrypt gt"));
    let min_cipher = cmp_a.min_cipher(&cmp_b).expect("min cipher");
    assert_eq!(min_cipher.decrypt().expect("decrypt min"), 32);
    let max_cipher = cmp_a.max_cipher(&cmp_b).expect("max cipher");
    assert_eq!(max_cipher.decrypt().expect("decrypt max"), 64);
    let picked = select_integer(&lt_result, &cmp_a, &cmp_b).expect("select integer");
    assert_eq!(picked.decrypt().expect("decrypt pick"), 32);
    let options = [Some(cmp_a.clone()), None, Some(cmp_b.clone())];
    let best = max_option_list(&options).expect("max option list");
    assert!(best.is_some());
    assert_eq!(best.unwrap().decrypt().expect("decrypt best"), 64);

    let third = EncryptedUint8::encrypt(50, &context).expect("encrypt third");
    let chain_min = min_array_u8::<3>([&cmp_a, &cmp_b, &third]).expect("min array");
    assert_eq!(chain_min.decrypt().expect("decrypt min array"), 32);

    let wrap_add = a8
        .wrapping_add(&b8)
        .expect("wrapping add")
        .decrypt()
        .expect("decrypt wrap add");
    assert_eq!(wrap_add, (200u16 + 100) as u8);
    assert!(a8.checked_add(&b8).is_err());
    let sat_add = a8
        .saturating_add(&b8)
        .expect("saturating add")
        .decrypt()
        .expect("decrypt sat add");
    assert_eq!(sat_add, u8::MAX);

    let c8 = EncryptedUint8::encrypt(5, &context).expect("encrypt c8");
    let d8 = EncryptedUint8::encrypt(3, &context).expect("encrypt d8");
    let checked_sub = c8
        .checked_sub(&d8)
        .expect("checked sub")
        .decrypt()
        .expect("decrypt");
    assert_eq!(checked_sub, 2);
    assert!(d8.checked_sub(&c8).is_err());

    let mul_wrap = c8
        .wrapping_mul(&b8)
        .expect("wrapping mul")
        .decrypt()
        .expect("decrypt mul");
    assert_eq!(mul_wrap, (5u16 * 100) as u8);
    assert!(b8.checked_mul(&b8).is_err());

    let noise_consumed = a8
        .wrapping_add(&EncryptedUint8::encrypt(1, &context).expect("encrypt one"))
        .expect("wrapping add noise")
        .noise_state()
        .consumed();
    assert!(noise_consumed > 0);

    let batch = EncryptedUint8::batch_add(&[(
        &EncryptedUint8::encrypt(1, &context).expect("encrypt x"),
        &EncryptedUint8::encrypt(2, &context).expect("encrypt y"),
    )])
    .expect("batch add");
    assert_eq!(batch[0].decrypt().expect("decrypt batch"), 3);

    // u16 sanity check
    let a16 = EncryptedUint16::encrypt(u16::MAX - 1, &context).expect("encrypt a16");
    let b16 = EncryptedUint16::encrypt(2, &context).expect("encrypt b16");
    let sat16 = a16
        .saturating_add(&b16)
        .expect("sat add")
        .decrypt()
        .expect("decrypt sat16");
    assert_eq!(sat16, u16::MAX);

    // u32 multiplication overflow check
    let a32 = EncryptedUint32::encrypt(65_536, &context).expect("encrypt a32");
    let b32 = EncryptedUint32::encrypt(65_536, &context).expect("encrypt b32");
    assert!(a32.checked_mul(&b32).is_err());
}

#[test]
fn encrypted_size_alignment_and_selection() {
    let context = TfheContext::balanced().expect("context initialization");

    let eight = EncryptedSize::encrypt(8, &context).expect("encrypt eight");
    let sixteen = EncryptedSize::encrypt(16, &context).expect("encrypt sixteen");
    let twenty_four = eight.checked_add(&sixteen).expect("checked add");

    let aligned = align_request(&twenty_four, 8).expect("align request");
    assert_eq!(aligned.decrypt().expect("decrypt aligned"), 24);

    let down = twenty_four.align_down_plain(8).expect("align down");
    assert_eq!(down.decrypt().expect("decrypt down"), 24);

    let min_pair = min_size_array::<2>([&twenty_four, &sixteen]).expect("min encrypted size array");
    assert_eq!(min_pair.decrypt().expect("decrypt min pair"), 16);

    let chosen = choose_smallest(&[twenty_four.clone(), sixteen.clone()]).expect("choose smallest");
    assert_eq!(chosen.decrypt().expect("decrypt chosen"), 16);
}

#[test]
fn encrypted_pointer_selection_and_guard() {
    let context = TfheContext::balanced().expect("context initialization");

    let address_a = EncryptedAddress::encrypt(0x1000, &context).expect("encrypt address a");
    let address_b = EncryptedAddress::encrypt(0x2000, &context).expect("encrypt address b");
    let span = EncryptedSize::encrypt(64, &context).expect("encrypt span");

    let valid_flag = EncryptedBool::encrypt(true, &context).expect("encrypt valid");
    let invalid_flag = EncryptedBool::encrypt(false, &context).expect("encrypt invalid");

    let pointer_a = EncryptedPointer::<u8>::new(address_a, Some(span.clone()), valid_flag.clone())
        .expect("construct pointer a");
    let pointer_b = EncryptedPointer::<u8>::new(address_b, None, invalid_flag.clone())
        .expect("construct pointer b");

    let condition = EncryptedBool::encrypt(true, &context).expect("encrypt condition");
    let selected =
        EncryptedPointer::select(&condition, &pointer_a, &pointer_b).expect("select pointer");
    assert_eq!(
        selected
            .address()
            .decrypt()
            .expect("decrypt selected address"),
        0x1000
    );
    assert!(selected.valid().decrypt().expect("decrypt selected valid"));

    let guard_flag = EncryptedBool::encrypt(false, &context).expect("encrypt guard");
    let guarded = pointer_a.guard(&guard_flag).expect("guard pointer");
    assert!(!guarded.valid().decrypt().expect("decrypt guarded valid"));

    let aligned = pointer_b.align_to(0x100).expect("align pointer");
    assert_eq!(
        aligned
            .address()
            .decrypt()
            .expect("decrypt aligned address"),
        0x2000
    );
}
