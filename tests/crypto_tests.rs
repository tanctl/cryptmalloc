use cryptmalloc::allocator::core::EncryptedAllocator;
use cryptmalloc::types::encrypted::{EncryptedBool, EncryptedUint8};
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
    use cryptmalloc::types::encrypted::{EncryptedUint16, EncryptedUint32, EncryptedUint8};

    let context = TfheContext::balanced().expect("context initialization");

    // u8 edge cases
    let a8 = EncryptedUint8::encrypt(200, &context).expect("encrypt a8");
    let b8 = EncryptedUint8::encrypt(100, &context).expect("encrypt b8");
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
    let d8 = EncryptedUint8::encrypt(5, &context).expect("encrypt d8");
    let checked_sub = c8
        .checked_sub(&d8)
        .expect("checked sub")
        .decrypt()
        .expect("decrypt");
    assert_eq!(checked_sub, 0);
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
