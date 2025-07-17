use cryptmalloc::types::encrypted::{EncryptedUint16, EncryptedUint32, EncryptedUint8};
use cryptmalloc::TfheContext;

#[test]
fn integer_roundtrip_and_addition() {
    let context = TfheContext::balanced().expect("context initialization");
    let value = 21_u8;
    let encrypted = EncryptedUint8::encrypt(value, &context).expect("encrypt value");
    assert_eq!(encrypted.decrypt().expect("decrypt value"), value);

    let rhs = EncryptedUint8::encrypt(21, &context).expect("encrypt rhs");
    let sum_cipher = encrypted.wrapping_add(&rhs).expect("homomorphic add");
    let sum = sum_cipher.decrypt().expect("decrypt sum");
    assert_eq!(sum, 42);

    let word = EncryptedUint16::encrypt(512, &context).expect("encrypt u16");
    let word_sum = word.wrapping_add(&word).expect("homomorphic add");
    assert_eq!(word_sum.decrypt().expect("decrypt"), 1024);

    let dword = EncryptedUint32::encrypt(1_024, &context).expect("encrypt u32");
    let dword_sum = dword.wrapping_add(&dword).expect("homomorphic add");
    assert_eq!(dword_sum.decrypt().expect("decrypt"), 2_048);
}
