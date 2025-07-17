use cryptmalloc::crypto::tfhe_context::TfheContextError;
use cryptmalloc::types::encrypted::{EncryptedBool, EncryptedUint32, EncryptedUint8};
use cryptmalloc::{SecurityLevel, TfheContext};

fn main() -> Result<(), TfheContextError> {
    // use the balanced profile by default to keep ciphertext sizes modest without sacrificing correctness
    let context = TfheContext::with_security_level(SecurityLevel::Balanced)?;
    let encrypted_value = EncryptedUint8::encrypt(7, &context)?;
    let encrypted_flag = EncryptedBool::encrypt(true, &context)?;
    let encrypted_large = EncryptedUint32::encrypt(1_048_576, &context)?;

    println!("Decrypted uint8: {}", encrypted_value.decrypt()?);
    println!("Decrypted bool: {}", encrypted_flag.decrypt()?);
    println!("Decrypted uint32: {}", encrypted_large.decrypt()?);

    Ok(())
}
