/// EncryptedPtr carries a single `FheUint64` byte offset; null is `EncryptedPtr(enc_zero_u64)` and no plaintext address math ever happens.
/// Downstream slabs treat the wrapped ciphertext as the full pointer payload and rely on `refresh_global_server_key()` before constructing one.
use crate::keys::refresh_global_server_key;
use core::fmt;
use tfhe::FheUint64;

#[derive(Clone)]
pub struct EncryptedPtr(pub FheUint64);

impl EncryptedPtr {
    pub fn new(offset: FheUint64) -> Self {
        refresh_global_server_key();
        Self(offset)
    }
}

impl fmt::Debug for EncryptedPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncryptedPtr")
            .field(&"<ciphertext>")
            .finish()
    }
}
