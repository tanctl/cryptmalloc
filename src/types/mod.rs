pub mod encrypted_bool;
pub mod encrypted_int;

pub mod encrypted {
    pub use super::encrypted_bool::EncryptedBool;
    pub use super::encrypted_int::{EncryptedUint16, EncryptedUint32, EncryptedUint8};
}
