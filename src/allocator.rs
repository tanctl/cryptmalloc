use crate::{arena::Arena, encrypted_ptr::EncryptedPtr, keys::Keys};

#[derive(Debug)]
pub struct CryptMalloc {
    keys: Keys,
    arena: Arena,
}

impl CryptMalloc {
    pub fn new(keys: Keys, arena: Arena) -> Self {
        Self { keys, arena }
    }

    pub fn allocate(&self) -> EncryptedPtr {
        // deterministic placeholder until ciphertext-backed pages are available
        EncryptedPtr::new(self.keys.enc_zero_u64())
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn arena(&self) -> &Arena {
        &self.arena
    }
}
