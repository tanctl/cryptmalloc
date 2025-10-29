//! Cryptmalloc is a fully homomorphic allocator; tfhe-rs 1.4 drives every ciphertext operation end-to-end.
//! Constant-time, oblivious memory management keeps access patterns hidden and never emits plaintext metadata or ciphertext branches.

pub mod allocator;
pub mod arena;
pub mod encrypted_option;
pub mod encrypted_ptr;
pub mod evm;
pub mod keys;
pub mod slab;

pub use allocator::CryptMalloc;
pub use arena::Arena;
pub use encrypted_option::EncryptedOption;
pub use encrypted_ptr::EncryptedPtr;
pub use evm::EVM;
pub use keys::Keys;
pub use slab::SlabClass;
