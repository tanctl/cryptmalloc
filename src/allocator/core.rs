use crate::types::encrypted::EncryptedUint8;

pub trait EncryptedAllocator {
    type Handle: Clone;

    fn allocate(&self, ciphertext: &[EncryptedUint8]) -> Self::Handle;

    fn load(&self, handle: &Self::Handle) -> Vec<EncryptedUint8>;

    fn deallocate(&self, handle: Self::Handle);
}
