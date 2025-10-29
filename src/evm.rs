use crate::allocator::CryptMalloc;

#[derive(Debug)]
pub struct EVM {
    allocator: CryptMalloc,
}

impl EVM {
    pub fn new(allocator: CryptMalloc) -> Self {
        Self { allocator }
    }

    pub fn allocator(&self) -> &CryptMalloc {
        &self.allocator
    }
}
