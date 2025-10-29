use crate::slab::SlabClass;

#[derive(Debug, Default)]
pub struct Arena {
    slabs: Vec<SlabClass>,
}

impl Arena {
    pub fn new() -> Self {
        Self { slabs: Vec::new() }
    }

    pub fn register_class(&mut self, class: SlabClass) {
        // order is significant for oblivious traversals so preserve insertion sequencing
        self.slabs.push(class);
    }

    pub fn classes(&self) -> &[SlabClass] {
        &self.slabs
    }
}
