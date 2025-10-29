#[derive(Clone, Debug)]
pub struct SlabClass {
    slot_size: usize,
    slots: usize,
}

impl SlabClass {
    pub fn new(slot_size: usize, slots: usize) -> Self {
        Self { slot_size, slots }
    }

    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    pub fn slots(&self) -> usize {
        self.slots
    }
}
