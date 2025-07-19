use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use crate::allocator::block::{BlockHandleValue, EncryptedMemoryBlock};
use crate::crypto::error::CryptoError;
use crate::types::encrypted::EncryptedBool;
use crate::types::structures::{EncryptedAddress, EncryptedPointer, EncryptedSize};
use crate::TfheContext;

#[derive(Debug, thiserror::Error, Clone)]
pub enum PoolError {
    #[error("pool configuration exceeds supported range")]
    InvalidSize,
    #[error("alignment must be a non-zero power of two")]
    InvalidAlignment,
    #[error("invalid pool operation: {0}")]
    InvalidOperation(&'static str),
    #[error("pool integrity check failed")]
    IntegrityViolation,
    #[error("pool has insufficient free capacity")]
    OutOfMemory,
    #[error("handle space exhausted")]
    HandleSpaceExhausted,
    #[error("pool lock poisoned")]
    LockPoisoned,
    #[error("handle not found in pool")]
    UnknownHandle,
    #[error("block is already released")]
    DoubleFree,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl<T> From<std::sync::PoisonError<T>> for PoolError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        PoolError::LockPoisoned
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHandle(BlockHandleValue);

impl BlockHandle {
    fn new(value: BlockHandleValue) -> Self {
        Self(value)
    }

    fn to_index(self) -> usize {
        self.0 as usize
    }

    pub fn value(self) -> BlockHandleValue {
        self.0
    }
}

#[derive(Clone)]
struct PoolMetadata {
    capacity: EncryptedSize,
    base_address: EncryptedAddress,
    min_alignment: u32,
}

#[derive(Clone, Copy)]
struct PlainMetadata {
    total_bytes: u32,
    base_address: u64,
    min_alignment: u32,
}

#[derive(Clone)]
pub struct VirtualMemoryPool {
    context: TfheContext,
    metadata: PoolMetadata,
    plain: PlainMetadata,
    state: Arc<RwLock<PoolState>>,
    digest: [u8; 32],
}

struct PoolState {
    blocks: Vec<Option<BlockRecord>>,
    free_list: Vec<BlockHandle>,
    vacant_handles: Vec<BlockHandle>,
    access_log: Vec<AccessRecord>,
    base_address: u64,
    used_bytes: u32,
    allocations: usize,
    deallocations: usize,
    next_handle: u64,
    timestamp: u64,
}

struct BlockRecord {
    handle: BlockHandle,
    block: EncryptedMemoryBlock,
    size_plain: u32,
    start_addr_plain: u64,
    alignment: u32,
    free: bool,
    prev: Option<BlockHandle>,
    next: Option<BlockHandle>,
    hits: u64,
}

#[derive(Clone)]
struct AccessRecord {
    address: u64,
    timestamp: u64,
}

#[derive(Clone)]
pub struct BlockView {
    pub handle: BlockHandle,
    pub address: EncryptedAddress,
    pub size: EncryptedSize,
    pub allocated: bool,
    pub alignment: u32,
    pub hits: u64,
}

pub struct BlockSnapshot {
    blocks: Vec<BlockView>,
    index: usize,
}

#[derive(Clone)]
pub struct PoolStats {
    pub total: EncryptedSize,
    pub used: EncryptedSize,
    pub free: EncryptedSize,
    pub utilization: f64,
    pub fragmentation: f64,
    pub allocations: usize,
    pub deallocations: usize,
    pub access_events: usize,
    pub last_access_timestamp: Option<u64>,
    pub last_access_address: Option<EncryptedAddress>,
}

impl VirtualMemoryPool {
    pub fn builder(context: TfheContext) -> VirtualMemoryPoolBuilder {
        VirtualMemoryPoolBuilder::new(context)
    }

    pub fn verify_integrity(&self) -> Result<(), PoolError> {
        let capacity = self.metadata.capacity.decrypt()?;
        let base = self.metadata.base_address.decrypt()?;
        if capacity != self.plain.total_bytes || base != self.plain.base_address {
            return Err(PoolError::IntegrityViolation);
        }
        if self.metadata.min_alignment != self.plain.min_alignment {
            return Err(PoolError::IntegrityViolation);
        }
        let mut hasher = Sha256::new();
        hasher.update(self.plain.total_bytes.to_le_bytes());
        hasher.update(self.plain.base_address.to_le_bytes());
        hasher.update(self.plain.min_alignment.to_le_bytes());
        let digest_bytes: [u8; 32] = hasher.finalize().into();
        if digest_bytes != self.digest {
            return Err(PoolError::IntegrityViolation);
        }
        Ok(())
    }

    pub fn allocate_block(&self, size: u32, alignment: u32) -> Result<BlockHandle, PoolError> {
        if size == 0 {
            return Err(PoolError::InvalidSize);
        }
        self.verify_integrity()?;
        let mut guard = self.state.write()?;
        let req_alignment = alignment.max(self.plain.min_alignment);
        if req_alignment == 0 || !req_alignment.is_power_of_two() {
            return Err(PoolError::InvalidAlignment);
        }

        let (candidate_handle, head_padding) = guard
            .find_fit(size, req_alignment)
            .ok_or(PoolError::OutOfMemory)?;

        let mut target_handle = candidate_handle;
        if head_padding > 0 {
            let padding = u32::try_from(head_padding)
                .map_err(|_| PoolError::InvalidOperation("padding exceeds 32-bit range"))?;
            target_handle = guard.split_block(&self.context, candidate_handle, padding)?;
        }

        if guard.blocks[target_handle.to_index()]
            .as_ref()
            .map(|record| record.size_plain as u64 > u64::from(size))
            .unwrap_or(false)
        {
            guard.split_block(&self.context, target_handle, size)?;
        }

        let size_plain;
        {
            let record = guard.blocks[target_handle.to_index()]
                .as_mut()
                .ok_or(PoolError::UnknownHandle)?;
            if !record.free {
                return Err(PoolError::InvalidOperation("block already allocated"));
            }
            record.free = false;
            record.alignment = req_alignment;
            record.hits = 0;
            record.block.mark_allocated().map_err(PoolError::from)?;
            size_plain = record.size_plain;
        }
        guard.remove_from_free_list(target_handle);
        guard.used_bytes = guard.used_bytes.saturating_add(size_plain);
        guard.allocations += 1;
        guard.rebuild_box_links();
        Ok(target_handle)
    }

    pub fn release_block(&self, handle: BlockHandle) -> Result<(), PoolError> {
        self.verify_integrity()?;
        let mut guard = self.state.write()?;
        let size_plain;
        {
            let record = guard.blocks[handle.to_index()]
                .as_mut()
                .ok_or(PoolError::UnknownHandle)?;
            if record.free {
                return Err(PoolError::DoubleFree);
            }
            record.free = true;
            record.block.mark_free().map_err(PoolError::from)?;
            size_plain = record.size_plain;
        }

        guard.used_bytes = guard.used_bytes.saturating_sub(size_plain);
        guard.deallocations += 1;

        let mut current_handle = handle;

        if let Some(prev_handle) = guard.blocks[handle.to_index()]
            .as_ref()
            .and_then(|record| record.prev)
        {
            let should_merge = guard.blocks[prev_handle.to_index()]
                .as_ref()
                .map(|record| record.free)
                .unwrap_or(false);
            if should_merge {
                current_handle = guard.merge_adjacent(prev_handle, current_handle)?;
            }
        }

        if let Some(next_handle) = guard.blocks[current_handle.to_index()]
            .as_ref()
            .and_then(|record| record.next)
        {
            let should_merge = guard.blocks[next_handle.to_index()]
                .as_ref()
                .map(|record| record.free)
                .unwrap_or(false);
            if should_merge {
                guard.merge_adjacent(current_handle, next_handle)?;
            }
        }

        guard.insert_into_free_list(current_handle);
        guard.rebuild_box_links();
        Ok(())
    }

    pub fn record_access(&self, handle: BlockHandle) -> Result<(), PoolError> {
        let mut guard = self.state.write()?;
        guard.timestamp = guard.timestamp.saturating_add(1);
        let timestamp = guard.timestamp;
        let address;
        {
            let record = guard.blocks[handle.to_index()]
                .as_mut()
                .ok_or(PoolError::UnknownHandle)?;
            record.hits = record.hits.saturating_add(1);
            address = record.block.address_plain().map_err(PoolError::from)?;
        }
        guard.access_log.push(AccessRecord { address, timestamp });
        guard.rebuild_box_links();
        Ok(())
    }

    pub fn stats(&self) -> Result<PoolStats, PoolError> {
        self.verify_integrity()?;
        let guard = self.state.read()?;
        let total = EncryptedSize::encrypt(self.plain.total_bytes, &self.context)?;
        let used = EncryptedSize::encrypt(guard.used_bytes, &self.context)?;
        let free_bytes = self.plain.total_bytes.saturating_sub(guard.used_bytes);
        let free = EncryptedSize::encrypt(free_bytes, &self.context)?;
        let utilization = if self.plain.total_bytes == 0 {
            0.0
        } else {
            f64::from(guard.used_bytes) / f64::from(self.plain.total_bytes)
        };
        let fragmentation = guard.fragmentation_ratio();
        let last = guard.access_log.last().cloned();
        let (last_timestamp, last_address) = if let Some(entry) = last {
            let enc_address = EncryptedAddress::encrypt(entry.address, &self.context)?;
            (Some(entry.timestamp), Some(enc_address))
        } else {
            (None, None)
        };
        Ok(PoolStats {
            total,
            used,
            free,
            utilization,
            fragmentation,
            allocations: guard.allocations,
            deallocations: guard.deallocations,
            access_events: guard.access_log.len(),
            last_access_timestamp: last_timestamp,
            last_access_address: last_address,
        })
    }

    pub fn block_snapshot(&self) -> Result<BlockSnapshot, PoolError> {
        let guard = self.state.read()?;
        let mut blocks = Vec::new();
        for record in guard.blocks.iter().filter_map(|entry| entry.as_ref()) {
            blocks.push(BlockView {
                handle: record.handle,
                address: record.block.address().clone(),
                size: record.block.size().clone(),
                allocated: !record.free,
                alignment: record.alignment,
                hits: record.hits,
            });
        }
        Ok(BlockSnapshot { blocks, index: 0 })
    }

    pub fn base_pointer<T>(&self) -> Result<EncryptedPointer<T>, PoolError> {
        let valid_flag = EncryptedBool::encrypt(true, &self.context)
            .map_err(|err| PoolError::from(CryptoError::from(err)))?;
        EncryptedPointer::new(
            self.metadata.base_address.clone(),
            Some(self.metadata.capacity.clone()),
            valid_flag,
        )
        .map_err(PoolError::from)
    }

    pub fn rebuild_box_links(&self) -> Result<(), PoolError> {
        let mut guard = self.state.write()?;
        guard.rebuild_box_links();
        Ok(())
    }

    pub fn snapshot_block(
        &self,
        handle: BlockHandle,
    ) -> Result<Option<EncryptedMemoryBlock>, PoolError> {
        let guard = self.state.read()?;
        Ok(guard
            .blocks
            .get(handle.to_index())
            .and_then(|entry| entry.as_ref())
            .map(|record| record.block.snapshot()))
    }
}

impl Display for VirtualMemoryPool {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.stats() {
            Ok(stats) => write!(
                f,
                "pool total={} used={} util={:.2}% frag={:.2} alloc={} free={}",
                stats.total,
                stats.used,
                stats.utilization * 100.0,
                stats.fragmentation,
                stats.allocations,
                stats.deallocations
            ),
            Err(_) => write!(f, "<pool unavailable>"),
        }
    }
}

impl Drop for VirtualMemoryPool {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.write() {
            guard.blocks.clear();
            guard.free_list.clear();
            guard.vacant_handles.clear();
            guard.access_log.clear();
        }
    }
}

impl Iterator for BlockSnapshot {
    type Item = BlockView;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.blocks.len() {
            None
        } else {
            let item = self.blocks[self.index].clone();
            self.index += 1;
            Some(item)
        }
    }
}

impl PoolState {
    fn new(base_address: u64) -> Self {
        Self {
            blocks: Vec::new(),
            free_list: Vec::new(),
            vacant_handles: Vec::new(),
            access_log: Vec::new(),
            base_address,
            used_bytes: 0,
            allocations: 0,
            deallocations: 0,
            next_handle: 0,
            timestamp: 0,
        }
    }

    fn ensure_slot(&mut self, handle: BlockHandle) {
        let index = handle.to_index();
        while index >= self.blocks.len() {
            self.blocks.push(None);
        }
    }

    fn alloc_handle(&mut self) -> Result<BlockHandle, PoolError> {
        if let Some(handle) = self.vacant_handles.pop() {
            return Ok(handle);
        }

        if self.next_handle > u64::from(BlockHandleValue::MAX) {
            return Err(PoolError::HandleSpaceExhausted);
        }

        let value = BlockHandleValue::try_from(self.next_handle)
            .expect("handle value within bounds after guard");
        let handle = BlockHandle::new(value);
        self.next_handle += 1;
        Ok(handle)
    }

    fn release_handle(&mut self, handle: BlockHandle) {
        self.vacant_handles.push(handle);
    }

    fn insert_block(&mut self, record: BlockRecord) {
        let handle = record.handle;
        self.ensure_slot(handle);
        self.blocks[handle.to_index()] = Some(record);
    }

    fn find_fit(&self, size: u32, alignment: u32) -> Option<(BlockHandle, u64)> {
        let required = u64::from(size);
        for &handle in &self.free_list {
            let record = self.blocks[handle.to_index()].as_ref()?;
            let start = record.start_addr_plain;
            let mask = alignment as u64 - 1;
            let misalign = start & mask;
            let padding = if misalign == 0 {
                0
            } else {
                alignment as u64 - misalign
            };
            let available = u64::from(record.size_plain);
            if available >= padding + required {
                return Some((handle, padding));
            }
        }
        None
    }

    fn split_block(
        &mut self,
        context: &TfheContext,
        handle: BlockHandle,
        leading_size: u32,
    ) -> Result<BlockHandle, PoolError> {
        {
            let record = self
                .blocks
                .get(handle.to_index())
                .and_then(Option::as_ref)
                .ok_or(PoolError::UnknownHandle)?;
            if !record.free {
                return Err(PoolError::InvalidOperation("block not free"));
            }
            if leading_size == 0 || leading_size >= record.size_plain {
                return Err(PoolError::InvalidSize);
            }
        }

        let new_handle = self.alloc_handle()?;
        let leading_size_enc = EncryptedSize::encrypt(leading_size, context)?;

        let (
            trailing_block,
            trailing_address,
            trailing_size,
            old_next,
            leading_alignment,
            leading_start,
        ) = {
            let record = self
                .blocks
                .get_mut(handle.to_index())
                .and_then(Option::as_mut)
                .ok_or(PoolError::UnknownHandle)?;
            let trailing_address = record.start_addr_plain + u64::from(leading_size);
            let trailing_size = record.size_plain - leading_size;
            let old_next = record.next;
            let leading_alignment = record.alignment;
            let leading_start = record.start_addr_plain;
            let trailing_block = record
                .block
                .split_block(leading_size_enc, new_handle.value(), trailing_address)
                .map_err(PoolError::from)?;
            record.size_plain = leading_size;
            record.next = Some(new_handle);
            record
                .block
                .set_next(Some(new_handle.value()), Some(trailing_address))
                .map_err(PoolError::from)?;
            (
                trailing_block,
                trailing_address,
                trailing_size,
                old_next,
                leading_alignment,
                leading_start,
            )
        };

        let trailing_record = BlockRecord {
            handle: new_handle,
            block: trailing_block,
            size_plain: trailing_size,
            start_addr_plain: trailing_address,
            alignment: leading_alignment,
            free: true,
            prev: Some(handle),
            next: old_next,
            hits: 0,
        };

        self.ensure_slot(new_handle);
        self.blocks[new_handle.to_index()] = Some(trailing_record);

        let next_after_new;
        {
            let trailing_entry = self.blocks[new_handle.to_index()]
                .as_mut()
                .expect("trailing entry exists");
            trailing_entry
                .block
                .set_prev(Some(handle.value()), Some(leading_start))
                .map_err(PoolError::from)?;
            next_after_new = trailing_entry.next;
            if next_after_new.is_none() {
                trailing_entry
                    .block
                    .set_next(None, None)
                    .map_err(PoolError::from)?;
            }
        }

        if let Some(next_handle) = next_after_new {
            let next_addr = self
                .blocks
                .get(next_handle.to_index())
                .and_then(Option::as_ref)
                .map(|rec| rec.start_addr_plain);
            if let Some(entry) = self.blocks[new_handle.to_index()].as_mut() {
                entry
                    .block
                    .set_next(Some(next_handle.value()), next_addr)
                    .map_err(PoolError::from)?;
            }
        }

        if let Some(next_handle) = old_next {
            if let Some(next_record) = self.blocks[next_handle.to_index()].as_mut() {
                next_record.prev = Some(new_handle);
                next_record
                    .block
                    .set_prev(Some(new_handle.value()), Some(trailing_address))
                    .map_err(PoolError::from)?;
            }
        }

        self.insert_into_free_list(new_handle);
        self.rebuild_box_links();
        Ok(new_handle)
    }

    fn merge_adjacent(
        &mut self,
        left_handle: BlockHandle,
        right_handle: BlockHandle,
    ) -> Result<BlockHandle, PoolError> {
        let right_index = right_handle.to_index();
        let left_index = left_handle.to_index();

        let mut right_record = self.blocks[right_index]
            .take()
            .ok_or(PoolError::UnknownHandle)?;
        let left_is_free = self
            .blocks
            .get(left_index)
            .and_then(Option::as_ref)
            .map(|record| record.free)
            .unwrap_or(false);
        if !left_is_free || !right_record.free {
            self.blocks[right_index] = Some(right_record);
            return Err(PoolError::InvalidOperation("merge requires free blocks"));
        }

        let left_end = self.blocks[left_index]
            .as_ref()
            .map(|record| record.start_addr_plain + u64::from(record.size_plain))
            .unwrap_or(self.base_address);
        if left_end != right_record.start_addr_plain {
            self.blocks[right_index] = Some(right_record);
            return Err(PoolError::InvalidOperation("blocks not adjacent"));
        }

        let (next_after, left_start) = {
            let left_record = self.blocks[left_index]
                .as_mut()
                .ok_or(PoolError::UnknownHandle)?;
            left_record
                .block
                .absorb_right(&right_record.block)
                .map_err(PoolError::from)?;
            left_record.size_plain = left_record
                .size_plain
                .saturating_add(right_record.size_plain);
            left_record.next = right_record.next;
            let next_pointer_plain = right_record.block.next_address_plain()?;
            left_record
                .block
                .set_next(right_record.next.map(|h| h.value()), next_pointer_plain)
                .map_err(PoolError::from)?;
            (left_record.next, left_record.start_addr_plain)
        };

        if let Some(next_handle) = next_after {
            if let Some(next_record) = self.blocks[next_handle.to_index()].as_mut() {
                next_record.prev = Some(left_handle);
                next_record
                    .block
                    .set_prev(Some(left_handle.value()), Some(left_start))
                    .map_err(PoolError::from)?;
            }
        }

        self.remove_from_free_list(right_handle);
        right_record.block.zeroize_sensitive();
        self.blocks[right_index] = None;
        self.release_handle(right_handle);
        self.rebuild_box_links();
        Ok(left_handle)
    }

    fn insert_into_free_list(&mut self, handle: BlockHandle) {
        if !self.free_list.contains(&handle) {
            self.free_list.push(handle);
        }
    }

    fn remove_from_free_list(&mut self, handle: BlockHandle) {
        self.free_list.retain(|candidate| *candidate != handle);
    }

    fn fragmentation_ratio(&self) -> f64 {
        let free_blocks: Vec<&BlockRecord> = self
            .blocks
            .iter()
            .filter_map(|entry| entry.as_ref())
            .filter(|record| record.free)
            .collect();
        if free_blocks.is_empty() {
            return 0.0;
        }
        let total_free: u64 = free_blocks
            .iter()
            .map(|record| u64::from(record.size_plain))
            .sum();
        let largest_free: u64 = free_blocks
            .iter()
            .map(|record| u64::from(record.size_plain))
            .max()
            .unwrap_or(0);
        if total_free == 0 {
            0.0
        } else {
            1.0 - (largest_free as f64 / total_free as f64)
        }
    }

    fn rebuild_box_links(&mut self) {
        let snapshots: Vec<Option<Box<EncryptedMemoryBlock>>> = self
            .blocks
            .iter()
            .map(|entry| entry.as_ref().map(|record| record.block.link_clone_box()))
            .collect();

        for record_opt in self.blocks.iter_mut() {
            if let Some(record) = record_opt {
                let prev_box = record.prev.and_then(|handle| {
                    snapshots
                        .get(handle.to_index())
                        .and_then(|opt| opt.as_deref())
                });
                record.block.set_prev_box(prev_box);

                let next_box = record.next.and_then(|handle| {
                    snapshots
                        .get(handle.to_index())
                        .and_then(|opt| opt.as_deref())
                });
                record.block.set_next_box(next_box);
            }
        }
    }
}

impl BlockRecord {
    fn new(
        handle: BlockHandle,
        block: EncryptedMemoryBlock,
        start_addr_plain: u64,
        size_plain: u32,
        alignment: u32,
        free: bool,
    ) -> Self {
        Self {
            handle,
            block,
            size_plain,
            start_addr_plain,
            alignment,
            free,
            prev: None,
            next: None,
            hits: 0,
        }
    }
}

pub struct VirtualMemoryPoolBuilder {
    context: TfheContext,
    total_bytes: u32,
    base_address: u64,
    min_alignment: u32,
}

impl VirtualMemoryPoolBuilder {
    fn new(context: TfheContext) -> Self {
        Self {
            context,
            total_bytes: 4 * 1024,
            base_address: 0x1000,
            min_alignment: 16,
        }
    }

    pub fn pool_bytes(mut self, bytes: u32) -> Self {
        self.total_bytes = bytes;
        self
    }

    pub fn base_address(mut self, address: u64) -> Self {
        self.base_address = address;
        self
    }

    pub fn min_alignment(mut self, alignment: u32) -> Self {
        self.min_alignment = alignment;
        self
    }

    pub fn build(self) -> Result<VirtualMemoryPool, PoolError> {
        if self.total_bytes < 4 * 1024 || self.total_bytes > (1 << 30) {
            return Err(PoolError::InvalidSize);
        }
        if self.min_alignment == 0 || !self.min_alignment.is_power_of_two() {
            return Err(PoolError::InvalidAlignment);
        }

        let capacity = EncryptedSize::encrypt(self.total_bytes, &self.context)?;
        let base_address = EncryptedAddress::encrypt(self.base_address, &self.context)?;
        let metadata = PoolMetadata {
            capacity,
            base_address,
            min_alignment: self.min_alignment,
        };
        let plain = PlainMetadata {
            total_bytes: self.total_bytes,
            base_address: self.base_address,
            min_alignment: self.min_alignment,
        };

        let mut hasher = Sha256::new();
        hasher.update(plain.total_bytes.to_le_bytes());
        hasher.update(plain.base_address.to_le_bytes());
        hasher.update(plain.min_alignment.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();

        let mut state = PoolState::new(self.base_address);
        let initial_handle = state.alloc_handle()?;
        let mut initial_block = EncryptedMemoryBlock::with_layout(
            &self.context,
            self.base_address,
            self.total_bytes,
            initial_handle.value(),
        )?;
        initial_block
            .set_prev(None, None)
            .map_err(PoolError::from)?;
        initial_block
            .set_next(None, None)
            .map_err(PoolError::from)?;
        let record = BlockRecord::new(
            initial_handle,
            initial_block,
            self.base_address,
            self.total_bytes,
            self.min_alignment,
            true,
        );
        state.insert_block(record);
        state.insert_into_free_list(initial_handle);
        state.rebuild_box_links();

        let pool = VirtualMemoryPool {
            context: self.context,
            metadata,
            plain,
            state: Arc::new(RwLock::new(state)),
            digest,
        };
        pool.verify_integrity()?;
        Ok(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_id_space_exhaustion_returns_error() {
        let mut state = PoolState::new(0);
        state.next_handle = u64::from(BlockHandleValue::MAX);

        let last = state
            .alloc_handle()
            .expect("allocate final available handle");
        assert_eq!(last.value(), BlockHandleValue::MAX);

        state.release_handle(last);

        let recycled = state
            .alloc_handle()
            .expect("recycle freed handle after exhaustion");
        assert_eq!(recycled.value(), BlockHandleValue::MAX);

        assert!(matches!(
            state.alloc_handle(),
            Err(PoolError::HandleSpaceExhausted)
        ));
    }
}
