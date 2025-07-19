use std::fmt::{self, Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::error::{CryptoError, InvalidOperationError};
use crate::types::encrypted::{EncryptedBool, EncryptedUint32, EncryptedUint64};
use crate::types::structures::{EncryptedAddress, EncryptedSize};
use crate::TfheContext;

pub type BlockHandleValue = u32;

const CURRENT_VERSION: u32 = 1;

fn default_context() -> TfheContext {
    TfheContext::balanced().expect("context initialization")
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMemoryBlock {
    #[serde(skip, default = "default_context")]
    context: TfheContext,
    address: EncryptedAddress,
    size: EncryptedSize,
    allocated: EncryptedBool,
    checksum: EncryptedUint32,
    version: EncryptedUint32,
    prev_pointer: Option<EncryptedAddress>,
    next_pointer: Option<EncryptedAddress>,
    #[serde(skip, default)]
    prev_box: Option<Box<EncryptedMemoryBlock>>,
    #[serde(skip, default)]
    next_box: Option<Box<EncryptedMemoryBlock>>,
    #[serde(skip, default)]
    prev_handle_enc: Option<EncryptedUint32>,
    #[serde(skip, default)]
    next_handle_enc: Option<EncryptedUint32>,
    #[serde(skip, default)]
    self_handle: Option<BlockHandleValue>,
    #[serde(skip, default)]
    prev_handle: Option<BlockHandleValue>,
    #[serde(skip, default)]
    next_handle: Option<BlockHandleValue>,
}

impl Debug for EncryptedMemoryBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedMemoryBlock")
            .field("address", &self.address)
            .field("size", &self.size)
            .field("allocated", &self.allocated)
            .field("prev_pointer", &self.prev_pointer)
            .field("next_pointer", &self.next_pointer)
            .finish_non_exhaustive()
    }
}

impl EncryptedMemoryBlock {
    pub fn create_block(size: EncryptedSize) -> Result<Self, CryptoError> {
        let context = size.context().clone();
        let plain_size = size.decrypt()?;
        let mut block = Self::with_layout(&context, 0, plain_size, BlockHandleValue::MAX)?;
        block.size = size;
        block.refresh_checksum()?;
        Ok(block)
    }

    pub fn with_layout(
        context: &TfheContext,
        address: u64,
        size: u32,
        handle: BlockHandleValue,
    ) -> Result<Self, CryptoError> {
        let address_cipher = EncryptedAddress::encrypt(address, context)?;
        let size_cipher = EncryptedSize::encrypt(size, context)?;
        Self::from_parts(context.clone(), address_cipher, size_cipher, handle)
    }

    fn from_parts(
        context: TfheContext,
        address: EncryptedAddress,
        size: EncryptedSize,
        handle: BlockHandleValue,
    ) -> Result<Self, CryptoError> {
        let allocated = EncryptedBool::encrypt(false, &context)?;
        let checksum_placeholder = EncryptedUint32::encrypt(0, &context)?;
        let version = EncryptedUint32::encrypt(CURRENT_VERSION, &context)?;
        let mut block = Self {
            context,
            address,
            size,
            allocated,
            checksum: checksum_placeholder,
            version,
            prev_pointer: None,
            next_pointer: None,
            prev_box: None,
            next_box: None,
            prev_handle_enc: None,
            next_handle_enc: None,
            self_handle: Some(handle),
            prev_handle: None,
            next_handle: None,
        };
        block.refresh_checksum()?;
        Ok(block)
    }

    pub fn context(&self) -> &TfheContext {
        &self.context
    }

    pub fn handle(&self) -> Option<BlockHandleValue> {
        self.self_handle
    }

    pub fn set_self_handle(&mut self, handle: BlockHandleValue) -> Result<(), CryptoError> {
        self.self_handle = Some(handle);
        self.refresh_checksum()
    }

    pub fn address(&self) -> &EncryptedAddress {
        &self.address
    }

    pub fn address_plain(&self) -> Result<u64, CryptoError> {
        self.address.decrypt().map_err(CryptoError::from)
    }

    pub fn set_address(&mut self, address: u64) -> Result<(), CryptoError> {
        self.address = EncryptedAddress::encrypt(address, &self.context)?;
        self.refresh_checksum()
    }

    pub fn size(&self) -> &EncryptedSize {
        &self.size
    }

    pub fn size_plain(&self) -> Result<u32, CryptoError> {
        self.size.decrypt().map_err(CryptoError::from)
    }

    pub fn set_size_plain(&mut self, size: u32) -> Result<(), CryptoError> {
        self.size = EncryptedSize::encrypt(size, &self.context)?;
        self.refresh_checksum()
    }

    pub fn allocation_status(&self) -> &EncryptedBool {
        &self.allocated
    }

    pub fn is_allocated(&self) -> Result<bool, CryptoError> {
        self.allocated.decrypt().map_err(CryptoError::from)
    }

    pub fn mark_allocated(&mut self) -> Result<(), CryptoError> {
        self.allocated = EncryptedBool::encrypt(true, &self.context)?;
        self.refresh_checksum()
    }

    pub fn mark_free(&mut self) -> Result<(), CryptoError> {
        self.allocated = EncryptedBool::encrypt(false, &self.context)?;
        self.refresh_checksum()
    }

    pub fn prev_handle(&self) -> Option<BlockHandleValue> {
        self.prev_handle
    }

    pub fn next_handle(&self) -> Option<BlockHandleValue> {
        self.next_handle
    }

    pub fn set_prev(
        &mut self,
        handle: Option<BlockHandleValue>,
        address: Option<u64>,
    ) -> Result<(), CryptoError> {
        self.prev_handle = handle;
        self.prev_handle_enc = self.encrypt_handle(handle)?;
        self.prev_pointer = match address {
            Some(value) => Some(EncryptedAddress::encrypt(value, &self.context)?),
            None => None,
        };
        self.refresh_checksum()
    }

    pub fn set_next(
        &mut self,
        handle: Option<BlockHandleValue>,
        address: Option<u64>,
    ) -> Result<(), CryptoError> {
        self.next_handle = handle;
        self.next_handle_enc = self.encrypt_handle(handle)?;
        self.next_pointer = match address {
            Some(value) => Some(EncryptedAddress::encrypt(value, &self.context)?),
            None => None,
        };
        self.refresh_checksum()
    }

    pub fn set_prev_box(&mut self, block: Option<&EncryptedMemoryBlock>) {
        self.prev_box = block.map(|node| node.link_clone_box());
    }

    pub fn set_next_box(&mut self, block: Option<&EncryptedMemoryBlock>) {
        self.next_box = block.map(|node| node.link_clone_box());
    }

    pub fn has_prev_box(&self) -> bool {
        self.prev_box.is_some()
    }

    pub fn has_next_box(&self) -> bool {
        self.next_box.is_some()
    }

    pub fn split_block(
        &mut self,
        leading_size: EncryptedSize,
        new_handle: BlockHandleValue,
        new_address: u64,
    ) -> Result<EncryptedMemoryBlock, CryptoError> {
        let leading_plain = leading_size.decrypt()?;
        let total_plain = self.size.decrypt()?;
        if leading_plain == 0 || leading_plain >= total_plain {
            return Err(InvalidOperationError::new("split size invalid").into());
        }

        let trailing_plain = total_plain - leading_plain;
        let old_next_handle = self.next_handle;
        let old_next_address = self.next_address_plain()?;
        let self_address = self.address.decrypt()?;

        self.size = leading_size;
        self.next_handle = Some(new_handle);
        self.next_handle_enc = self.encrypt_handle(Some(new_handle))?;
        self.next_pointer = None;
        self.next_box = None;
        self.refresh_checksum()?;

        let mut trailing_block = EncryptedMemoryBlock::with_layout(
            &self.context,
            new_address,
            trailing_plain,
            new_handle,
        )?;
        trailing_block.set_prev(self.self_handle, Some(self_address))?;
        trailing_block.set_next(old_next_handle, old_next_address)?;
        trailing_block.set_prev_box(Some(self));
        trailing_block.set_next_box(None);
        trailing_block.refresh_checksum()?;

        self.next_pointer = Some(trailing_block.address.clone());
        self.set_next_box(Some(&trailing_block));
        self.refresh_checksum()?;
        Ok(trailing_block)
    }

    pub fn absorb_right(&mut self, right: &EncryptedMemoryBlock) -> Result<(), CryptoError> {
        if !self.context.ptr_eq(right.context()) {
            return Err(CryptoError::ContextMismatch);
        }
        let combined = self.size.checked_add(right.size())?;
        self.size = combined;
        self.refresh_checksum()
    }

    pub fn prev_address_plain(&self) -> Result<Option<u64>, CryptoError> {
        self.prev_pointer
            .as_ref()
            .map(|addr| addr.decrypt().map_err(CryptoError::from))
            .transpose()
    }

    pub fn next_address_plain(&self) -> Result<Option<u64>, CryptoError> {
        self.next_pointer
            .as_ref()
            .map(|addr| addr.decrypt().map_err(CryptoError::from))
            .transpose()
    }

    pub fn merge_blocks(
        mut left: EncryptedMemoryBlock,
        right: EncryptedMemoryBlock,
    ) -> Result<EncryptedMemoryBlock, CryptoError> {
        if !left.context.ptr_eq(right.context()) {
            return Err(CryptoError::ContextMismatch);
        }
        if left.is_allocated()? || right.is_allocated()? {
            return Err(InvalidOperationError::new("cannot merge allocated blocks").into());
        }

        let left_start = left.address.decrypt()?;
        let left_size = left.size.decrypt()?;
        let right_start = right.address.decrypt()?;
        if left_start + u64::from(left_size) != right_start {
            return Err(InvalidOperationError::new("blocks not adjacent").into());
        }

        left.absorb_right(&right)?;
        left.next_handle = right.next_handle;
        left.next_pointer = right.next_pointer.clone();
        left.next_handle_enc = right.next_handle_enc.clone();
        if let Some(next_box) = right.next_box.as_deref() {
            left.set_next_box(Some(next_box));
        } else {
            left.set_next_box(None);
        }
        left.refresh_checksum()?;
        Ok(left)
    }

    pub fn validate_integrity(&self) -> Result<bool, CryptoError> {
        let expected = self.compute_checksum_value()?;
        let actual = self.checksum.decrypt()?;
        Ok(expected == actual)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        bincode::serialize(self).map_err(|err| CryptoError::Serialization(err.to_string()))
    }

    pub fn deserialize(bytes: &[u8], context: &TfheContext) -> Result<Self, CryptoError> {
        let mut block: EncryptedMemoryBlock = bincode::deserialize(bytes)
            .map_err(|err| CryptoError::Serialization(err.to_string()))?;
        block.rebind_context(context)?;
        block.refresh_checksum()?;
        Ok(block)
    }

    pub fn zeroize_sensitive(&mut self) {
        if let Ok(zero_addr) = EncryptedAddress::encrypt(0, &self.context) {
            self.address = zero_addr;
        }
        if let Ok(zero_size) = EncryptedSize::encrypt(0, &self.context) {
            self.size = zero_size;
        }
        if let Ok(zero_bool) = EncryptedBool::encrypt(false, &self.context) {
            self.allocated = zero_bool;
        }
        self.prev_pointer = None;
        self.next_pointer = None;
        self.prev_box = None;
        self.next_box = None;
        self.prev_handle_enc = None;
        self.next_handle_enc = None;
        self.prev_handle = None;
        self.next_handle = None;
        self.self_handle = None;
        let _ = self.refresh_checksum();
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn corrupt_checksum(&mut self) -> Result<(), CryptoError> {
        self.checksum = EncryptedUint32::encrypt(0, &self.context)?;
        Ok(())
    }

    pub fn corrupt_prev_handle_cipher(&mut self) -> Result<(), CryptoError> {
        self.prev_handle_enc = Some(EncryptedUint32::encrypt(0, &self.context)?);
        Ok(())
    }

    pub fn corrupt_next_pointer_cipher(&mut self) -> Result<(), CryptoError> {
        self.next_pointer = Some(EncryptedAddress::encrypt(0, &self.context)?);
        Ok(())
    }

    fn rebind_context(&mut self, context: &TfheContext) -> Result<(), CryptoError> {
        self.context = context.clone();
        self.address = Self::rebind_address(&self.address, context)?;
        self.size = Self::rebind_size(&self.size, context)?;
        self.allocated = Self::rebind_bool(&self.allocated, context)?;
        self.checksum = Self::rebind_uint32(&self.checksum, context)?;
        self.version = Self::rebind_uint32(&self.version, context)?;
        self.prev_pointer = Self::rebind_option_address(self.prev_pointer.take(), context)?;
        self.next_pointer = Self::rebind_option_address(self.next_pointer.take(), context)?;
        Ok(())
    }

    fn rebind_size(
        size: &EncryptedSize,
        context: &TfheContext,
    ) -> Result<EncryptedSize, CryptoError> {
        let cipher = size.inner().inner().clone();
        let noise = size.inner().noise_state();
        let rebuilt = EncryptedUint32::from_parts(cipher, context, noise);
        Ok(EncryptedSize::from_encrypted(rebuilt))
    }

    fn rebind_bool(
        value: &EncryptedBool,
        context: &TfheContext,
    ) -> Result<EncryptedBool, CryptoError> {
        let cipher = value.inner().clone();
        let noise = value.noise_state();
        Ok(EncryptedBool::from_parts(cipher, context, noise))
    }

    fn rebind_uint32(
        value: &EncryptedUint32,
        context: &TfheContext,
    ) -> Result<EncryptedUint32, CryptoError> {
        let cipher = value.inner().clone();
        let noise = value.noise_state();
        Ok(EncryptedUint32::from_parts(cipher, context, noise))
    }

    fn rebind_address(
        address: &EncryptedAddress,
        context: &TfheContext,
    ) -> Result<EncryptedAddress, CryptoError> {
        let cipher = address.inner().inner().clone();
        let noise = address.inner().noise_state();
        let rebuilt = EncryptedUint64::from_parts(cipher, context, noise);
        Ok(EncryptedAddress::from_encrypted(rebuilt))
    }

    fn rebind_option_address(
        pointer: Option<EncryptedAddress>,
        context: &TfheContext,
    ) -> Result<Option<EncryptedAddress>, CryptoError> {
        pointer
            .map(|address| Self::rebind_address(&address, context))
            .transpose()
    }

    fn compute_checksum_value(&self) -> Result<u32, CryptoError> {
        let mut hasher = Sha256::new();
        let address_plain = self.address.decrypt()?;
        hasher.update(address_plain.to_le_bytes());
        let size_plain = self.size.decrypt()?;
        hasher.update(size_plain.to_le_bytes());
        let allocated_plain = self.allocated.decrypt()?;
        hasher.update([allocated_plain as u8]);
        let prev_plain = self.prev_address_plain()?.unwrap_or(0);
        hasher.update(prev_plain.to_le_bytes());
        let next_plain = self.next_address_plain()?.unwrap_or(0);
        hasher.update(next_plain.to_le_bytes());
        let version_plain = self.version.decrypt()?;
        hasher.update(version_plain.to_le_bytes());
        hasher.update(
            self.self_handle
                .unwrap_or(BlockHandleValue::MAX)
                .to_le_bytes(),
        );
        hasher.update(
            self.prev_handle
                .unwrap_or(BlockHandleValue::MAX)
                .to_le_bytes(),
        );
        hasher.update(
            self.next_handle
                .unwrap_or(BlockHandleValue::MAX)
                .to_le_bytes(),
        );
        let prev_handle_cipher = self
            .prev_handle_enc
            .as_ref()
            .map(|enc| enc.decrypt().map_err(CryptoError::from))
            .transpose()?
            .unwrap_or(BlockHandleValue::MAX);
        hasher.update(prev_handle_cipher.to_le_bytes());
        let next_handle_cipher = self
            .next_handle_enc
            .as_ref()
            .map(|enc| enc.decrypt().map_err(CryptoError::from))
            .transpose()?
            .unwrap_or(BlockHandleValue::MAX);
        hasher.update(next_handle_cipher.to_le_bytes());
        let digest = hasher.finalize();
        Ok(u32::from_le_bytes([
            digest[0], digest[1], digest[2], digest[3],
        ]))
    }

    fn refresh_checksum(&mut self) -> Result<(), CryptoError> {
        let checksum_value = self.compute_checksum_value()?;
        self.checksum = EncryptedUint32::encrypt(checksum_value, &self.context)?;
        Ok(())
    }

    fn encrypt_handle(
        &self,
        handle: Option<BlockHandleValue>,
    ) -> Result<Option<EncryptedUint32>, CryptoError> {
        handle
            .map(|value| EncryptedUint32::encrypt(value, &self.context).map_err(CryptoError::from))
            .transpose()
    }

    pub(crate) fn link_clone_box(&self) -> Box<EncryptedMemoryBlock> {
        Box::new(EncryptedMemoryBlock {
            context: self.context.clone(),
            address: self.address.clone(),
            size: self.size.clone(),
            allocated: self.allocated.clone(),
            checksum: self.checksum.clone(),
            version: self.version.clone(),
            prev_pointer: self.prev_pointer.clone(),
            next_pointer: self.next_pointer.clone(),
            prev_box: None,
            next_box: None,
            prev_handle_enc: self.prev_handle_enc.clone(),
            next_handle_enc: self.next_handle_enc.clone(),
            self_handle: self.self_handle,
            prev_handle: self.prev_handle,
            next_handle: self.next_handle,
        })
    }

    pub(crate) fn snapshot(&self) -> EncryptedMemoryBlock {
        *self.link_clone_box()
    }
}

impl Drop for EncryptedMemoryBlock {
    fn drop(&mut self) {
        self.prev_pointer = None;
        self.next_pointer = None;
        self.prev_handle = None;
        self.next_handle = None;
        self.zeroize_sensitive();
    }
}
