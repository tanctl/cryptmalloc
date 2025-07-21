/**
 * @file encrypted_block.cpp
 * @brief Implementation of core encrypted memory block with cryptographic integrity protection
 */

#include "cryptmalloc/encrypted_block.hpp"
#include "cryptmalloc/bfv_operations.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <sstream>
#include <unordered_set>

#ifdef __linux__
#include <sys/mman.h>
#endif

namespace cryptmalloc {

// ========== BlockVersion Implementation ==========

bool BlockVersion::is_compatible(const BlockVersion& other) const {
    // Compatible if major version matches and minor version is >= other's minor
    return (major == other.major) && (minor >= other.minor);
}

uint64_t BlockVersion::as_uint64() const {
    // Simple version encoding to stay within our 32767 limit
    // Version: major*1000 + minor*100 + patch*10 + reserved
    // This allows versions up to 32.76.7 which is plenty
    return static_cast<uint64_t>(major * 1000 + minor * 100 + patch * 10 + reserved);
}

BlockVersion BlockVersion::from_uint64(uint64_t value) {
    BlockVersion version;
    version.major = static_cast<uint16_t>(value / 1000);
    uint64_t remainder = value % 1000;
    version.minor = static_cast<uint16_t>(remainder / 100);
    remainder = remainder % 100;
    version.patch = static_cast<uint16_t>(remainder / 10);
    version.reserved = static_cast<uint16_t>(remainder % 10);
    return version;
}

// ========== EncryptedBlockHeader Implementation ==========

EncryptedBlockHeader::EncryptedBlockHeader(std::shared_ptr<BFVContext> context)
    : size(EncryptedSize(0, context)),
      status(EncryptedInt(static_cast<int64_t>(BlockStatus::FREE), context)),
      next_block(EncryptedAddress(uintptr_t(0), context)),
      prev_block(EncryptedAddress(uintptr_t(0), context)),
      timestamp_created(EncryptedInt(0, context)),
      timestamp_modified(EncryptedInt(0, context)),
      checksum(EncryptedInt(0, context)),
      version_info(EncryptedSize(BlockVersion{}.as_uint64(), context)) {
}

// ========== EncryptedBlockFooter Implementation ==========

EncryptedBlockFooter::EncryptedBlockFooter(std::shared_ptr<BFVContext> context)
    : magic_number(EncryptedInt(static_cast<int64_t>(EncryptedMemoryBlock::MAGIC_NUMBER), context)),
      payload_checksum(EncryptedInt(0, context)),
      total_size_verify(EncryptedSize(0, context)),
      mac(EncryptedInt(0, context)) {
}

// ========== EncryptedMemoryBlock Implementation ==========

EncryptedMemoryBlock::EncryptedMemoryBlock(std::shared_ptr<BFVContext> context)
    : context_(std::move(context)),
      header_(context_),
      footer_(context_),
      payload_data_(nullptr),
      payload_capacity_(0) {
}

EncryptedMemoryBlock::~EncryptedMemoryBlock() {
    if (payload_data_) {
        secure_wipe();
    }
}

EncryptedMemoryBlock::EncryptedMemoryBlock(EncryptedMemoryBlock&& other) noexcept
    : context_(std::move(other.context_)),
      header_(std::move(other.header_)),
      footer_(std::move(other.footer_)),
      payload_data_(std::move(other.payload_data_)),
      payload_capacity_(other.payload_capacity_),
      is_locked_(other.is_locked_.load()) {
    
    other.payload_capacity_ = 0;
    other.is_locked_.store(false);
}

EncryptedMemoryBlock& EncryptedMemoryBlock::operator=(EncryptedMemoryBlock&& other) noexcept {
    if (this != &other) {
        // Secure cleanup of current data
        if (payload_data_) {
            secure_wipe();
        }
        
        context_ = std::move(other.context_);
        header_ = std::move(other.header_);
        footer_ = std::move(other.footer_);
        payload_data_ = std::move(other.payload_data_);
        payload_capacity_ = other.payload_capacity_;
        is_locked_.store(other.is_locked_.load());
        
        other.payload_capacity_ = 0;
        other.is_locked_.store(false);
    }
    return *this;
}

Result<std::unique_ptr<EncryptedMemoryBlock>> EncryptedMemoryBlock::create_block(
    std::shared_ptr<BFVContext> context,
    const EncryptedSize& size) {
    
    if (!context || !context->is_initialized()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("BFV context not initialized");
    }
    
    auto block = std::make_unique<EncryptedMemoryBlock>(context);
    
    // Initialize header with provided size
    auto init_result = block->initialize_header(size);
    if (!init_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to initialize header: " + init_result.error());
    }
    
    // Get plaintext size to allocate payload
    auto plaintext_size_result = size.decrypt();
    if (!plaintext_size_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to decrypt size: " + plaintext_size_result.error());
    }
    
    size_t total_size = plaintext_size_result.value();
    if (total_size < MIN_BLOCK_SIZE) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Block size too small: " + std::to_string(total_size));
    }
    
    // Calculate payload size (total - headers)
    size_t required_header_space = HEADER_SIZE + FOOTER_SIZE;
    if (total_size < required_header_space) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Block size too small for headers: " + 
            std::to_string(total_size) + " < " + std::to_string(required_header_space));
    }
    size_t payload_size = total_size - required_header_space;
    
    // Allocate payload
    auto alloc_result = block->allocate_payload(payload_size);
    if (!alloc_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to allocate payload: " + alloc_result.error());
    }
    
    // Initialize footer
    auto footer_result = block->initialize_footer();
    if (!footer_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to initialize footer: " + footer_result.error());
    }
    
    // Compute initial checksums
    auto checksum_result = block->recompute_checksums();
    if (!checksum_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to compute checksums: " + checksum_result.error());
    }
    
    return Result<std::unique_ptr<EncryptedMemoryBlock>>(std::move(block));
}

Result<std::unique_ptr<EncryptedMemoryBlock>> EncryptedMemoryBlock::create_block_from_plaintext_size(
    std::shared_ptr<BFVContext> context,
    size_t plaintext_size) {
    
    if (!context || !context->is_initialized()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("BFV context not initialized");
    }
    
    try {
        // Debug output
        if (plaintext_size > 786432) {
            return Result<std::unique_ptr<EncryptedMemoryBlock>>("Plaintext size too large: " + std::to_string(plaintext_size));
        }
        
        EncryptedSize encrypted_size(plaintext_size, context);
        return create_block(context, encrypted_size);
    } catch (const std::exception& e) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to encrypt size: " + std::string(e.what()));
    }
}

Result<void> EncryptedMemoryBlock::set_status(BlockStatus status) {
    try {
        header_.status = EncryptedInt(static_cast<int64_t>(status), context_);
        
        // Update modification timestamp
        auto timestamp_result = update_timestamp();
        if (!timestamp_result.has_value()) {
            return Result<void>("Failed to update timestamp: " + timestamp_result.error());
        }
        
        // Recompute checksums
        return recompute_checksums();
    } catch (const std::exception& e) {
        return Result<void>("Failed to set status: " + std::string(e.what()));
    }
}

Result<BlockStatus> EncryptedMemoryBlock::get_status() const {
    auto status_result = header_.status.decrypt();
    if (!status_result.has_value()) {
        return Result<BlockStatus>("Failed to decrypt status: " + status_result.error());
    }
    
    int64_t status_value = status_result.value();
    if (status_value < 0 || status_value > static_cast<int64_t>(BlockStatus::SPLITTING)) {
        return Result<BlockStatus>("Invalid status value: " + std::to_string(status_value));
    }
    
    return Result<BlockStatus>(static_cast<BlockStatus>(status_value));
}

Result<bool> EncryptedMemoryBlock::is_free() const {
    auto status_result = get_status();
    if (!status_result.has_value()) {
        return Result<bool>("Failed to get status: " + status_result.error());
    }
    
    return Result<bool>(status_result.value() == BlockStatus::FREE);
}

Result<bool> EncryptedMemoryBlock::is_allocated() const {
    auto status_result = get_status();
    if (!status_result.has_value()) {
        return Result<bool>("Failed to get status: " + status_result.error());
    }
    
    return Result<bool>(status_result.value() == BlockStatus::ALLOCATED);
}

Result<size_t> EncryptedMemoryBlock::get_plaintext_size() const {
    auto size_result = header_.size.decrypt();
    if (!size_result.has_value()) {
        return Result<size_t>("Failed to decrypt size: " + size_result.error());
    }
    
    return Result<size_t>(static_cast<size_t>(size_result.value()));
}

Result<size_t> EncryptedMemoryBlock::get_payload_size() const {
    auto total_size_result = get_plaintext_size();
    if (!total_size_result.has_value()) {
        return Result<size_t>(total_size_result.error());
    }
    
    size_t total_size = total_size_result.value();
    if (total_size < HEADER_SIZE + FOOTER_SIZE) {
        return Result<size_t>("Block size too small for headers");
    }
    
    return Result<size_t>(total_size - HEADER_SIZE - FOOTER_SIZE);
}

Result<void> EncryptedMemoryBlock::set_next_block(const EncryptedAddress& next) {
    header_.next_block = next;
    
    // Update modification timestamp
    auto timestamp_result = update_timestamp();
    if (!timestamp_result.has_value()) {
        return Result<void>("Failed to update timestamp: " + timestamp_result.error());
    }
    
    // Recompute checksums
    return recompute_checksums();
}

Result<void> EncryptedMemoryBlock::set_prev_block(const EncryptedAddress& prev) {
    header_.prev_block = prev;
    
    // Update modification timestamp
    auto timestamp_result = update_timestamp();
    if (!timestamp_result.has_value()) {
        return Result<void>("Failed to update timestamp: " + timestamp_result.error());
    }
    
    // Recompute checksums
    return recompute_checksums();
}

Result<void> EncryptedMemoryBlock::update_timestamp() {
    try {
        // Use the same small counter approach as in initialize_header
        static std::atomic<int64_t> timestamp_counter{1000};  // Start higher to distinguish from creation
        int64_t timestamp = timestamp_counter.fetch_add(1);
        
        header_.timestamp_modified = EncryptedInt(timestamp, context_);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>("Failed to update timestamp: " + std::string(e.what()));
    }
}

Result<std::chrono::seconds> EncryptedMemoryBlock::get_creation_time() const {
    auto timestamp_result = header_.timestamp_created.decrypt();
    if (!timestamp_result.has_value()) {
        return Result<std::chrono::seconds>("Failed to decrypt creation timestamp: " + timestamp_result.error());
    }
    
    return Result<std::chrono::seconds>(std::chrono::seconds(timestamp_result.value()));
}

Result<std::chrono::seconds> EncryptedMemoryBlock::get_modification_time() const {
    auto timestamp_result = header_.timestamp_modified.decrypt();
    if (!timestamp_result.has_value()) {
        return Result<std::chrono::seconds>("Failed to decrypt modification timestamp: " + timestamp_result.error());
    }
    
    return Result<std::chrono::seconds>(std::chrono::seconds(timestamp_result.value()));
}

Result<bool> EncryptedMemoryBlock::validate_integrity() const {
    // Check header checksum
    auto header_valid = validate_header_checksum();
    if (!header_valid.has_value() || !header_valid.value()) {
        return Result<bool>("Header checksum validation failed");
    }
    
    // Check payload checksum
    auto payload_valid = validate_payload_checksum();
    if (!payload_valid.has_value() || !payload_valid.value()) {
        return Result<bool>("Payload checksum validation failed");
    }
    
    // Check MAC
    auto mac_valid = validate_mac();
    if (!mac_valid.has_value() || !mac_valid.value()) {
        return Result<bool>("MAC validation failed");
    }
    
    // Check magic number
    auto magic_valid = verify_magic_number();
    if (!magic_valid.has_value() || !magic_valid.value()) {
        return Result<bool>("Magic number validation failed");
    }
    
    // Check size consistency
    auto size_valid = verify_size_consistency();
    if (!size_valid.has_value() || !size_valid.value()) {
        return Result<bool>("Size consistency validation failed");
    }
    
    return Result<bool>(true);
}

Result<void> EncryptedMemoryBlock::recompute_checksums() {
    // Compute header checksum
    auto header_checksum_result = compute_header_checksum();
    if (!header_checksum_result.has_value()) {
        return Result<void>("Failed to compute header checksum: " + header_checksum_result.error());
    }
    header_.checksum = header_checksum_result.value();
    
    // Compute payload checksum
    auto payload_checksum_result = compute_payload_checksum();
    if (!payload_checksum_result.has_value()) {
        return Result<void>("Failed to compute payload checksum: " + payload_checksum_result.error());
    }
    footer_.payload_checksum = payload_checksum_result.value();
    
    // Compute MAC
    auto mac_result = compute_mac();
    if (!mac_result.has_value()) {
        return Result<void>("Failed to compute MAC: " + mac_result.error());
    }
    footer_.mac = mac_result.value();
    
    return Result<void>::success();
}

Result<bool> EncryptedMemoryBlock::verify_magic_number() const {
    auto magic_result = footer_.magic_number.decrypt();
    if (!magic_result.has_value()) {
        return Result<bool>("Failed to decrypt magic number: " + magic_result.error());
    }
    
    return Result<bool>(static_cast<uint64_t>(magic_result.value()) == MAGIC_NUMBER);
}

Result<bool> EncryptedMemoryBlock::verify_size_consistency() const {
    // Compare header size with footer size verification
    auto header_size_result = header_.size.decrypt();
    if (!header_size_result.has_value()) {
        return Result<bool>("Failed to decrypt header size: " + header_size_result.error());
    }
    
    auto footer_size_result = footer_.total_size_verify.decrypt();
    if (!footer_size_result.has_value()) {
        return Result<bool>("Failed to decrypt footer size: " + footer_size_result.error());
    }
    
    return Result<bool>(header_size_result.value() == footer_size_result.value());
}

BlockVersion EncryptedMemoryBlock::get_version() const {
    auto version_result = header_.version_info.decrypt();
    if (!version_result.has_value()) {
        return BlockVersion{}; // Return default version on error
    }
    
    return BlockVersion::from_uint64(static_cast<uint64_t>(version_result.value()));
}

Result<bool> EncryptedMemoryBlock::is_version_compatible(const BlockVersion& other_version) const {
    BlockVersion current_version = get_version();
    return Result<bool>(current_version.is_compatible(other_version));
}

Result<void> EncryptedMemoryBlock::secure_wipe() {
    if (payload_data_ && payload_capacity_ > 0) {
        secure_zero_memory(payload_data_.get(), payload_capacity_);
    }
    return Result<void>::success();
}

Result<void> EncryptedMemoryBlock::lock_memory() {
#ifdef __linux__
    if (payload_data_ && payload_capacity_ > 0) {
        if (mlock(payload_data_.get(), payload_capacity_) != 0) {
            return Result<void>("Failed to lock memory pages");
        }
        is_locked_.store(true);
    }
#endif
    return Result<void>::success();
}

Result<void> EncryptedMemoryBlock::unlock_memory() {
#ifdef __linux__
    if (payload_data_ && payload_capacity_ > 0 && is_locked_.load()) {
        if (munlock(payload_data_.get(), payload_capacity_) != 0) {
            return Result<void>("Failed to unlock memory pages");
        }
        is_locked_.store(false);
    }
#endif
    return Result<void>::success();
}

std::string EncryptedMemoryBlock::debug_info() const {
    std::ostringstream oss;
    oss << "EncryptedMemoryBlock Debug Info:\n";
    
    auto size_result = get_plaintext_size();
    if (size_result.has_value()) {
        oss << "  Total Size: " << size_result.value() << " bytes\n";
    }
    
    auto payload_size_result = get_payload_size();
    if (payload_size_result.has_value()) {
        oss << "  Payload Size: " << payload_size_result.value() << " bytes\n";
    }
    
    auto status_result = get_status();
    if (status_result.has_value()) {
        oss << "  Status: " << static_cast<int>(status_result.value()) << "\n";
    }
    
    auto creation_time_result = get_creation_time();
    if (creation_time_result.has_value()) {
        oss << "  Created: " << creation_time_result.value().count() << " (epoch seconds)\n";
    }
    
    auto modification_time_result = get_modification_time();
    if (modification_time_result.has_value()) {
        oss << "  Modified: " << modification_time_result.value().count() << " (epoch seconds)\n";
    }
    
    oss << "  Version: " << get_version().major << "." << get_version().minor << "." << get_version().patch << "\n";
    oss << "  Memory Locked: " << (is_locked_.load() ? "Yes" : "No") << "\n";
    
    auto integrity_result = validate_integrity();
    if (integrity_result.has_value()) {
        oss << "  Integrity Valid: " << (integrity_result.value() ? "Yes" : "No") << "\n";
    }
    
    return oss.str();
}

Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>> 
EncryptedMemoryBlock::split_block(const EncryptedSize& split_size) {
    // Validate that block is in correct state for splitting
    auto status_result = get_status();
    if (!status_result.has_value()) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to get status: " + status_result.error());
    }
    
    if (status_result.value() != BlockStatus::FREE) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Block must be free to split");
    }
    
    // Get current size and split size in plaintext
    auto current_size_result = get_plaintext_size();
    if (!current_size_result.has_value()) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to get current size: " + current_size_result.error());
    }
    
    auto split_size_result = split_size.decrypt();
    if (!split_size_result.has_value()) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to decrypt split size: " + split_size_result.error());
    }
    
    size_t current_size = current_size_result.value();
    size_t split_plaintext_size = static_cast<size_t>(split_size_result.value());
    
    // Validate split is possible
    if (split_plaintext_size >= current_size) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Split size must be smaller than current size");
    }
    
    if (split_plaintext_size < MIN_BLOCK_SIZE) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Split size too small");
    }
    
    size_t remaining_size = current_size - split_plaintext_size;
    if (remaining_size < MIN_BLOCK_SIZE) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Remaining size after split too small");
    }
    
    // Set status to splitting
    auto set_status_result = set_status(BlockStatus::SPLITTING);
    if (!set_status_result.has_value()) {
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to set splitting status: " + set_status_result.error());
    }
    
    // Create first block (with split size)
    auto first_block_result = create_block_from_plaintext_size(context_, split_plaintext_size);
    if (!first_block_result.has_value()) {
        set_status(BlockStatus::FREE); // Restore status
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to create first block: " + first_block_result.error());
    }
    
    // Create second block (with remaining size)
    auto second_block_result = create_block_from_plaintext_size(context_, remaining_size);
    if (!second_block_result.has_value()) {
        set_status(BlockStatus::FREE); // Restore status
        return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
            "Failed to create second block: " + second_block_result.error());
    }
    
    auto first_block = first_block_result.take();
    auto second_block = second_block_result.take();
    
    // Copy payload data to new blocks if needed
    if (payload_data_ && payload_capacity_ > 0) {
        auto first_payload_size_result = first_block->get_payload_size();
        auto second_payload_size_result = second_block->get_payload_size();
        
        if (first_payload_size_result.has_value() && first_block->payload_data_) {
            size_t copy_size = std::min(first_payload_size_result.value(), payload_capacity_);
            std::memcpy(first_block->payload_data_.get(), payload_data_.get(), copy_size);
        }
        
        if (second_payload_size_result.has_value() && second_block->payload_data_ && 
            first_payload_size_result.has_value() && payload_capacity_ > first_payload_size_result.value()) {
            size_t offset = first_payload_size_result.value();
            size_t copy_size = std::min(second_payload_size_result.value(), payload_capacity_ - offset);
            std::memcpy(second_block->payload_data_.get(), 
                       payload_data_.get() + offset, copy_size);
        }
    }
    
    // Set up linked list pointers
    auto next_block = get_next_block();
    auto prev_block = get_prev_block();
    
    first_block->set_prev_block(prev_block);
    first_block->set_next_block(EncryptedAddress(reinterpret_cast<uintptr_t>(second_block.get()), context_));
    
    second_block->set_prev_block(EncryptedAddress(reinterpret_cast<uintptr_t>(first_block.get()), context_));
    second_block->set_next_block(next_block);
    
    // Recompute checksums for both blocks
    first_block->recompute_checksums();
    second_block->recompute_checksums();
    
    // Mark original block as corrupted (it should not be used anymore)
    set_status(BlockStatus::CORRUPTED);
    
    return Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>>(
        std::make_pair(std::move(first_block), std::move(second_block)));
}

Result<std::unique_ptr<EncryptedMemoryBlock>> EncryptedMemoryBlock::merge_blocks(
    std::unique_ptr<EncryptedMemoryBlock> block1,
    std::unique_ptr<EncryptedMemoryBlock> block2) {
    
    if (!block1 || !block2) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Invalid blocks for merging");
    }
    
    // Validate both blocks are free
    auto block1_status = block1->get_status();
    auto block2_status = block2->get_status();
    
    if (!block1_status.has_value() || block1_status.value() != BlockStatus::FREE) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Block1 must be free for merging");
    }
    
    if (!block2_status.has_value() || block2_status.value() != BlockStatus::FREE) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Block2 must be free for merging");
    }
    
    // Get sizes
    auto block1_size_result = block1->get_plaintext_size();
    auto block2_size_result = block2->get_plaintext_size();
    
    if (!block1_size_result.has_value() || !block2_size_result.has_value()) {
        return Result<std::unique_ptr<EncryptedMemoryBlock>>("Failed to get block sizes for merging");
    }
    
    size_t merged_size = block1_size_result.value() + block2_size_result.value();
    
    // Set both blocks to merging status
    block1->set_status(BlockStatus::MERGING);
    block2->set_status(BlockStatus::MERGING);
    
    // Create merged block
    auto merged_block_result = create_block_from_plaintext_size(block1->context_, merged_size);
    if (!merged_block_result.has_value()) {
        // Restore status
        block1->set_status(BlockStatus::FREE);
        block2->set_status(BlockStatus::FREE);
        return Result<std::unique_ptr<EncryptedMemoryBlock>>(
            "Failed to create merged block: " + merged_block_result.error());
    }
    
    auto merged_block = merged_block_result.take();
    
    // Copy payload data from both blocks
    auto merged_payload_size_result = merged_block->get_payload_size();
    if (merged_payload_size_result.has_value() && merged_block->payload_data_) {
        size_t offset = 0;
        
        // Copy from block1
        if (block1->payload_data_ && block1->payload_capacity_ > 0) {
            size_t copy_size = std::min(block1->payload_capacity_, 
                                       merged_payload_size_result.value() - offset);
            std::memcpy(merged_block->payload_data_.get() + offset, 
                       block1->payload_data_.get(), copy_size);
            offset += copy_size;
        }
        
        // Copy from block2
        if (block2->payload_data_ && block2->payload_capacity_ > 0 && 
            offset < merged_payload_size_result.value()) {
            size_t copy_size = std::min(block2->payload_capacity_, 
                                       merged_payload_size_result.value() - offset);
            std::memcpy(merged_block->payload_data_.get() + offset, 
                       block2->payload_data_.get(), copy_size);
        }
    }
    
    // Set up linked list pointers from original blocks
    auto prev_block = block1->get_prev_block();
    auto next_block = block2->get_next_block();
    
    merged_block->set_prev_block(prev_block);
    merged_block->set_next_block(next_block);
    
    // Recompute checksums
    merged_block->recompute_checksums();
    
    // Mark original blocks as corrupted
    block1->set_status(BlockStatus::CORRUPTED);
    block2->set_status(BlockStatus::CORRUPTED);
    
    return Result<std::unique_ptr<EncryptedMemoryBlock>>(std::move(merged_block));
}

Result<void> EncryptedMemoryBlock::self_test() const {
    // Validate integrity
    auto integrity_result = validate_integrity();
    if (!integrity_result.has_value()) {
        return Result<void>("Self-test failed: integrity check error: " + integrity_result.error());
    }
    if (!integrity_result.value()) {
        return Result<void>("Self-test failed: integrity validation failed");
    }
    
    // Check basic invariants
    auto size_result = get_plaintext_size();
    if (!size_result.has_value()) {
        return Result<void>("Self-test failed: cannot get size");
    }
    if (size_result.value() < MIN_BLOCK_SIZE) {
        return Result<void>("Self-test failed: size too small");
    }
    
    auto status_result = get_status();
    if (!status_result.has_value()) {
        return Result<void>("Self-test failed: cannot get status");
    }
    
    // Check version compatibility
    auto version_result = is_version_compatible(BlockVersion{});
    if (!version_result.has_value()) {
        return Result<void>("Self-test failed: version check error");
    }
    if (!version_result.value()) {
        return Result<void>("Self-test failed: version incompatible");
    }
    
    return Result<void>::success();
}

// ========== Private Methods ==========

Result<void> EncryptedMemoryBlock::initialize_header(const EncryptedSize& size) {
    try {
        header_.size = size;
        header_.status = EncryptedInt(static_cast<int64_t>(BlockStatus::FREE), context_);
        header_.next_block = EncryptedAddress(uintptr_t(0), context_);
        header_.prev_block = EncryptedAddress(uintptr_t(0), context_);
        
        // Use small relative timestamps to stay within plaintext modulus limits
        // Static counter for unique block IDs (much smaller than unix timestamps)
        static std::atomic<int64_t> block_counter{1};
        int64_t timestamp = block_counter.fetch_add(1);
        header_.timestamp_created = EncryptedInt(timestamp, context_);
        header_.timestamp_modified = EncryptedInt(timestamp, context_);
        
        header_.version_info = EncryptedSize(static_cast<int64_t>(BlockVersion{}.as_uint64()), context_);
        
        // Initialize checksum to zero (will be computed later)
        header_.checksum = EncryptedInt(0, context_);
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>("Failed to initialize header: " + std::string(e.what()));
    }
}

Result<void> EncryptedMemoryBlock::initialize_footer() {
    try {
        footer_.magic_number = EncryptedInt(static_cast<int64_t>(MAGIC_NUMBER), context_);
        footer_.payload_checksum = EncryptedInt(0, context_);
        footer_.total_size_verify = header_.size; // Copy size for verification
        footer_.mac = EncryptedInt(0, context_);
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>("Failed to initialize footer: " + std::string(e.what()));
    }
}

Result<void> EncryptedMemoryBlock::allocate_payload(size_t size) {
    if (size == 0) {
        payload_data_ = nullptr;
        payload_capacity_ = 0;
        return Result<void>::success();
    }
    
    // Sanity check to prevent extremely large allocations
    if (size > 1024 * 1024) {  // 1MB limit for safety
        return Result<void>("Payload size too large: " + std::to_string(size));
    }
    
    try {
        payload_data_ = std::make_unique<uint8_t[]>(size);
        payload_capacity_ = size;
        
        // Initialize payload to zero
        std::memset(payload_data_.get(), 0, size);
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>("Failed to allocate payload: " + std::string(e.what()));
    }
}

Result<EncryptedInt> EncryptedMemoryBlock::compute_header_checksum() const {
    try {
        // Polynomial hash of header fields (excluding the checksum field itself)
        int64_t checksum = 1;
        const int64_t PRIME = 31;
        const int64_t MOD = 65537;
        
        auto size_result = header_.size.decrypt();
        if (size_result.has_value()) {
            checksum = (checksum * PRIME + size_result.value()) % MOD;
        }
        
        auto status_result = header_.status.decrypt();
        if (status_result.has_value()) {
            checksum = (checksum * PRIME + status_result.value()) % MOD;
        }
        
        auto timestamp_created_result = header_.timestamp_created.decrypt();
        if (timestamp_created_result.has_value()) {
            checksum = (checksum * PRIME + (timestamp_created_result.value() % 65536)) % MOD;
        }
        
        auto timestamp_modified_result = header_.timestamp_modified.decrypt();
        if (timestamp_modified_result.has_value()) {
            checksum = (checksum * PRIME + (timestamp_modified_result.value() % 65536)) % MOD;
        }
        
        return Result<EncryptedInt>(EncryptedInt(checksum, context_));
    } catch (const std::exception& e) {
        return Result<EncryptedInt>("Failed to compute header checksum: " + std::string(e.what()));
    }
}

Result<EncryptedInt> EncryptedMemoryBlock::compute_payload_checksum() const {
    try {
        int64_t checksum = 0;
        
        if (payload_data_ && payload_capacity_ > 0) {
            // More robust checksum using polynomial hash
            const uint8_t* data = payload_data_.get();
            const int64_t PRIME = 31;
            for (size_t i = 0; i < payload_capacity_; ++i) {
                checksum = (checksum * PRIME + static_cast<int64_t>(data[i])) % 65537;
            }
        }
        
        return Result<EncryptedInt>(EncryptedInt(checksum, context_));
    } catch (const std::exception& e) {
        return Result<EncryptedInt>("Failed to compute payload checksum: " + std::string(e.what()));
    }
}

Result<EncryptedInt> EncryptedMemoryBlock::compute_mac() const {
    try {
        // HMAC-like construction combining header and payload checksums
        int64_t mac = static_cast<int64_t>(MAGIC_NUMBER);
        const int64_t PRIME = 37;
        const int64_t MOD = 65537;
        
        auto header_checksum_result = header_.checksum.decrypt();
        if (header_checksum_result.has_value()) {
            mac = (mac * PRIME + header_checksum_result.value()) % MOD;
        }
        
        auto payload_checksum_result = footer_.payload_checksum.decrypt();
        if (payload_checksum_result.has_value()) {
            mac = (mac * PRIME + payload_checksum_result.value()) % MOD;
        }
        
        // Add size for additional security
        auto size_result = header_.size.decrypt();
        if (size_result.has_value()) {
            mac = (mac * PRIME + size_result.value()) % MOD;
        }
        
        return Result<EncryptedInt>(EncryptedInt(mac, context_));
    } catch (const std::exception& e) {
        return Result<EncryptedInt>("Failed to compute MAC: " + std::string(e.what()));
    }
}

Result<bool> EncryptedMemoryBlock::validate_header_checksum() const {
    auto expected_checksum_result = compute_header_checksum();
    if (!expected_checksum_result.has_value()) {
        return Result<bool>("Failed to compute expected header checksum: " + expected_checksum_result.error());
    }
    
    // Compare encrypted checksums using homomorphic subtraction
    try {
        BFVOperations ops(context_);
        auto diff_result = ops.subtract(header_.checksum, expected_checksum_result.value());
        if (!diff_result.has_value()) {
            return Result<bool>("Failed to compute checksum difference: " + diff_result.error());
        }
        
        auto decrypt_result = diff_result.value().decrypt();
        if (!decrypt_result.has_value()) {
            return Result<bool>("Failed to decrypt checksum difference: " + decrypt_result.error());
        }
        
        return Result<bool>(decrypt_result.value() == 0);
    } catch (const std::exception& e) {
        return Result<bool>("Failed to validate header checksum: " + std::string(e.what()));
    }
}

Result<bool> EncryptedMemoryBlock::validate_payload_checksum() const {
    auto expected_checksum_result = compute_payload_checksum();
    if (!expected_checksum_result.has_value()) {
        return Result<bool>("Failed to compute expected payload checksum: " + expected_checksum_result.error());
    }
    
    // Compare encrypted checksums
    try {
        BFVOperations ops(context_);
        auto diff_result = ops.subtract(footer_.payload_checksum, expected_checksum_result.value());
        if (!diff_result.has_value()) {
            return Result<bool>("Failed to compute payload checksum difference: " + diff_result.error());
        }
        
        auto decrypt_result = diff_result.value().decrypt();
        if (!decrypt_result.has_value()) {
            return Result<bool>("Failed to decrypt payload checksum difference: " + decrypt_result.error());
        }
        
        return Result<bool>(decrypt_result.value() == 0);
    } catch (const std::exception& e) {
        return Result<bool>("Failed to validate payload checksum: " + std::string(e.what()));
    }
}

Result<bool> EncryptedMemoryBlock::validate_mac() const {
    auto expected_mac_result = compute_mac();
    if (!expected_mac_result.has_value()) {
        return Result<bool>("Failed to compute expected MAC: " + expected_mac_result.error());
    }
    
    // Compare encrypted MACs
    try {
        BFVOperations ops(context_);
        auto diff_result = ops.subtract(footer_.mac, expected_mac_result.value());
        if (!diff_result.has_value()) {
            return Result<bool>("Failed to compute MAC difference: " + diff_result.error());
        }
        
        auto decrypt_result = diff_result.value().decrypt();
        if (!decrypt_result.has_value()) {
            return Result<bool>("Failed to decrypt MAC difference: " + decrypt_result.error());
        }
        
        return Result<bool>(decrypt_result.value() == 0);
    } catch (const std::exception& e) {
        return Result<bool>("Failed to validate MAC: " + std::string(e.what()));
    }
}

void EncryptedMemoryBlock::secure_zero_memory(void* ptr, size_t size) {
    if (ptr && size > 0) {
        // Use volatile to prevent compiler optimization
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            vptr[i] = 0;
        }
    }
}

// ========== Utility Functions ==========

namespace block_utils {

size_t calculate_total_block_size(size_t payload_size, size_t alignment) {
    size_t total_size = EncryptedMemoryBlock::HEADER_SIZE + payload_size + EncryptedMemoryBlock::FOOTER_SIZE;
    
    // Align to specified boundary
    if (alignment > 1) {
        total_size = (total_size + alignment - 1) & ~(alignment - 1);
    }
    
    return total_size;
}

bool is_valid_block_size(size_t size) {
    return size >= EncryptedMemoryBlock::MIN_BLOCK_SIZE && 
           size <= (1ULL << 30); // Max 1GB
}

size_t align_size(size_t size, size_t alignment) {
    if (alignment <= 1) {
        return size;
    }
    return (size + alignment - 1) & ~(alignment - 1);
}

Result<bool> secure_encrypted_compare(const EncryptedInt& a, const EncryptedInt& b, 
                                     std::shared_ptr<BFVContext> context) {
    try {
        BFVOperations ops(context);
        auto diff_result = ops.subtract(a, b);
        if (!diff_result.has_value()) {
            return Result<bool>("Failed to compute difference for comparison: " + diff_result.error());
        }
        
        auto decrypt_result = diff_result.value().decrypt();
        if (!decrypt_result.has_value()) {
            return Result<bool>("Failed to decrypt comparison result: " + decrypt_result.error());
        }
        
        return Result<bool>(decrypt_result.value() == 0);
    } catch (const std::exception& e) {
        return Result<bool>("Failed to perform secure comparison: " + std::string(e.what()));
    }
}

Result<EncryptedInt> generate_secure_random_encrypted(std::shared_ptr<BFVContext> context) {
    try {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<int64_t> dis(1, 1000000);
        
        int64_t random_value = dis(gen);
        return Result<EncryptedInt>(EncryptedInt(random_value, context));
    } catch (const std::exception& e) {
        return Result<EncryptedInt>("Failed to generate secure random value: " + std::string(e.what()));
    }
}

} // namespace block_utils

// ========== BlockValidator Implementation ==========

BlockValidator::BlockValidator(std::shared_ptr<BFVContext> context)
    : context_(std::move(context)) {
}

Result<bool> BlockValidator::validate_block(const EncryptedMemoryBlock& block) const {
    return block.validate_integrity();
}

Result<bool> BlockValidator::detect_corruption(const EncryptedMemoryBlock& block) const {
    // Check various forms of corruption
    
    // 1. Header integrity
    auto header_result = check_header_integrity(block);
    if (!header_result.has_value() || !header_result.value()) {
        return Result<bool>(false); // Corruption detected
    }
    
    // 2. Footer integrity
    auto footer_result = check_footer_integrity(block);
    if (!footer_result.has_value() || !footer_result.value()) {
        return Result<bool>(false); // Corruption detected
    }
    
    // 3. Size consistency
    auto size_result = check_size_consistency(block);
    if (!size_result.has_value() || !size_result.value()) {
        return Result<bool>(false); // Corruption detected
    }
    
    // 4. Version compatibility
    auto version_result = check_version_compatibility(block);
    if (!version_result.has_value() || !version_result.value()) {
        return Result<bool>(false); // Corruption detected
    }
    
    // 5. Timestamp validity
    auto timestamp_result = check_timestamp_validity(block);
    if (!timestamp_result.has_value() || !timestamp_result.value()) {
        return Result<bool>(false); // Corruption detected
    }
    
    return Result<bool>(true); // No corruption detected
}

Result<bool> BlockValidator::detect_tampering(const EncryptedMemoryBlock& block) const {
    // Tampering detection focuses on cryptographic integrity
    
    // Check if all checksums and MACs are valid
    auto integrity_result = block.validate_integrity();
    if (!integrity_result.has_value()) {
        return Result<bool>("Failed to validate integrity: " + integrity_result.error());
    }
    
    if (!integrity_result.value()) {
        return Result<bool>(false); // Tampering detected
    }
    
    // Additional tampering checks could include:
    // - Sequence number validation
    // - Time-based MAC validation
    // - Cross-reference with external audit log
    
    return Result<bool>(true); // No tampering detected
}

Result<bool> BlockValidator::validate_block_chain(const std::vector<const EncryptedMemoryBlock*>& blocks) const {
    if (blocks.empty()) {
        return Result<bool>(true); // Empty chain is valid
    }
    
    // Validate each block individually
    for (const auto* block : blocks) {
        if (!block) {
            return Result<bool>("Null block in chain");
        }
        
        auto block_valid = validate_block(*block);
        if (!block_valid.has_value() || !block_valid.value()) {
            return Result<bool>("Invalid block found in chain");
        }
    }
    
    // Validate chain linkage
    for (size_t i = 0; i < blocks.size() - 1; ++i) {
        const auto* current_block = blocks[i];
        const auto* next_block = blocks[i + 1];
        
        // Check if current block's next pointer matches next block's address
        auto next_addr_result = current_block->get_next_block().decrypt();
        if (next_addr_result.has_value()) {
            uintptr_t expected_addr = reinterpret_cast<uintptr_t>(next_block);
            if (static_cast<uintptr_t>(next_addr_result.value()) != expected_addr) {
                return Result<bool>("Chain linkage broken between blocks " + std::to_string(i) + 
                                   " and " + std::to_string(i + 1));
            }
        }
        
        // Check if next block's prev pointer matches current block's address
        auto prev_addr_result = next_block->get_prev_block().decrypt();
        if (prev_addr_result.has_value()) {
            uintptr_t expected_addr = reinterpret_cast<uintptr_t>(current_block);
            if (static_cast<uintptr_t>(prev_addr_result.value()) != expected_addr) {
                return Result<bool>("Chain linkage broken between blocks " + std::to_string(i + 1) + 
                                   " and " + std::to_string(i));
            }
        }
    }
    
    return Result<bool>(true);
}

Result<bool> BlockValidator::check_consistency_violations(const std::vector<const EncryptedMemoryBlock*>& blocks) const {
    if (blocks.empty()) {
        return Result<bool>(true);
    }
    
    // Check for overlapping memory regions
    std::vector<std::pair<uintptr_t, size_t>> regions;
    
    for (const auto* block : blocks) {
        auto size_result = block->get_plaintext_size();
        if (!size_result.has_value()) {
            continue; // Skip blocks we can't analyze
        }
        
        uintptr_t addr = reinterpret_cast<uintptr_t>(block);
        size_t size = size_result.value();
        
        // Check for overlaps with existing regions
        for (const auto& region : regions) {
            uintptr_t region_start = region.first;
            uintptr_t region_end = region_start + region.second;
            uintptr_t block_end = addr + size;
            
            // Check for overlap
            if ((addr >= region_start && addr < region_end) ||
                (block_end > region_start && block_end <= region_end) ||
                (addr <= region_start && block_end >= region_end)) {
                return Result<bool>("Memory region overlap detected");
            }
        }
        
        regions.emplace_back(addr, size);
    }
    
    // Check for status consistency
    std::unordered_map<BlockStatus, size_t> status_counts;
    for (const auto* block : blocks) {
        auto status_result = block->get_status();
        if (status_result.has_value()) {
            status_counts[status_result.value()]++;
        }
    }
    
    // Check for suspicious patterns (e.g., too many corrupted blocks)
    auto corrupted_count = status_counts[BlockStatus::CORRUPTED];
    if (corrupted_count > blocks.size() / 2) {
        return Result<bool>("Suspicious number of corrupted blocks detected");
    }
    
    return Result<bool>(true);
}

Result<BlockValidator::ValidationReport> BlockValidator::comprehensive_validation(const EncryptedMemoryBlock& block) const {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    ValidationReport report;
    report.blocks_checked = 1;
    report.is_valid = true;
    
    // Basic integrity check
    auto integrity_result = validate_block(block);
    if (!integrity_result.has_value()) {
        report.errors.push_back("Integrity validation failed: " + integrity_result.error());
        report.is_valid = false;
    } else if (!integrity_result.value()) {
        report.errors.push_back("Block integrity validation failed");
        report.is_valid = false;
    }
    
    // Corruption detection
    auto corruption_result = detect_corruption(block);
    if (!corruption_result.has_value()) {
        report.errors.push_back("Corruption detection failed: " + corruption_result.error());
        report.is_valid = false;
    } else if (!corruption_result.value()) {
        report.errors.push_back("Block corruption detected");
        report.is_valid = false;
    }
    
    // Tampering detection
    auto tamper_result = detect_tampering(block);
    if (!tamper_result.has_value()) {
        report.errors.push_back("Tampering detection failed: " + tamper_result.error());
        report.is_valid = false;
    } else if (!tamper_result.value()) {
        report.errors.push_back("Block tampering detected");
        report.is_valid = false;
    }
    
    // Self-test
    auto self_test_result = block.self_test();
    if (!self_test_result.has_value()) {
        report.warnings.push_back("Self-test failed: " + self_test_result.error());
    }
    
    // Check version compatibility
    auto version_result = check_version_compatibility(block);
    if (!version_result.has_value()) {
        report.warnings.push_back("Version check failed: " + version_result.error());
    } else if (!version_result.value()) {
        report.warnings.push_back("Block version may be incompatible");
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    report.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    return Result<ValidationReport>(report);
}

Result<BlockValidator::ValidationReport> BlockValidator::batch_validation(const std::vector<const EncryptedMemoryBlock*>& blocks) const {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    ValidationReport report;
    report.blocks_checked = blocks.size();
    report.is_valid = true;
    
    // Validate individual blocks
    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto* block = blocks[i];
        if (!block) {
            report.errors.push_back("Block " + std::to_string(i) + " is null");
            report.is_valid = false;
            continue;
        }
        
        auto block_validation = comprehensive_validation(*block);
        if (!block_validation.has_value()) {
            report.errors.push_back("Block " + std::to_string(i) + " validation failed: " + block_validation.error());
            report.is_valid = false;
        } else {
            const auto& block_report = block_validation.value();
            if (!block_report.is_valid) {
                report.is_valid = false;
                for (const auto& error : block_report.errors) {
                    report.errors.push_back("Block " + std::to_string(i) + ": " + error);
                }
            }
            for (const auto& warning : block_report.warnings) {
                report.warnings.push_back("Block " + std::to_string(i) + ": " + warning);
            }
        }
    }
    
    // Validate block chain consistency
    auto chain_result = validate_block_chain(blocks);
    if (!chain_result.has_value()) {
        report.errors.push_back("Chain validation failed: " + chain_result.error());
        report.is_valid = false;
    } else if (!chain_result.value()) {
        report.errors.push_back("Block chain validation failed");
        report.is_valid = false;
    }
    
    // Check for consistency violations
    auto consistency_result = check_consistency_violations(blocks);
    if (!consistency_result.has_value()) {
        report.errors.push_back("Consistency check failed: " + consistency_result.error());
        report.is_valid = false;
    } else if (!consistency_result.value()) {
        report.errors.push_back("Block consistency violations detected");
        report.is_valid = false;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    report.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    return Result<ValidationReport>(report);
}

// Private validation methods
Result<bool> BlockValidator::check_header_integrity(const EncryptedMemoryBlock& block) const {
    return block.validate_integrity(); // Delegate to block's own validation
}

Result<bool> BlockValidator::check_footer_integrity(const EncryptedMemoryBlock& block) const {
    // Check magic number
    auto magic_result = block.verify_magic_number();
    if (!magic_result.has_value() || !magic_result.value()) {
        return Result<bool>(false);
    }
    
    return Result<bool>(true);
}

Result<bool> BlockValidator::check_version_compatibility(const EncryptedMemoryBlock& block) const {
    BlockVersion current_version{1, 0, 0, 0}; // Current system version
    auto compat_result = block.is_version_compatible(current_version);
    if (!compat_result.has_value()) {
        return Result<bool>("Failed to check version compatibility: " + compat_result.error());
    }
    
    return Result<bool>(compat_result.value());
}

Result<bool> BlockValidator::check_size_consistency(const EncryptedMemoryBlock& block) const {
    return block.verify_size_consistency();
}

Result<bool> BlockValidator::check_timestamp_validity(const EncryptedMemoryBlock& block) const {
    auto creation_time_result = block.get_creation_time();
    auto modification_time_result = block.get_modification_time();
    
    if (!creation_time_result.has_value() || !modification_time_result.has_value()) {
        return Result<bool>("Failed to get timestamps");
    }
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch());
    
    // Check if timestamps are reasonable (not in future, not too old)
    if (creation_time_result.value() > now) {
        return Result<bool>(false); // Creation time in future
    }
    
    if (modification_time_result.value() > now) {
        return Result<bool>(false); // Modification time in future
    }
    
    if (modification_time_result.value() < creation_time_result.value()) {
        return Result<bool>(false); // Modified before created
    }
    
    // Check if timestamps are not too old (e.g., more than 100 years)
    auto hundred_years_ago = now - std::chrono::seconds(100LL * 365 * 24 * 3600);
    if (creation_time_result.value() < hundred_years_ago) {
        return Result<bool>(false); // Too old
    }
    
    return Result<bool>(true);
}

} // namespace cryptmalloc