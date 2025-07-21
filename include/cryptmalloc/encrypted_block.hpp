/**
 * @file encrypted_block.hpp
 * @brief Core encrypted memory block data structure with cryptographic integrity protection
 */

#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <vector>
#include <cstdint>
#include <atomic>

#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/encrypted_types.hpp"
#include "cryptmalloc/core.hpp"

namespace cryptmalloc {

// Forward declarations
class EncryptedMemoryBlock;
class BlockValidator;
class BlockSerializer;

/**
 * @brief Version information for forward/backward compatibility
 */
struct BlockVersion {
    uint16_t major{1};
    uint16_t minor{0};
    uint16_t patch{0};
    uint16_t reserved{0};
    
    bool is_compatible(const BlockVersion& other) const;
    uint64_t as_uint64() const;
    static BlockVersion from_uint64(uint64_t value);
};

/**
 * @brief Block allocation status
 */
enum class BlockStatus : uint8_t {
    FREE = 0,
    ALLOCATED = 1,
    CORRUPTED = 2,
    MERGING = 3,
    SPLITTING = 4
};

/**
 * @brief Encrypted block header containing all metadata
 */
struct EncryptedBlockHeader {
    EncryptedSize size;                    // Block size (including header/footer)
    EncryptedInt status;                   // BlockStatus as encrypted integer
    EncryptedAddress next_block;           // Pointer to next block in list
    EncryptedAddress prev_block;           // Pointer to previous block in list
    EncryptedInt timestamp_created;        // Creation timestamp (seconds since epoch)
    EncryptedInt timestamp_modified;       // Last modification timestamp
    EncryptedInt checksum;                 // Integrity checksum of header data
    EncryptedSize version_info;            // Version information for compatibility
    
    EncryptedBlockHeader(std::shared_ptr<BFVContext> context);
    
    // Copy operations for encrypted types
    EncryptedBlockHeader(const EncryptedBlockHeader& other) = default;
    EncryptedBlockHeader& operator=(const EncryptedBlockHeader& other) = default;
    EncryptedBlockHeader(EncryptedBlockHeader&& other) = default;
    EncryptedBlockHeader& operator=(EncryptedBlockHeader&& other) = default;
};

/**
 * @brief Encrypted block footer for integrity verification
 */
struct EncryptedBlockFooter {
    EncryptedInt magic_number;             // Magic number for block validation
    EncryptedInt payload_checksum;         // Checksum of payload data
    EncryptedSize total_size_verify;       // Duplicate size for verification
    EncryptedInt mac;                      // Message Authentication Code
    
    EncryptedBlockFooter(std::shared_ptr<BFVContext> context);
    
    // Copy operations for encrypted types
    EncryptedBlockFooter(const EncryptedBlockFooter& other) = default;
    EncryptedBlockFooter& operator=(const EncryptedBlockFooter& other) = default;
    EncryptedBlockFooter(EncryptedBlockFooter&& other) = default;
    EncryptedBlockFooter& operator=(EncryptedBlockFooter&& other) = default;
};

/**
 * @brief Core encrypted memory block with cryptographic integrity protection
 */
class EncryptedMemoryBlock {
public:
    static constexpr uint64_t MAGIC_NUMBER = 0xBE;  // Small magic number within plaintext modulus limits (190)
    static constexpr size_t MIN_BLOCK_SIZE = 128;  // Minimum block size including headers
    static constexpr size_t HEADER_SIZE = sizeof(void*) * 8;  // Conservative estimate
    static constexpr size_t FOOTER_SIZE = sizeof(void*) * 4;  // Conservative estimate
    
    explicit EncryptedMemoryBlock(std::shared_ptr<BFVContext> context);
    ~EncryptedMemoryBlock();
    
    // Non-copyable but moveable for security
    EncryptedMemoryBlock(const EncryptedMemoryBlock&) = delete;
    EncryptedMemoryBlock& operator=(const EncryptedMemoryBlock&) = delete;
    EncryptedMemoryBlock(EncryptedMemoryBlock&& other) noexcept;
    EncryptedMemoryBlock& operator=(EncryptedMemoryBlock&& other) noexcept;
    
    // Block creation and initialization
    static Result<std::unique_ptr<EncryptedMemoryBlock>> create_block(
        std::shared_ptr<BFVContext> context,
        const EncryptedSize& size);
        
    static Result<std::unique_ptr<EncryptedMemoryBlock>> create_block_from_plaintext_size(
        std::shared_ptr<BFVContext> context,
        size_t plaintext_size);
    
    // Core block operations
    Result<std::pair<std::unique_ptr<EncryptedMemoryBlock>, std::unique_ptr<EncryptedMemoryBlock>>> 
    split_block(const EncryptedSize& split_size);
    
    static Result<std::unique_ptr<EncryptedMemoryBlock>> merge_blocks(
        std::unique_ptr<EncryptedMemoryBlock> block1,
        std::unique_ptr<EncryptedMemoryBlock> block2);
    
    // Block state management
    Result<void> set_status(BlockStatus status);
    Result<BlockStatus> get_status() const;
    Result<bool> is_free() const;
    Result<bool> is_allocated() const;
    
    // Size operations
    Result<size_t> get_plaintext_size() const;
    const EncryptedSize& get_encrypted_size() const { return header_.size; }
    Result<size_t> get_payload_size() const;
    
    // Linked list operations
    Result<void> set_next_block(const EncryptedAddress& next);
    Result<void> set_prev_block(const EncryptedAddress& prev);
    const EncryptedAddress& get_next_block() const { return header_.next_block; }
    const EncryptedAddress& get_prev_block() const { return header_.prev_block; }
    
    // Timestamp operations
    Result<void> update_timestamp();
    Result<std::chrono::seconds> get_creation_time() const;
    Result<std::chrono::seconds> get_modification_time() const;
    
    // Payload access (user data area)
    void* get_payload_ptr() { return payload_data_.get(); }
    const void* get_payload_ptr() const { return payload_data_.get(); }
    
    // Integrity and validation
    Result<bool> validate_integrity() const;
    Result<void> recompute_checksums();
    Result<bool> verify_magic_number() const;
    Result<bool> verify_size_consistency() const;
    
    // Serialization support
    Result<std::vector<uint8_t>> serialize() const;
    static Result<std::unique_ptr<EncryptedMemoryBlock>> deserialize(
        std::shared_ptr<BFVContext> context,
        const std::vector<uint8_t>& data);
    
    // Version compatibility
    BlockVersion get_version() const;
    Result<bool> is_version_compatible(const BlockVersion& other_version) const;
    
    // Security operations
    Result<void> secure_wipe();
    Result<void> lock_memory();
    Result<void> unlock_memory();
    
    // Debug and diagnostic
    std::string debug_info() const;
    Result<void> self_test() const;
    
private:
    std::shared_ptr<BFVContext> context_;
    EncryptedBlockHeader header_;
    EncryptedBlockFooter footer_;
    std::unique_ptr<uint8_t[]> payload_data_;
    size_t payload_capacity_;
    std::atomic<bool> is_locked_{false};
    
    // Internal helper methods
    Result<void> initialize_header(const EncryptedSize& size);
    Result<void> initialize_footer();
    Result<void> allocate_payload(size_t size);
    Result<EncryptedInt> compute_header_checksum() const;
    Result<EncryptedInt> compute_payload_checksum() const;
    Result<EncryptedInt> compute_mac() const;
    Result<bool> validate_header_checksum() const;
    Result<bool> validate_payload_checksum() const;
    Result<bool> validate_mac() const;
    void secure_zero_memory(void* ptr, size_t size);
};

/**
 * @brief Block validation utilities for detecting corruption and tampering
 */
class BlockValidator {
public:
    explicit BlockValidator(std::shared_ptr<BFVContext> context);
    
    // Single block validation
    Result<bool> validate_block(const EncryptedMemoryBlock& block) const;
    Result<bool> detect_corruption(const EncryptedMemoryBlock& block) const;
    Result<bool> detect_tampering(const EncryptedMemoryBlock& block) const;
    
    // Block chain validation
    Result<bool> validate_block_chain(const std::vector<const EncryptedMemoryBlock*>& blocks) const;
    Result<bool> check_consistency_violations(const std::vector<const EncryptedMemoryBlock*>& blocks) const;
    
    // Diagnostic methods
    struct ValidationReport {
        bool is_valid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        size_t blocks_checked;
        std::chrono::microseconds validation_time;
    };
    
    Result<ValidationReport> comprehensive_validation(const EncryptedMemoryBlock& block) const;
    Result<ValidationReport> batch_validation(const std::vector<const EncryptedMemoryBlock*>& blocks) const;
    
private:
    std::shared_ptr<BFVContext> context_;
    
    Result<bool> check_header_integrity(const EncryptedMemoryBlock& block) const;
    Result<bool> check_footer_integrity(const EncryptedMemoryBlock& block) const;
    Result<bool> check_version_compatibility(const EncryptedMemoryBlock& block) const;
    Result<bool> check_size_consistency(const EncryptedMemoryBlock& block) const;
    Result<bool> check_timestamp_validity(const EncryptedMemoryBlock& block) const;
};

/**
 * @brief Block serialization/deserialization maintaining OpenFHE compatibility
 */
class BlockSerializer {
public:
    explicit BlockSerializer(std::shared_ptr<BFVContext> context);
    
    // Serialization methods
    Result<std::vector<uint8_t>> serialize_block(const EncryptedMemoryBlock& block) const;
    Result<std::vector<uint8_t>> serialize_header(const EncryptedBlockHeader& header) const;
    Result<std::vector<uint8_t>> serialize_footer(const EncryptedBlockFooter& footer) const;
    
    // Deserialization methods
    Result<std::unique_ptr<EncryptedMemoryBlock>> deserialize_block(const std::vector<uint8_t>& data) const;
    Result<EncryptedBlockHeader> deserialize_header(const std::vector<uint8_t>& data, size_t offset) const;
    Result<EncryptedBlockFooter> deserialize_footer(const std::vector<uint8_t>& data, size_t offset) const;
    
    // Batch operations
    Result<std::vector<uint8_t>> serialize_block_chain(const std::vector<const EncryptedMemoryBlock*>& blocks) const;
    Result<std::vector<std::unique_ptr<EncryptedMemoryBlock>>> deserialize_block_chain(const std::vector<uint8_t>& data) const;
    
    // Compatibility checking
    Result<bool> check_format_version(const std::vector<uint8_t>& data) const;
    Result<BlockVersion> get_serialized_version(const std::vector<uint8_t>& data) const;
    
    // Format information
    struct SerializationInfo {
        size_t total_size;
        size_t header_size;
        size_t footer_size;
        size_t payload_size;
        BlockVersion format_version;
        bool is_compressed;
        std::chrono::microseconds serialization_time;
    };
    
    Result<SerializationInfo> get_serialization_info(const std::vector<uint8_t>& data) const;
    
private:
    std::shared_ptr<BFVContext> context_;
    
    Result<size_t> write_encrypted_size(std::vector<uint8_t>& buffer, size_t offset, const EncryptedSize& value) const;
    Result<size_t> write_encrypted_int(std::vector<uint8_t>& buffer, size_t offset, const EncryptedInt& value) const;
    Result<size_t> write_encrypted_address(std::vector<uint8_t>& buffer, size_t offset, const EncryptedAddress& value) const;
    
    Result<std::pair<EncryptedSize, size_t>> read_encrypted_size(const std::vector<uint8_t>& buffer, size_t offset) const;
    Result<std::pair<EncryptedInt, size_t>> read_encrypted_int(const std::vector<uint8_t>& buffer, size_t offset) const;
    Result<std::pair<EncryptedAddress, size_t>> read_encrypted_address(const std::vector<uint8_t>& buffer, size_t offset) const;
};

/**
 * @brief Memory block lifecycle manager for secure creation, updates, and destruction
 */
class BlockLifecycleManager {
public:
    explicit BlockLifecycleManager(std::shared_ptr<BFVContext> context);
    ~BlockLifecycleManager();
    
    // Block creation
    Result<std::unique_ptr<EncryptedMemoryBlock>> create_block(size_t size);
    Result<std::unique_ptr<EncryptedMemoryBlock>> create_block_with_data(const void* data, size_t size);
    
    // Block tracking and management
    Result<void> register_block(const EncryptedMemoryBlock* block);
    Result<void> unregister_block(const EncryptedMemoryBlock* block);
    Result<bool> is_block_registered(const EncryptedMemoryBlock* block) const;
    
    // Safe destruction
    Result<void> secure_destroy_block(std::unique_ptr<EncryptedMemoryBlock> block);
    Result<void> emergency_cleanup();
    
    // Memory leak detection
    size_t get_active_block_count() const;
    Result<std::vector<const EncryptedMemoryBlock*>> get_active_blocks() const;
    Result<void> detect_memory_leaks() const;
    
    // Statistics
    struct LifecycleStats {
        size_t total_blocks_created;
        size_t total_blocks_destroyed;
        size_t current_active_blocks;
        size_t total_memory_allocated;
        size_t peak_memory_usage;
        std::chrono::microseconds avg_creation_time;
        std::chrono::microseconds avg_destruction_time;
    };
    
    LifecycleStats get_stats() const;
    void reset_stats();
    
private:
    std::shared_ptr<BFVContext> context_;
    mutable std::mutex blocks_mutex_;
    std::unordered_set<const EncryptedMemoryBlock*> active_blocks_;
    
    // Statistics tracking
    mutable std::atomic<size_t> total_created_{0};
    mutable std::atomic<size_t> total_destroyed_{0};
    mutable std::atomic<size_t> total_memory_{0};
    mutable std::atomic<size_t> peak_memory_{0};
    
    void update_stats_on_create(size_t block_size);
    void update_stats_on_destroy(size_t block_size);
};

// Utility functions for block operations
namespace block_utils {
    /**
     * @brief Calculate optimal block size including headers and alignment
     */
    size_t calculate_total_block_size(size_t payload_size, size_t alignment = 8);
    
    /**
     * @brief Check if size is valid for block creation
     */
    bool is_valid_block_size(size_t size);
    
    /**
     * @brief Align size to specified boundary
     */
    size_t align_size(size_t size, size_t alignment);
    
    /**
     * @brief Secure comparison of encrypted values with timing attack protection
     */
    Result<bool> secure_encrypted_compare(const EncryptedInt& a, const EncryptedInt& b, 
                                         std::shared_ptr<BFVContext> context);
    
    /**
     * @brief Generate cryptographically secure random values for MACs
     */
    Result<EncryptedInt> generate_secure_random_encrypted(std::shared_ptr<BFVContext> context);
}

} // namespace cryptmalloc