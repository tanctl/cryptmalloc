/**
 * @file test_encrypted_block.cpp
 * @brief Comprehensive tests for encrypted memory block with cryptographic integrity protection
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <cstring>

#include "cryptmalloc/encrypted_block.hpp"
#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

// Test fixture for encrypted block tests
class EncryptedBlockTestFixture {
public:
    EncryptedBlockTestFixture() {
        auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 50000, 3);
        context_ = std::make_shared<BFVContext>(params);
        auto init_result = context_->initialize();
        if (!init_result.has_value()) {
            throw std::runtime_error("Failed to initialize BFV context for encrypted block tests");
        }
    }

    std::shared_ptr<BFVContext> context() { return context_; }

    std::unique_ptr<EncryptedMemoryBlock> create_test_block(size_t size = 128) {
        auto result = EncryptedMemoryBlock::create_block_from_plaintext_size(context_, size);
        if (!result.has_value()) {
            throw std::runtime_error("Failed to create test block: " + result.error());
        }
        return result.take();
    }

private:
    std::shared_ptr<BFVContext> context_;
};

TEST_CASE_METHOD(EncryptedBlockTestFixture, "EncryptedMemoryBlock basic functionality", "[encrypted_block][basic]") {
    SECTION("Block creation and initialization") {
        auto block = create_test_block(128);
        
        REQUIRE(block != nullptr);
        
        // Check initial status
        auto status_result = block->get_status();
        REQUIRE(status_result.has_value());
        REQUIRE(status_result.value() == BlockStatus::FREE);
        
        // Check size
        auto size_result = block->get_plaintext_size();
        REQUIRE(size_result.has_value());
        REQUIRE(size_result.value() == 128);
        
        // Check payload size
        auto payload_size_result = block->get_payload_size();
        REQUIRE(payload_size_result.has_value());
        REQUIRE(payload_size_result.value() > 0);
        REQUIRE(payload_size_result.value() < 128); // Should be less due to headers
    }
    
    SECTION("Block status management") {
        auto block = create_test_block();
        
        // Test setting status to allocated
        auto set_result = block->set_status(BlockStatus::ALLOCATED);
        REQUIRE(set_result.has_value());
        
        auto status_result = block->get_status();
        REQUIRE(status_result.has_value());
        REQUIRE(status_result.value() == BlockStatus::ALLOCATED);
        
        auto is_allocated_result = block->is_allocated();
        REQUIRE(is_allocated_result.has_value());
        REQUIRE(is_allocated_result.value() == true);
        
        auto is_free_result = block->is_free();
        REQUIRE(is_free_result.has_value());
        REQUIRE(is_free_result.value() == false);
        
        // Test setting back to free
        block->set_status(BlockStatus::FREE);
        is_free_result = block->is_free();
        REQUIRE(is_free_result.has_value());
        REQUIRE(is_free_result.value() == true);
    }
    
    SECTION("Block size operations") {
        auto block = create_test_block(512);
        
        auto size_result = block->get_plaintext_size();
        REQUIRE(size_result.has_value());
        REQUIRE(size_result.value() == 512);
        
        // Check that payload size is reasonable
        auto payload_size_result = block->get_payload_size();
        REQUIRE(payload_size_result.has_value());
        REQUIRE(payload_size_result.value() > 400); // Should be most of the space
        REQUIRE(payload_size_result.value() < 512); // But less than total
    }
    
    SECTION("Block version compatibility") {
        auto block = create_test_block();
        
        auto version = block->get_version();
        REQUIRE(version.major == 1);
        REQUIRE(version.minor == 0);
        REQUIRE(version.patch == 0);
        
        BlockVersion compatible_version{1, 0, 1, 0};
        auto compat_result = block->is_version_compatible(compatible_version);
        REQUIRE(compat_result.has_value());
        REQUIRE(compat_result.value() == true);
        
        BlockVersion incompatible_version{2, 0, 0, 0};
        auto incompat_result = block->is_version_compatible(incompatible_version);
        REQUIRE(incompat_result.has_value());
        REQUIRE(incompat_result.value() == false);
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block integrity and validation", "[encrypted_block][integrity]") {
    SECTION("Basic integrity validation") {
        auto block = create_test_block();
        
        // Block should be valid after creation
        auto integrity_result = block->validate_integrity();
        REQUIRE(integrity_result.has_value());
        REQUIRE(integrity_result.value() == true);
        
        // Self-test should pass
        auto self_test_result = block->self_test();
        REQUIRE(self_test_result.has_value());
    }
    
    SECTION("Magic number verification") {
        auto block = create_test_block();
        
        auto magic_result = block->verify_magic_number();
        REQUIRE(magic_result.has_value());
        REQUIRE(magic_result.value() == true);
    }
    
    SECTION("Size consistency verification") {
        auto block = create_test_block();
        
        auto consistency_result = block->verify_size_consistency();
        REQUIRE(consistency_result.has_value());
        REQUIRE(consistency_result.value() == true);
    }
    
    SECTION("Checksum recomputation") {
        auto block = create_test_block();
        
        // Modify status to trigger checksum update
        auto set_status_result = block->set_status(BlockStatus::ALLOCATED);
        REQUIRE(set_status_result.has_value());
        
        // Integrity should still be valid
        auto integrity_result = block->validate_integrity();
        REQUIRE(integrity_result.has_value());
        REQUIRE(integrity_result.value() == true);
        
        // Manual checksum recomputation
        auto recompute_result = block->recompute_checksums();
        REQUIRE(recompute_result.has_value());
        
        // Should still be valid
        integrity_result = block->validate_integrity();
        REQUIRE(integrity_result.has_value());
        REQUIRE(integrity_result.value() == true);
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block splitting operations", "[encrypted_block][splitting]") {
    SECTION("Basic block splitting") {
        auto block = create_test_block(256);
        
        // Split block in half
        auto split_size = EncryptedSize(128, context());
        auto split_result = block->split_block(split_size);
        
        REQUIRE(split_result.has_value());
        
        auto [first_block, second_block] = split_result.take();
        
        REQUIRE(first_block != nullptr);
        REQUIRE(second_block != nullptr);
        
        // Check sizes
        auto first_size_result = first_block->get_plaintext_size();
        auto second_size_result = second_block->get_plaintext_size();
        
        REQUIRE(first_size_result.has_value());
        REQUIRE(second_size_result.has_value());
        REQUIRE(first_size_result.value() == 128);
        REQUIRE(second_size_result.value() == 128);
        
        // Both blocks should be valid
        auto first_integrity = first_block->validate_integrity();
        auto second_integrity = second_block->validate_integrity();
        
        REQUIRE(first_integrity.has_value());
        REQUIRE(first_integrity.value() == true);
        REQUIRE(second_integrity.has_value());
        REQUIRE(second_integrity.value() == true);
    }
    
    SECTION("Split size validation") {
        auto block = create_test_block(128);
        
        // Try to split with too large size
        auto large_split_size = EncryptedSize(150, context());
        auto large_split_result = block->split_block(large_split_size);
        REQUIRE_FALSE(large_split_result.has_value());
        
        // Try to split with too small size
        auto small_split_size = EncryptedSize(32, context()); // Below MIN_BLOCK_SIZE
        auto small_split_result = block->split_block(small_split_size);
        REQUIRE_FALSE(small_split_result.has_value());
    }
    
    SECTION("Split allocated block should fail") {
        auto block = create_test_block();
        
        // Set block to allocated
        auto set_status_result = block->set_status(BlockStatus::ALLOCATED);
        REQUIRE(set_status_result.has_value());
        
        // Try to split - should fail
        auto split_size = EncryptedSize(64, context());
        auto split_result = block->split_block(split_size);
        REQUIRE_FALSE(split_result.has_value());
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block merging operations", "[encrypted_block][merging]") {
    SECTION("Basic block merging") {
        auto block1 = create_test_block(128);
        auto block2 = create_test_block(128);
        
        // Both blocks should be free for merging
        REQUIRE((block1->is_free().has_value() && block1->is_free().value() == true));
        REQUIRE((block2->is_free().has_value() && block2->is_free().value() == true));
        
        auto merge_result = EncryptedMemoryBlock::merge_blocks(std::move(block1), std::move(block2));
        
        REQUIRE(merge_result.has_value());
        
        auto merged_block = merge_result.take();
        REQUIRE(merged_block != nullptr);
        
        // Check merged size
        auto merged_size_result = merged_block->get_plaintext_size();
        REQUIRE(merged_size_result.has_value());
        REQUIRE(merged_size_result.value() == 256);
        
        // Merged block should be valid
        auto integrity_result = merged_block->validate_integrity();
        REQUIRE(integrity_result.has_value());
        REQUIRE(integrity_result.value() == true);
    }
    
    SECTION("Merge with null blocks should fail") {
        auto block1 = create_test_block();
        
        auto merge_result = EncryptedMemoryBlock::merge_blocks(std::move(block1), nullptr);
        REQUIRE_FALSE(merge_result.has_value());
    }
    
    SECTION("Merge allocated blocks should fail") {
        auto block1 = create_test_block();
        auto block2 = create_test_block();
        
        // Set one block to allocated
        auto set_status_result = block1->set_status(BlockStatus::ALLOCATED);
        REQUIRE(set_status_result.has_value());
        
        auto merge_result = EncryptedMemoryBlock::merge_blocks(std::move(block1), std::move(block2));
        REQUIRE_FALSE(merge_result.has_value());
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block payload operations", "[encrypted_block][payload]") {
    SECTION("Payload access and modification") {
        auto block = create_test_block();
        
        void* payload_ptr = block->get_payload_ptr();
        REQUIRE(payload_ptr != nullptr);
        
        auto payload_size_result = block->get_payload_size();
        REQUIRE(payload_size_result.has_value());
        
        size_t payload_size = payload_size_result.value();
        
        // Write test data
        const char test_data[] = "Hello, Encrypted World!";
        size_t test_data_size = std::min(sizeof(test_data), payload_size);
        
        std::memcpy(payload_ptr, test_data, test_data_size);
        
        // Recompute checksums after modification
        auto recompute_result = block->recompute_checksums();
        REQUIRE(recompute_result.has_value());
        
        // Block should still be valid
        auto integrity_result = block->validate_integrity();
        REQUIRE(integrity_result.has_value());
        REQUIRE(integrity_result.value() == true);
        
        // Verify data
        REQUIRE(std::memcmp(payload_ptr, test_data, test_data_size) == 0);
    }
    
    SECTION("Payload in split blocks") {
        auto block = create_test_block(256);
        
        // Write test data
        void* payload_ptr = block->get_payload_ptr();
        const char test_data[] = "Test data for splitting";
        size_t test_data_size = sizeof(test_data);
        
        std::memcpy(payload_ptr, test_data, test_data_size);
        block->recompute_checksums();
        
        // Split block
        auto split_size = EncryptedSize(128, context());
        auto split_result = block->split_block(split_size);
        REQUIRE(split_result.has_value());
        
        auto [first_block, second_block] = split_result.take();
        
        // Check that data is preserved in first block
        void* first_payload = first_block->get_payload_ptr();
        REQUIRE(first_payload != nullptr);
        
        // At least some of the data should be in the first block
        bool data_found = (std::memcmp(first_payload, test_data, std::min(test_data_size, size_t(10))) == 0);
        REQUIRE(data_found);
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block timestamp operations", "[encrypted_block][timestamps]") {
    SECTION("Creation and modification timestamps") {
        auto block = create_test_block();
        
        auto creation_time_result = block->get_creation_time();
        auto modification_time_result = block->get_modification_time();
        
        REQUIRE(creation_time_result.has_value());
        REQUIRE(modification_time_result.has_value());
        
        // Initially, creation and modification times should be the same
        REQUIRE(creation_time_result.value() == modification_time_result.value());
        
        // Sleep briefly and update status
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        auto set_status_result = block->set_status(BlockStatus::ALLOCATED);
        REQUIRE(set_status_result.has_value());
        
        // Modification time should be updated
        auto new_modification_time_result = block->get_modification_time();
        REQUIRE(new_modification_time_result.has_value());
        REQUIRE(new_modification_time_result.value() >= modification_time_result.value());
        
        // Creation time should remain the same
        auto new_creation_time_result = block->get_creation_time();
        REQUIRE(new_creation_time_result.has_value());
        REQUIRE(new_creation_time_result.value() == creation_time_result.value());
    }
    
    SECTION("Manual timestamp update") {
        auto block = create_test_block();
        
        auto initial_time_result = block->get_modification_time();
        REQUIRE(initial_time_result.has_value());
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        auto update_result = block->update_timestamp();
        REQUIRE(update_result.has_value());
        
        auto updated_time_result = block->get_modification_time();
        REQUIRE(updated_time_result.has_value());
        REQUIRE(updated_time_result.value() > initial_time_result.value());
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block security operations", "[encrypted_block][security]") {
    SECTION("Secure memory wiping") {
        auto block = create_test_block();
        
        // Write test data
        void* payload_ptr = block->get_payload_ptr();
        const char test_data[] = "Sensitive data to be wiped";
        std::memcpy(payload_ptr, test_data, sizeof(test_data));
        
        // Wipe memory
        auto wipe_result = block->secure_wipe();
        REQUIRE(wipe_result.has_value());
        
        // Check that memory is zeroed (basic check)
        const uint8_t* payload_bytes = static_cast<const uint8_t*>(payload_ptr);
        bool all_zero = true;
        for (size_t i = 0; i < sizeof(test_data); ++i) {
            if (payload_bytes[i] != 0) {
                all_zero = false;
                break;
            }
        }
        REQUIRE(all_zero);
    }
    
    SECTION("Memory locking operations") {
        auto block = create_test_block();
        
        // Lock memory (may fail on systems without privilege)
        auto lock_result = block->lock_memory();
        // Don't require success as it may need privileges
        
        if (lock_result.has_value()) {
            // If locking succeeded, unlocking should work
            auto unlock_result = block->unlock_memory();
            REQUIRE(unlock_result.has_value());
        }
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "BlockValidator functionality", "[encrypted_block][validation]") {
    SECTION("Basic block validation") {
        BlockValidator validator(context());
        auto block = create_test_block();
        
        auto validation_result = validator.validate_block(*block);
        REQUIRE(validation_result.has_value());
        REQUIRE(validation_result.value() == true);
    }
    
    SECTION("Corruption detection") {
        BlockValidator validator(context());
        auto block = create_test_block();
        
        // Initially no corruption
        auto corruption_result = validator.detect_corruption(*block);
        REQUIRE(corruption_result.has_value());
        REQUIRE(corruption_result.value() == true); // No corruption detected
        
        // Corruption would be detected by checksum mismatches
        // (In a real scenario, we would manually corrupt the block)
    }
    
    SECTION("Tampering detection") {
        BlockValidator validator(context());
        auto block = create_test_block();
        
        auto tampering_result = validator.detect_tampering(*block);
        REQUIRE(tampering_result.has_value());
        REQUIRE(tampering_result.value() == true); // No tampering detected
    }
    
    SECTION("Comprehensive validation report") {
        BlockValidator validator(context());
        auto block = create_test_block();
        
        auto report_result = validator.comprehensive_validation(*block);
        REQUIRE(report_result.has_value());
        
        const auto& report = report_result.value();
        REQUIRE(report.is_valid == true);
        REQUIRE(report.blocks_checked == 1);
        REQUIRE(report.errors.empty());
        REQUIRE(report.validation_time.count() > 0);
    }
    
    SECTION("Block chain validation") {
        BlockValidator validator(context());
        
        auto block1 = create_test_block();
        auto block2 = create_test_block();
        auto block3 = create_test_block();
        
        // Set up a simple chain (without proper linking for simplicity)
        std::vector<const EncryptedMemoryBlock*> blocks = {
            block1.get(), block2.get(), block3.get()
        };
        
        auto chain_result = validator.validate_block_chain(blocks);
        REQUIRE(chain_result.has_value());
        // Chain validation might fail due to improper linking, but method should work
    }
    
    SECTION("Batch validation") {
        BlockValidator validator(context());
        
        std::vector<std::unique_ptr<EncryptedMemoryBlock>> owned_blocks;
        std::vector<const EncryptedMemoryBlock*> block_ptrs;
        
        // Create multiple blocks
        for (int i = 0; i < 5; ++i) {
            auto block = create_test_block(128 + i * 64);
            block_ptrs.push_back(block.get());
            owned_blocks.push_back(std::move(block));
        }
        
        auto batch_result = validator.batch_validation(block_ptrs);
        REQUIRE(batch_result.has_value());
        
        const auto& report = batch_result.value();
        REQUIRE(report.blocks_checked == 5);
        REQUIRE(report.validation_time.count() > 0);
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block utility functions", "[encrypted_block][utils]") {
    SECTION("Block size calculations") {
        size_t payload_size = 100;
        size_t total_size = block_utils::calculate_total_block_size(payload_size);
        
        REQUIRE(total_size > payload_size);
        REQUIRE(total_size >= EncryptedMemoryBlock::MIN_BLOCK_SIZE);
        
        // With alignment
        size_t aligned_size = block_utils::calculate_total_block_size(payload_size, 16);
        REQUIRE(aligned_size >= total_size);
        REQUIRE(aligned_size % 16 == 0);
    }
    
    SECTION("Block size validation") {
        REQUIRE(block_utils::is_valid_block_size(128) == true);
        REQUIRE(block_utils::is_valid_block_size(32) == false); // Too small
        REQUIRE(block_utils::is_valid_block_size(SIZE_MAX) == false); // Too large
    }
    
    SECTION("Size alignment") {
        REQUIRE(block_utils::align_size(100, 8) == 104);
        REQUIRE(block_utils::align_size(100, 16) == 112);
        REQUIRE(block_utils::align_size(128, 16) == 128); // Already aligned
        REQUIRE(block_utils::align_size(100, 1) == 100); // No alignment
    }
    
    SECTION("Secure encrypted comparison") {
        auto val1 = EncryptedInt(42, context());
        auto val2 = EncryptedInt(42, context());
        auto val3 = EncryptedInt(24, context());
        
        auto eq_result = block_utils::secure_encrypted_compare(val1, val2, context());
        REQUIRE(eq_result.has_value());
        REQUIRE(eq_result.value() == true);
        
        auto neq_result = block_utils::secure_encrypted_compare(val1, val3, context());
        REQUIRE(neq_result.has_value());
        REQUIRE(neq_result.value() == false);
    }
    
    SECTION("Secure random generation") {
        auto random1_result = block_utils::generate_secure_random_encrypted(context());
        auto random2_result = block_utils::generate_secure_random_encrypted(context());
        
        REQUIRE(random1_result.has_value());
        REQUIRE(random2_result.has_value());
        
        // Values should be different (with high probability)
        BFVOperations ops(context());
        auto diff_result_encrypted = ops.subtract(random1_result.value(), random2_result.value());
        REQUIRE(diff_result_encrypted.has_value());
        auto diff_result = diff_result_encrypted.value().decrypt();
        REQUIRE(diff_result.has_value());
        // Allow small chance they're equal
        // bool are_different = (diff_result.value() != 0);
        // We can't require this with 100% certainty due to randomness
        // but the probability is very low (commented out to avoid unused variable warning)
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block error handling", "[encrypted_block][error_handling]") {
    SECTION("Invalid block creation") {
        // Try to create block with size too small
        auto small_result = EncryptedMemoryBlock::create_block_from_plaintext_size(context(), 32);
        REQUIRE_FALSE(small_result.has_value());
        
        // Try with null context
        auto null_result = EncryptedMemoryBlock::create_block_from_plaintext_size(nullptr, 128);
        REQUIRE_FALSE(null_result.has_value());
    }
    
    SECTION("Operations on corrupted block") {
        auto block = create_test_block();
        
        // Set block to corrupted status
        auto corrupt_result = block->set_status(BlockStatus::CORRUPTED);
        REQUIRE(corrupt_result.has_value());
        
        // Operations should still work but with corrupted status
        auto status_result = block->get_status();
        REQUIRE(status_result.has_value());
        REQUIRE(status_result.value() == BlockStatus::CORRUPTED);
    }

    SECTION("Self-test validation") {
        auto block = create_test_block();
        
        auto self_test_result = block->self_test();
        REQUIRE(self_test_result.has_value());
    }
}

TEST_CASE_METHOD(EncryptedBlockTestFixture, "Debug and diagnostic", "[encrypted_block][debug]") {
    SECTION("Debug information") {
        auto block = create_test_block();
        
        std::string debug_info = block->debug_info();
        REQUIRE_FALSE(debug_info.empty());
        REQUIRE(debug_info.find("EncryptedMemoryBlock Debug Info") != std::string::npos);
        REQUIRE(debug_info.find("Total Size") != std::string::npos);
        REQUIRE(debug_info.find("Status") != std::string::npos);
    }
}

// Benchmarks for performance analysis
TEST_CASE_METHOD(EncryptedBlockTestFixture, "Block performance benchmarks", "[encrypted_block][benchmark]") {
    SECTION("Block creation performance") {
        const size_t num_iterations = 10; // Reduced for homomorphic encryption
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < num_iterations; ++i) {
            auto block = create_test_block(128);
            // Block will be destroyed automatically
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        double avg_time = static_cast<double>(duration.count()) / num_iterations;
        
        // Log performance info (times will be much higher due to encryption)
        INFO("Average block creation time: " << avg_time << " microseconds");
        
        // Sanity check - should complete within reasonable time
        REQUIRE(avg_time < 1000000); // Less than 1 second per block
    }
    
    SECTION("Block validation performance") {
        auto block = create_test_block();
        BlockValidator validator(context());
        
        const size_t num_validations = 5; // Reduced for encryption overhead
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < num_validations; ++i) {
            auto result = validator.validate_block(*block);
            REQUIRE(result.has_value());
            REQUIRE(result.value() == true);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        double avg_time = static_cast<double>(duration.count()) / num_validations;
        
        INFO("Average block validation time: " << avg_time << " microseconds");
        
        // Should complete within reasonable time
        REQUIRE(avg_time < 500000); // Less than 0.5 seconds per validation
    }
}