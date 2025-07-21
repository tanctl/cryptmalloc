/**
 * @file test_memory_pool.cpp
 * @brief comprehensive tests for virtual memory pool simulation
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <thread>
#include <chrono>
#include <random>

#include "cryptmalloc/memory_pool.hpp"
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

// test fixture for memory pool tests
class MemoryPoolTestFixture {
public:
    MemoryPoolTestFixture() {
        auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
        context_ = std::make_shared<BFVContext>(params);
        auto init_result = context_->initialize();
        if (!init_result.has_value()) {
            throw std::runtime_error("Failed to initialize BFV context for memory pool tests");
        }
    }

    std::shared_ptr<BFVContext> context() { return context_; }

    VirtualMemoryPool create_pool(const PoolConfig& config = PoolConfig::debug_config()) {
        return VirtualMemoryPool(context_, config);
    }

private:
    std::shared_ptr<BFVContext> context_;
};

TEST_CASE_METHOD(MemoryPoolTestFixture, "VirtualMemoryPool basic functionality", "[memory_pool][basic]") {
    SECTION("Pool initialization and shutdown") {
        auto pool = create_pool();
        
        REQUIRE_FALSE(pool.is_initialized());
        
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        REQUIRE(pool.is_initialized());
        
        auto shutdown_result = pool.shutdown();
        REQUIRE(shutdown_result.has_value());
        REQUIRE_FALSE(pool.is_initialized());
    }
    
    SECTION("Pool configuration validation") {
        auto default_config = PoolConfig::default_config();
        auto performance_config = PoolConfig::performance_config();
        auto debug_config = PoolConfig::debug_config();
        
        REQUIRE(default_config.total_size > 0);
        REQUIRE(default_config.min_block_size > 0);
        REQUIRE(default_config.max_block_size >= default_config.min_block_size);
        
        REQUIRE(performance_config.total_size >= default_config.total_size);
        REQUIRE(debug_config.total_size <= default_config.total_size);
    }
    
    SECTION("Pool size queries") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto total_size = pool.total_size();
        REQUIRE(total_size.has_value());
        
        auto used_size = pool.used_size();
        REQUIRE(used_size.has_value());
        
        auto free_size = pool.free_size();
        REQUIRE(free_size.has_value());
        
        // verify initial state
        auto used_decrypted = used_size.value().decrypt();
        REQUIRE(used_decrypted.has_value());
        REQUIRE(used_decrypted.value() == 0);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Memory allocation and deallocation", "[memory_pool][allocation]") {
    SECTION("Basic allocation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        const auto* block = alloc_result.value();
        auto size_decrypted = block->size.decrypt();
        REQUIRE(size_decrypted.has_value());
        REQUIRE(size_decrypted.value() == 64);
        
        REQUIRE(block->access_count.load() == 0);
        REQUIRE_FALSE(block->is_free.load());
    }
    
    SECTION("Allocation with different alignments") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        std::vector<Alignment> alignments = {
            Alignment::BYTE_1, Alignment::BYTE_8, 
            Alignment::BYTE_16, Alignment::BYTE_32
        };
        
        for (auto alignment : alignments) {
            auto alloc_result = pool.allocate(64, alignment);
            REQUIRE(alloc_result.has_value());
            
            auto align_decrypted = alloc_result.value()->alignment.decrypt();
            REQUIRE(align_decrypted.has_value());
            REQUIRE(align_decrypted.value() == static_cast<int64_t>(alignment));
        }
    }
    
    SECTION("Allocation with different access patterns") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        std::vector<AccessPattern> patterns = {
            AccessPattern::SEQUENTIAL, AccessPattern::RANDOM,
            AccessPattern::LOCALITY, AccessPattern::STRIDED, AccessPattern::MIXED
        };
        
        for (auto pattern : patterns) {
            auto alloc_result = pool.allocate(64, Alignment::BYTE_8, pattern);
            REQUIRE(alloc_result.has_value());
            REQUIRE(alloc_result.value()->access_pattern == pattern);
        }
    }
    
    SECTION("Deallocation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        auto dealloc_result = pool.deallocate(alloc_result.value()->virtual_address);
        REQUIRE(dealloc_result.has_value());
        
        // verify used size decreased
        auto used_size = pool.used_size();
        REQUIRE(used_size.has_value());
        auto used_decrypted = used_size.value().decrypt();
        REQUIRE(used_decrypted.has_value());
        REQUIRE(used_decrypted.value() == 0);
    }
    
    SECTION("Allocation size limits") {
        auto config = PoolConfig::debug_config();
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // too small
        auto small_result = pool.allocate(config.min_block_size - 1);
        REQUIRE_FALSE(small_result.has_value());
        
        // too large
        auto large_result = pool.allocate(config.max_block_size + 1);
        REQUIRE_FALSE(large_result.has_value());
        
        // just right
        auto good_result = pool.allocate(config.min_block_size);
        REQUIRE(good_result.has_value());
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Memory access simulation", "[memory_pool][access_simulation]") {
    SECTION("Basic access simulation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        auto access_result = pool.simulate_access(alloc_result.value()->virtual_address);
        REQUIRE(access_result.has_value());
        REQUIRE(access_result.value().count() > 0);
        
        // check statistics updated
        const auto& stats = pool.access_statistics();
        REQUIRE(stats.total_accesses.load() > 0);
    }
    
    SECTION("Access with different patterns") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(1024);
        REQUIRE(alloc_result.has_value());
        
        std::vector<AccessPattern> patterns = {
            AccessPattern::SEQUENTIAL, AccessPattern::RANDOM, AccessPattern::LOCALITY
        };
        
        for (auto pattern : patterns) {
            auto access_result = pool.simulate_access(
                alloc_result.value()->virtual_address, 8, pattern);
            REQUIRE(access_result.has_value());
        }
        
        const auto& stats = pool.access_statistics();
        REQUIRE(stats.total_accesses.load() == patterns.size());
    }
    
    SECTION("Cache hit ratio tracking") {
        auto config = PoolConfig::debug_config();
        config.cache_hit_ratio = 0.8;
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        // perform many accesses to get statistically meaningful results
        for (int i = 0; i < 100; ++i) {
            auto access_result = pool.simulate_access(alloc_result.value()->virtual_address);
            REQUIRE(access_result.has_value());
        }
        
        const auto& stats = pool.access_statistics();
        REQUIRE(stats.total_accesses.load() == 100);
        
        double actual_hit_ratio = stats.cache_hit_ratio();
        // should be reasonably close to configured ratio (within 20%)
        REQUIRE(actual_hit_ratio >= 0.6);
        REQUIRE(actual_hit_ratio <= 1.0);
    }
    
    SECTION("Prefetch simulation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(1024);
        REQUIRE(alloc_result.has_value());
        
        auto prefetch_result = pool.prefetch(alloc_result.value()->virtual_address, 256);
        REQUIRE(prefetch_result.has_value());
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Fragmentation analysis", "[memory_pool][fragmentation]") {
    SECTION("Basic fragmentation info") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto frag_info = pool.fragmentation_info();
        REQUIRE(frag_info.has_value());
        
        const auto& info = frag_info.value();
        REQUIRE(info.free_block_count >= 1); // at least one initial free block
        REQUIRE(info.total_free_space > 0);
        REQUIRE(info.external_fragmentation >= 0.0);
        REQUIRE(info.internal_fragmentation >= 0.0);
    }
    
    SECTION("Fragmentation after allocations") {
        auto config = PoolConfig::debug_config();
        config.enable_fragmentation_sim = true;
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // allocate several blocks to create fragmentation
        std::vector<const MemoryBlock*> blocks;
        for (int i = 0; i < 5; ++i) {
            auto alloc_result = pool.allocate(64 + i * 32);
            REQUIRE(alloc_result.has_value());
            blocks.push_back(alloc_result.value());
        }
        
        // deallocate every other block to create holes
        for (size_t i = 1; i < blocks.size(); i += 2) {
            auto dealloc_result = pool.deallocate(blocks[i]->virtual_address);
            REQUIRE(dealloc_result.has_value());
        }
        
        auto frag_info = pool.fragmentation_info();
        REQUIRE(frag_info.has_value());
        
        const auto& info = frag_info.value();
        REQUIRE(info.free_block_count > 1); // should have multiple free blocks
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Reallocation functionality", "[memory_pool][reallocation]") {
    SECTION("Basic reallocation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        auto original_addr = alloc_result.value()->virtual_address;
        
        auto realloc_result = pool.reallocate(original_addr, 128);
        REQUIRE(realloc_result.has_value());
        
        auto new_size = realloc_result.value()->size.decrypt();
        REQUIRE(new_size.has_value());
        REQUIRE(new_size.value() == 128);
    }
    
    SECTION("Reallocation preserves access pattern") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(64, Alignment::BYTE_8, AccessPattern::SEQUENTIAL);
        REQUIRE(alloc_result.has_value());
        REQUIRE(alloc_result.value()->access_pattern == AccessPattern::SEQUENTIAL);
        
        auto realloc_result = pool.reallocate(alloc_result.value()->virtual_address, 128);
        REQUIRE(realloc_result.has_value());
        REQUIRE(realloc_result.value()->access_pattern == AccessPattern::SEQUENTIAL);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Thread safety", "[memory_pool][thread_safety]") {
    SECTION("Concurrent allocations") {
        auto config = PoolConfig::default_config();
        config.total_size = 1024 * 1024; // 1MB for more room
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        const size_t num_threads = 4;
        const size_t allocations_per_thread = 10;
        
        std::vector<std::thread> threads;
        std::atomic<size_t> successful_allocations{0};
        std::atomic<size_t> successful_deallocations{0};
        
        for (size_t t = 0; t < num_threads; ++t) {
            threads.emplace_back([&pool, &successful_allocations, &successful_deallocations, allocations_per_thread]() {
                std::vector<EncryptedAddress> allocated_addresses;
                
                for (size_t i = 0; i < allocations_per_thread; ++i) {
                    auto alloc_result = pool.allocate(64 + i * 8);
                    if (alloc_result.has_value()) {
                        allocated_addresses.push_back(alloc_result.value()->virtual_address);
                        successful_allocations.fetch_add(1);
                    }
                }
                
                for (const auto& addr : allocated_addresses) {
                    auto dealloc_result = pool.deallocate(addr);
                    if (dealloc_result.has_value()) {
                        successful_deallocations.fetch_add(1);
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        REQUIRE(successful_allocations.load() > 0);
        REQUIRE(successful_deallocations.load() == successful_allocations.load());
        
        // verify pool integrity after concurrent operations
        auto integrity_result = pool.validate_integrity();
        REQUIRE(integrity_result.has_value());
    }
    
    SECTION("Concurrent access simulation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // pre-allocate some blocks
        std::vector<const MemoryBlock*> blocks;
        for (int i = 0; i < 10; ++i) {
            auto alloc_result = pool.allocate(64);
            REQUIRE(alloc_result.has_value());
            blocks.push_back(alloc_result.value());
        }
        
        const size_t num_threads = 4;
        const size_t accesses_per_thread = 50;
        
        std::vector<std::thread> threads;
        std::atomic<size_t> total_accesses{0};
        
        for (size_t t = 0; t < num_threads; ++t) {
            threads.emplace_back([&pool, &blocks, &total_accesses, accesses_per_thread]() {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<size_t> block_dist(0, blocks.size() - 1);
                
                for (size_t i = 0; i < accesses_per_thread; ++i) {
                    size_t block_index = block_dist(gen);
                    auto access_result = pool.simulate_access(blocks[block_index]->virtual_address);
                    if (access_result.has_value()) {
                        total_accesses.fetch_add(1);
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        REQUIRE(total_accesses.load() == num_threads * accesses_per_thread);
        
        const auto& stats = pool.access_statistics();
        REQUIRE(stats.total_accesses.load() == total_accesses.load());
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Pool integrity validation", "[memory_pool][integrity]") {
    SECTION("Integrity after normal operations") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // perform various operations
        std::vector<const MemoryBlock*> blocks;
        for (int i = 0; i < 5; ++i) {
            auto alloc_result = pool.allocate(64 + i * 16);
            REQUIRE(alloc_result.has_value());
            blocks.push_back(alloc_result.value());
        }
        
        // simulate some accesses
        for (const auto& block : blocks) {
            auto access_result = pool.simulate_access(block->virtual_address);
            REQUIRE(access_result.has_value());
        }
        
        // validate integrity
        auto integrity_result = pool.validate_integrity();
        REQUIRE(integrity_result.has_value());
        
        // deallocate all blocks
        for (const auto& block : blocks) {
            auto dealloc_result = pool.deallocate(block->virtual_address);
            REQUIRE(dealloc_result.has_value());
        }
        
        // validate integrity again
        auto final_integrity = pool.validate_integrity();
        REQUIRE(final_integrity.has_value());
    }
    
    SECTION("Integrity validation detects corruption") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // normal state should validate
        auto integrity_result = pool.validate_integrity();
        REQUIRE(integrity_result.has_value());
        
        // attempt to deallocate non-existent address should fail
        EncryptedAddress fake_addr(uintptr_t(0xDEADBEEF), context());
        auto bad_dealloc = pool.deallocate(fake_addr);
        REQUIRE_FALSE(bad_dealloc.has_value());
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Memory block visualization", "[memory_pool][visualization]") {
    SECTION("Memory map generation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // allocate some blocks
        for (int i = 0; i < 3; ++i) {
            auto alloc_result = pool.allocate(64 + i * 32);
            REQUIRE(alloc_result.has_value());
        }
        
        MemoryBlockVisualizer visualizer(pool);
        auto memory_map = visualizer.generate_memory_map(80);
        
        REQUIRE_FALSE(memory_map.empty());
        REQUIRE(memory_map.find("Memory Pool Layout") != std::string::npos);
        REQUIRE(memory_map.find("#") != std::string::npos); // should show allocated blocks
    }
    
    SECTION("Fragmentation chart generation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // create some fragmentation
        std::vector<const MemoryBlock*> blocks;
        for (int i = 0; i < 4; ++i) {
            auto alloc_result = pool.allocate(64 + i * 16);
            REQUIRE(alloc_result.has_value());
            blocks.push_back(alloc_result.value());
        }
        
        // deallocate alternating blocks
        for (size_t i = 1; i < blocks.size(); i += 2) {
            auto dealloc_result = pool.deallocate(blocks[i]->virtual_address);
            REQUIRE(dealloc_result.has_value());
        }
        
        MemoryBlockVisualizer visualizer(pool);
        auto frag_chart = visualizer.generate_fragmentation_chart();
        
        REQUIRE_FALSE(frag_chart.empty());
        REQUIRE(frag_chart.find("Fragmentation Analysis") != std::string::npos);
        REQUIRE(frag_chart.find("External Fragmentation") != std::string::npos);
    }
    
    SECTION("Access pattern heatmap") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto alloc_result = pool.allocate(1024);
        REQUIRE(alloc_result.has_value());
        
        // simulate various accesses
        for (int i = 0; i < 10; ++i) {
            auto access_result = pool.simulate_access(alloc_result.value()->virtual_address);
            REQUIRE(access_result.has_value());
        }
        
        MemoryBlockVisualizer visualizer(pool);
        auto heatmap = visualizer.generate_access_pattern_heatmap();
        
        REQUIRE_FALSE(heatmap.empty());
        REQUIRE(heatmap.find("Access Pattern Heatmap") != std::string::npos);
        REQUIRE(heatmap.find("Total Accesses: 10") != std::string::npos);
    }
    
    SECTION("Allocation timeline") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // allocate blocks with delays to create timeline
        for (int i = 0; i < 3; ++i) {
            auto alloc_result = pool.allocate(64 + i * 32);
            REQUIRE(alloc_result.has_value());
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        
        MemoryBlockVisualizer visualizer(pool);
        auto timeline = visualizer.generate_allocation_timeline();
        
        REQUIRE_FALSE(timeline.empty());
        REQUIRE(timeline.find("Allocation Timeline") != std::string::npos);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Pool statistics collection", "[memory_pool][statistics]") {
    SECTION("Basic statistics tracking") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        PoolStatistics stats(pool);
        auto snapshot = stats.get_current_snapshot();
        
        REQUIRE(snapshot.total_size > 0);
        REQUIRE(snapshot.used_size == 0); // no allocations yet
        REQUIRE(snapshot.free_size == snapshot.total_size);
    }
    
    SECTION("Statistics monitoring") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        PoolStatistics stats(pool);
        stats.start_monitoring(std::chrono::milliseconds(10));
        
        // perform some operations
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        stats.stop_monitoring();
        
        auto snapshots = stats.get_snapshots();
        REQUIRE(snapshots.size() > 1); // should have collected multiple snapshots
        
        // snapshots should show progression
        REQUIRE(snapshots.front().used_size <= snapshots.back().used_size);
    }
    
    SECTION("Peak memory usage tracking") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        PoolStatistics stats(pool);
        stats.start_monitoring(std::chrono::milliseconds(5));
        
        // allocate increasing amounts
        std::vector<const MemoryBlock*> blocks;
        for (int i = 0; i < 5; ++i) {
            auto alloc_result = pool.allocate(64 + i * 32);
            REQUIRE(alloc_result.has_value());
            blocks.push_back(alloc_result.value());
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        stats.stop_monitoring();
        
        double peak_usage = stats.peak_memory_usage();
        REQUIRE(peak_usage > 0.0);
        REQUIRE(peak_usage <= 1.0);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Utility functions", "[memory_pool][utils]") {
    SECTION("Pool creation for different workloads") {
        std::vector<std::string> workload_types = {
            "default", "high_performance", "debug", "large_allocations", "fragmentation_test"
        };
        
        for (const auto& workload_type : workload_types) {
            auto pool = memory_pool_utils::create_pool_for_workload(context(), workload_type);
            REQUIRE(pool != nullptr);
            
            auto init_result = pool->initialize();
            REQUIRE(init_result.has_value());
            
            // test basic functionality
            auto alloc_result = pool->allocate(64);
            REQUIRE(alloc_result.has_value());
            
            auto dealloc_result = pool->deallocate(alloc_result.value()->virtual_address);
            REQUIRE(dealloc_result.has_value());
        }
    }
    
    SECTION("Pool correctness validation") {
        auto validation_result = memory_pool_utils::validate_pool_correctness(context());
        REQUIRE(validation_result.has_value());
    }
    
    SECTION("Pool benchmarking") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto benchmark_result = memory_pool_utils::benchmark_pool(pool, 100);
        REQUIRE(benchmark_result.has_value());
        
        const auto& results = benchmark_result.value();
        REQUIRE(results.allocations_per_second > 0);
        REQUIRE(results.deallocations_per_second > 0);
        REQUIRE(results.avg_allocation_latency.count() > 0);
        REQUIRE(results.avg_deallocation_latency.count() > 0);
        REQUIRE(results.peak_fragmentation >= 0.0);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Stress testing", "[memory_pool][stress]") {
    SECTION("Basic stress test") {
        auto config = PoolConfig::default_config();
        config.total_size = 1024 * 1024; // 1MB
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        auto stress_result = memory_pool_utils::stress_test_pool(
            pool, 2, std::chrono::seconds(1));
        REQUIRE(stress_result.has_value());
        
        // verify pool is still functional after stress test
        auto integrity_result = pool.validate_integrity();
        REQUIRE(integrity_result.has_value());
        
        const auto& final_stats = pool.access_statistics();
        REQUIRE(final_stats.total_accesses.load() > 0);
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Error handling", "[memory_pool][error_handling]") {
    SECTION("Operations on uninitialized pool") {
        auto pool = create_pool();
        REQUIRE_FALSE(pool.is_initialized());
        
        auto alloc_result = pool.allocate(64);
        REQUIRE_FALSE(alloc_result.has_value());
        
        auto size_result = pool.total_size();
        REQUIRE_FALSE(size_result.has_value());
    }
    
    SECTION("Double initialization") {
        auto pool = create_pool();
        
        auto init1 = pool.initialize();
        REQUIRE(init1.has_value());
        
        auto init2 = pool.initialize();
        REQUIRE_FALSE(init2.has_value());
    }
    
    SECTION("Invalid deallocation") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // try to deallocate address that was never allocated
        EncryptedAddress fake_addr(uintptr_t(0x12345678), context());
        auto dealloc_result = pool.deallocate(fake_addr);
        REQUIRE_FALSE(dealloc_result.has_value());
    }
    
    SECTION("Pool exhaustion") {
        auto config = PoolConfig::debug_config();
        config.total_size = 1024; // very small pool
        config.max_block_size = 512;
        auto pool = create_pool(config);
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // allocate until pool is exhausted
        std::vector<const MemoryBlock*> blocks;
        while (true) {
            auto alloc_result = pool.allocate(64);
            if (!alloc_result.has_value()) {
                break; // pool exhausted
            }
            blocks.push_back(alloc_result.value());
        }
        
        REQUIRE(blocks.size() > 0); // should have allocated at least one block
        
        // try one more allocation - should fail
        auto final_alloc = pool.allocate(64);
        REQUIRE_FALSE(final_alloc.has_value());
    }
}

TEST_CASE_METHOD(MemoryPoolTestFixture, "Pool status reporting", "[memory_pool][status]") {
    SECTION("Pool status string") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // allocate some blocks
        for (int i = 0; i < 3; ++i) {
            auto alloc_result = pool.allocate(64 + i * 32);
            REQUIRE(alloc_result.has_value());
        }
        
        auto status = pool.pool_status_string();
        REQUIRE_FALSE(status.empty());
        REQUIRE(status.find("Memory Pool Status") != std::string::npos);
        REQUIRE(status.find("Total Size") != std::string::npos);
        REQUIRE(status.find("Used Size") != std::string::npos);
        REQUIRE(status.find("Allocated Blocks: 3") != std::string::npos);
    }
    
    SECTION("Statistics reset") {
        auto pool = create_pool();
        auto init_result = pool.initialize();
        REQUIRE(init_result.has_value());
        
        // perform operations to generate statistics
        auto alloc_result = pool.allocate(64);
        REQUIRE(alloc_result.has_value());
        
        auto access_result = pool.simulate_access(alloc_result.value()->virtual_address);
        REQUIRE(access_result.has_value());
        
        const auto& stats_before = pool.access_statistics();
        REQUIRE(stats_before.total_accesses.load() > 0);
        
        // reset statistics
        pool.reset_statistics();
        
        const auto& stats_after = pool.access_statistics();
        REQUIRE(stats_after.total_accesses.load() == 0);
    }
}

// Benchmarks disabled for now to get basic tests working
/*
BENCHMARK("Memory pool allocation performance") {
    auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<BFVContext>(params);
    auto init_result = context->initialize();
    REQUIRE(init_result.has_value());
    
    VirtualMemoryPool pool(context, PoolConfig::performance_config());
    auto pool_init = pool.initialize();
    REQUIRE(pool_init.has_value());
    
    return [&pool] {
        auto result = pool.allocate(64);
        if (result.has_value()) {
            pool.deallocate(result.value()->virtual_address);
        }
    };
}

BENCHMARK("Memory access simulation performance") {
    auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<BFVContext>(params);
    auto init_result = context->initialize();
    REQUIRE(init_result.has_value());
    
    VirtualMemoryPool pool(context, PoolConfig::performance_config());
    auto pool_init = pool.initialize();
    REQUIRE(pool_init.has_value());
    
    auto alloc_result = pool.allocate(1024);
    REQUIRE(alloc_result.has_value());
    
    return [&pool, &alloc_result] {
        pool.simulate_access(alloc_result.value()->virtual_address);
    };
}
*/