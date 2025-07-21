/**
 * @file memory_pool.hpp
 * @brief virtual memory pool simulation with encrypted metadata tracking
 */

#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/encrypted_types.hpp"

namespace cryptmalloc {

// forward declarations
class VirtualMemoryPool;
class MemoryBlockVisualizer;
class PoolStatistics;

/**
 * @brief memory access pattern types for simulation
 */
enum class AccessPattern {
    SEQUENTIAL,      // linear memory access
    RANDOM,          // random access pattern
    LOCALITY,        // spatial locality with hotspots
    STRIDED,         // fixed stride access
    MIXED            // combination of patterns
};

/**
 * @brief memory hierarchy levels for latency simulation
 */
enum class MemoryLevel {
    L1_CACHE,        // ~1ns access time
    L2_CACHE,        // ~3ns access time  
    L3_CACHE,        // ~12ns access time
    RAM,             // ~100ns access time
    STORAGE          // ~10ms access time
};

/**
 * @brief memory alignment requirements
 */
enum class Alignment {
    BYTE_1 = 1,
    BYTE_8 = 8,
    BYTE_16 = 16,
    BYTE_32 = 32,
    BYTE_64 = 64,
    PAGE_4KB = 4096,
    PAGE_2MB = 2097152,
    PAGE_1GB = 1073741824
};

/**
 * @brief memory block metadata with encryption
 */
struct MemoryBlock {
    EncryptedAddress virtual_address;    // encrypted virtual address
    EncryptedSize size;                  // encrypted block size
    EncryptedSize alignment;             // encrypted alignment requirement
    std::chrono::steady_clock::time_point allocated_at;  // allocation timestamp
    std::thread::id owner_thread;       // owning thread id
    AccessPattern access_pattern;       // predicted access pattern
    std::atomic<uint64_t> access_count; // number of accesses
    std::atomic<bool> is_free;          // block status
    
    MemoryBlock(const EncryptedAddress& addr, const EncryptedSize& sz, 
                const EncryptedSize& align, AccessPattern pattern = AccessPattern::RANDOM);
    
    // explicitly delete copy operations because of atomics
    MemoryBlock(const MemoryBlock&) = delete;
    MemoryBlock& operator=(const MemoryBlock&) = delete;
    MemoryBlock(MemoryBlock&&) = delete;
    MemoryBlock& operator=(MemoryBlock&&) = delete;
};

/**
 * @brief pool configuration parameters
 */
struct PoolConfig {
    size_t total_size;                   // total pool size in bytes
    size_t min_block_size;              // minimum allocation size
    size_t max_block_size;              // maximum allocation size
    Alignment default_alignment;        // default alignment requirement
    bool enable_fragmentation_sim;      // enable fragmentation simulation
    bool enable_access_tracking;        // enable access pattern tracking
    double cache_hit_ratio;             // simulated cache hit ratio
    std::chrono::nanoseconds base_latency; // base memory access latency
    
    static PoolConfig default_config();
    static PoolConfig performance_config();
    static PoolConfig debug_config();
};

/**
 * @brief fragmentation analysis results
 */
struct FragmentationInfo {
    double external_fragmentation;      // external fragmentation percentage
    double internal_fragmentation;      // internal fragmentation percentage
    size_t largest_free_block;         // size of largest free block
    size_t total_free_space;           // total free space
    size_t free_block_count;           // number of free blocks
    std::vector<size_t> free_block_sizes; // sizes of all free blocks
};

/**
 * @brief memory access statistics
 */
struct AccessStats {
    std::atomic<uint64_t> total_accesses{0};
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    std::atomic<uint64_t> sequential_accesses{0};
    std::atomic<uint64_t> random_accesses{0};
    std::chrono::nanoseconds total_latency{0};
    std::chrono::nanoseconds avg_latency{0};
    
    // explicitly delete copy operations for atomics
    AccessStats() = default;
    AccessStats(const AccessStats&) = delete;
    AccessStats& operator=(const AccessStats&) = delete;
    AccessStats(AccessStats&&) = delete;
    AccessStats& operator=(AccessStats&&) = delete;
    
    void reset();
    double cache_hit_ratio() const;
    double sequential_ratio() const;
};

/**
 * @brief virtual memory pool with encrypted metadata
 */
class VirtualMemoryPool {
public:
    explicit VirtualMemoryPool(std::shared_ptr<BFVContext> context, 
                              const PoolConfig& config = PoolConfig::default_config());
    ~VirtualMemoryPool();

    // non-copyable, moveable
    VirtualMemoryPool(const VirtualMemoryPool&) = delete;
    VirtualMemoryPool& operator=(const VirtualMemoryPool&) = delete;
    VirtualMemoryPool(VirtualMemoryPool&&) noexcept;
    VirtualMemoryPool& operator=(VirtualMemoryPool&&) noexcept;

    // pool management
    Result<void> initialize();
    Result<void> shutdown();
    bool is_initialized() const;
    
    // memory allocation/deallocation
    Result<const MemoryBlock*> allocate(size_t size, Alignment alignment = Alignment::BYTE_8,
                                AccessPattern pattern = AccessPattern::RANDOM);
    Result<void> deallocate(const EncryptedAddress& address);
    Result<const MemoryBlock*> reallocate(const EncryptedAddress& address, size_t new_size);
    
    // memory access simulation
    Result<std::chrono::nanoseconds> simulate_access(const EncryptedAddress& address,
                                                    size_t access_size = 8,
                                                    AccessPattern pattern = AccessPattern::RANDOM);
    Result<void> prefetch(const EncryptedAddress& address, size_t size);
    
    // pool information
    PoolConfig config() const { return config_; }
    Result<EncryptedSize> total_size() const;
    Result<EncryptedSize> used_size() const;
    Result<EncryptedSize> free_size() const;
    Result<FragmentationInfo> fragmentation_info() const;
    
    // statistics and monitoring
    const AccessStats& access_statistics() const { return access_stats_; }
    void reset_statistics();
    Result<std::vector<const MemoryBlock*>> allocated_blocks() const;
    Result<std::vector<std::pair<size_t, size_t>>> free_regions() const;
    
    // debugging and visualization
    std::string pool_status_string() const;
    Result<void> validate_integrity() const;
    void enable_debug_mode(bool enabled) { debug_mode_ = enabled; }
    
    // thread safety
    void set_thread_safe(bool thread_safe) { thread_safe_ = thread_safe; }
    bool is_thread_safe() const { return thread_safe_; }
    
    // encryption helpers (public for friend classes)
    Result<uint64_t> decrypt_address(const EncryptedAddress& encrypted_addr) const;
    Result<size_t> decrypt_size(const EncryptedSize& encrypted_size) const;

private:
    // internal state
    std::shared_ptr<BFVContext> context_;
    PoolConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> debug_mode_{false};
    std::atomic<bool> thread_safe_{true};
    
    // encrypted pool metadata
    EncryptedSize total_pool_size_;
    EncryptedSize current_used_size_;
    EncryptedAddress base_address_;
    EncryptedAddress next_free_address_;
    
    // memory management
    std::unordered_map<uint64_t, std::unique_ptr<MemoryBlock>> allocated_blocks_;
    std::vector<std::pair<size_t, size_t>> free_regions_; // (offset, size) pairs
    std::atomic<uint64_t> next_virtual_address_{0x1000}; // start at 4KB to fit in plaintext modulus
    
    // synchronization
    mutable std::shared_mutex pool_mutex_;
    mutable std::mutex stats_mutex_;
    mutable std::mutex allocation_mutex_;
    
    // statistics
    mutable AccessStats access_stats_;
    std::atomic<uint64_t> allocation_count_{0};
    std::atomic<uint64_t> deallocation_count_{0};
    
    // memory access simulation
    std::random_device random_device_;
    mutable std::mt19937 random_generator_;
    mutable std::uniform_real_distribution<double> latency_distribution_;
    
    // internal methods
    Result<uint64_t> generate_virtual_address(size_t size, Alignment alignment);
    Result<void> update_fragmentation_info() const;
    MemoryLevel determine_memory_level(const EncryptedAddress& address) const;
    std::chrono::nanoseconds calculate_access_latency(MemoryLevel level, 
                                                     AccessPattern pattern) const;
    Result<void> verify_address_bounds(const EncryptedAddress& address) const;
    void log_debug_info(const std::string& message) const;
    
    // encryption helpers
    Result<EncryptedAddress> encrypt_address(uint64_t address) const;
    Result<EncryptedSize> encrypt_size(size_t size) const;
};

/**
 * @brief memory block visualization and debugging utilities
 */
class MemoryBlockVisualizer {
public:
    explicit MemoryBlockVisualizer(const VirtualMemoryPool& pool);
    
    // visualization methods
    std::string generate_memory_map(size_t width = 80) const;
    std::string generate_fragmentation_chart() const;
    std::string generate_access_pattern_heatmap() const;
    std::string generate_allocation_timeline() const;
    
    // export methods
    Result<void> export_memory_map_svg(const std::string& filename) const;
    Result<void> export_statistics_json(const std::string& filename) const;
    Result<void> export_allocation_trace(const std::string& filename) const;

private:
    const VirtualMemoryPool& pool_;
    
    std::string format_size(size_t size) const;
    std::string format_address(uint64_t address) const;
    char get_fragmentation_char(double fragmentation) const;
};

/**
 * @brief comprehensive pool statistics collector
 */
class PoolStatistics {
public:
    explicit PoolStatistics(const VirtualMemoryPool& pool);
    
    // statistics collection
    struct PoolSnapshot {
        std::chrono::steady_clock::time_point timestamp;
        size_t total_size;
        size_t used_size;
        size_t free_size;
        double fragmentation;
        size_t allocation_count;
        size_t deallocation_count;
        
        // simple stats instead of AccessStats to avoid atomic copy issues
        uint64_t total_accesses;
        uint64_t cache_hits;
        uint64_t cache_misses;
        uint64_t sequential_accesses;
        uint64_t random_accesses;
        std::chrono::nanoseconds total_latency;
        std::chrono::nanoseconds avg_latency;
    };
    
    void start_monitoring(std::chrono::milliseconds interval = std::chrono::milliseconds(100));
    void stop_monitoring();
    
    std::vector<PoolSnapshot> get_snapshots() const;
    PoolSnapshot get_current_snapshot() const;
    
    // analysis methods
    double peak_memory_usage() const;
    double average_fragmentation() const;
    std::chrono::nanoseconds peak_access_latency() const;
    size_t allocation_rate_per_second() const;

private:
    const VirtualMemoryPool& pool_;
    std::atomic<bool> monitoring_{false};
    std::thread monitoring_thread_;
    mutable std::mutex snapshots_mutex_;
    std::vector<PoolSnapshot> snapshots_;
    
    void monitoring_loop(std::chrono::milliseconds interval);
};

// utility functions
namespace memory_pool_utils {
    /**
     * @brief create a memory pool with recommended settings for the given use case
     */
    std::unique_ptr<VirtualMemoryPool> create_pool_for_workload(
        std::shared_ptr<BFVContext> context,
        const std::string& workload_type);
    
    /**
     * @brief run comprehensive memory pool stress test
     */
    Result<void> stress_test_pool(VirtualMemoryPool& pool, 
                                 size_t num_threads = 4,
                                 std::chrono::seconds duration = std::chrono::seconds(10));
    
    /**
     * @brief benchmark memory pool performance
     */
    struct BenchmarkResults {
        double allocations_per_second;
        double deallocations_per_second;
        std::chrono::nanoseconds avg_allocation_latency;
        std::chrono::nanoseconds avg_deallocation_latency;
        double peak_fragmentation;
    };
    
    Result<BenchmarkResults> benchmark_pool(VirtualMemoryPool& pool,
                                          size_t num_operations = 10000);
    
    /**
     * @brief validate pool correctness across different configurations
     */
    Result<void> validate_pool_correctness(std::shared_ptr<BFVContext> context);
}

} // namespace cryptmalloc