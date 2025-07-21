/**
 * @file memory_pool.cpp
 * @brief implementation of virtual memory pool simulation with encrypted metadata
 */

#include "cryptmalloc/memory_pool.hpp"
#include "cryptmalloc/bfv_operations.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace cryptmalloc {

// ========== MemoryBlock Implementation ==========

MemoryBlock::MemoryBlock(const EncryptedAddress& addr, const EncryptedSize& sz, 
                        const EncryptedSize& align, AccessPattern pattern)
    : virtual_address(addr), size(sz), alignment(align), 
      allocated_at(std::chrono::steady_clock::now()),
      owner_thread(std::this_thread::get_id()),
      access_pattern(pattern), access_count(0), is_free(false) {
}

// ========== PoolConfig Implementation ==========

PoolConfig PoolConfig::default_config() {
    return PoolConfig{
        .total_size = 64 * 1024 * 1024,  // 64MB
        .min_block_size = 8,
        .max_block_size = 1024 * 1024,   // 1MB
        .default_alignment = Alignment::BYTE_8,
        .enable_fragmentation_sim = true,
        .enable_access_tracking = true,
        .cache_hit_ratio = 0.85,
        .base_latency = std::chrono::nanoseconds(100)
    };
}

PoolConfig PoolConfig::performance_config() {
    return PoolConfig{
        .total_size = 256 * 1024 * 1024, // 256MB
        .min_block_size = 16,
        .max_block_size = 4 * 1024 * 1024, // 4MB
        .default_alignment = Alignment::BYTE_64,
        .enable_fragmentation_sim = false,
        .enable_access_tracking = false,
        .cache_hit_ratio = 0.95,
        .base_latency = std::chrono::nanoseconds(50)
    };
}

PoolConfig PoolConfig::debug_config() {
    return PoolConfig{
        .total_size = 16 * 1024,         // 16KB for testing (within address space)
        .min_block_size = 8,             // Minimum 8 bytes
        .max_block_size = 1024,
        .default_alignment = Alignment::BYTE_8,
        .enable_fragmentation_sim = true,
        .enable_access_tracking = true,
        .cache_hit_ratio = 0.5,
        .base_latency = std::chrono::nanoseconds(1000)
    };
}

// ========== AccessStats Implementation ==========

void AccessStats::reset() {
    total_accesses.store(0);
    cache_hits.store(0);
    cache_misses.store(0);
    sequential_accesses.store(0);
    random_accesses.store(0);
    total_latency = std::chrono::nanoseconds(0);
    avg_latency = std::chrono::nanoseconds(0);
}

double AccessStats::cache_hit_ratio() const {
    uint64_t total = total_accesses.load();
    return total > 0 ? static_cast<double>(cache_hits.load()) / total : 0.0;
}

double AccessStats::sequential_ratio() const {
    uint64_t total = total_accesses.load();
    return total > 0 ? static_cast<double>(sequential_accesses.load()) / total : 0.0;
}

// ========== VirtualMemoryPool Implementation ==========

VirtualMemoryPool::VirtualMemoryPool(std::shared_ptr<BFVContext> context, 
                                    const PoolConfig& config)
    : context_(std::move(context)), config_(config),
      total_pool_size_(EncryptedSize(0, context_)),
      current_used_size_(EncryptedSize(0, context_)),
      base_address_(EncryptedAddress(uintptr_t(0), context_)),
      next_free_address_(EncryptedAddress(uintptr_t(0), context_)),
      random_generator_(random_device_()),
      latency_distribution_(0.8, 1.2) {
    
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("Invalid or uninitialized BFV context");
    }
}

VirtualMemoryPool::~VirtualMemoryPool() {
    if (initialized_.load()) {
        shutdown();
    }
}

VirtualMemoryPool::VirtualMemoryPool(VirtualMemoryPool&& other) noexcept
    : context_(std::move(other.context_)),
      config_(std::move(other.config_)),
      initialized_(other.initialized_.load()),
      debug_mode_(other.debug_mode_.load()),
      thread_safe_(other.thread_safe_.load()),
      total_pool_size_(std::move(other.total_pool_size_)),
      current_used_size_(std::move(other.current_used_size_)),
      base_address_(std::move(other.base_address_)),
      next_free_address_(std::move(other.next_free_address_)),
      allocated_blocks_(std::move(other.allocated_blocks_)),
      free_regions_(std::move(other.free_regions_)),
      next_virtual_address_(other.next_virtual_address_.load()),
      // access_stats_ initialized by default constructor
      allocation_count_(other.allocation_count_.load()),
      deallocation_count_(other.deallocation_count_.load()),
      random_generator_(std::move(other.random_generator_)),
      latency_distribution_(std::move(other.latency_distribution_)) {
    
    other.initialized_.store(false);
}

VirtualMemoryPool& VirtualMemoryPool::operator=(VirtualMemoryPool&& other) noexcept {
    if (this != &other) {
        if (initialized_.load()) {
            shutdown();
        }
        
        context_ = std::move(other.context_);
        config_ = std::move(other.config_);
        initialized_.store(other.initialized_.load());
        debug_mode_.store(other.debug_mode_.load());
        thread_safe_.store(other.thread_safe_.load());
        total_pool_size_ = std::move(other.total_pool_size_);
        current_used_size_ = std::move(other.current_used_size_);
        base_address_ = std::move(other.base_address_);
        next_free_address_ = std::move(other.next_free_address_);
        allocated_blocks_ = std::move(other.allocated_blocks_);
        free_regions_ = std::move(other.free_regions_);
        next_virtual_address_.store(other.next_virtual_address_.load());
        // reset access_stats_ instead of copying atomics
        access_stats_.reset();
        allocation_count_.store(other.allocation_count_.load());
        deallocation_count_.store(other.deallocation_count_.load());
        random_generator_ = std::move(other.random_generator_);
        latency_distribution_ = std::move(other.latency_distribution_);
        
        other.initialized_.store(false);
    }
    return *this;
}

Result<void> VirtualMemoryPool::initialize() {
    std::unique_lock<std::shared_mutex> lock(pool_mutex_);
    
    if (initialized_.load()) {
        return Result<void>("Pool already initialized");
    }
    
    // encrypt initial pool metadata
    auto total_size_result = encrypt_size(config_.total_size);
    if (!total_size_result.has_value()) {
        return Result<void>("Failed to encrypt total pool size: " + total_size_result.error());
    }
    total_pool_size_ = total_size_result.value();
    
    auto zero_size_result = encrypt_size(0);
    if (!zero_size_result.has_value()) {
        return Result<void>("Failed to encrypt zero size: " + zero_size_result.error());
    }
    current_used_size_ = zero_size_result.value();
    
    // set up base address
    auto base_addr_result = encrypt_address(next_virtual_address_.load());
    if (!base_addr_result.has_value()) {
        return Result<void>("Failed to encrypt base address: " + base_addr_result.error());
    }
    base_address_ = base_addr_result.value();
    next_free_address_ = base_address_;
    
    // initialize free region list with entire pool
    free_regions_.clear();
    free_regions_.emplace_back(0, config_.total_size);
    
    // reset statistics
    access_stats_.reset();
    allocation_count_.store(0);
    deallocation_count_.store(0);
    
    initialized_.store(true);
    
    log_debug_info("Memory pool initialized with size: " + std::to_string(config_.total_size) + " bytes");
    
    return Result<void>::success();
}

Result<void> VirtualMemoryPool::shutdown() {
    std::unique_lock<std::shared_mutex> lock(pool_mutex_);
    
    if (!initialized_.load()) {
        return Result<void>("Pool not initialized");
    }
    
    // clean up allocated blocks
    allocated_blocks_.clear();
    free_regions_.clear();
    
    initialized_.store(false);
    
    log_debug_info("Memory pool shutdown completed");
    
    return Result<void>::success();
}

bool VirtualMemoryPool::is_initialized() const {
    return initialized_.load();
}

Result<const MemoryBlock*> VirtualMemoryPool::allocate(size_t size, Alignment alignment, 
                                               AccessPattern pattern) {
    if (!initialized_.load()) {
        return Result<const MemoryBlock*>("Pool not initialized");
    }
    
    if (size < config_.min_block_size || size > config_.max_block_size) {
        return Result<const MemoryBlock*>("Size " + std::to_string(size) + 
                                  " outside allowed range [" + std::to_string(config_.min_block_size) +
                                  ", " + std::to_string(config_.max_block_size) + "]");
    }
    
    std::unique_lock<std::mutex> alloc_lock(allocation_mutex_);
    
    // find suitable free region
    size_t aligned_size = size;
    size_t align_val = static_cast<size_t>(alignment);
    if (align_val > 1) {
        aligned_size = (size + align_val - 1) & ~(align_val - 1);
    }
    
    auto free_it = std::find_if(free_regions_.begin(), free_regions_.end(),
        [aligned_size](const auto& region) { return region.second >= aligned_size; });
    
    if (free_it == free_regions_.end()) {
        return Result<const MemoryBlock*>("No suitable free region found for size " + std::to_string(size));
    }
    
    // allocate from the found region
    size_t region_offset = free_it->first;
    size_t region_size = free_it->second;
    
    // generate virtual address
    auto addr_result = generate_virtual_address(aligned_size, alignment);
    if (!addr_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to generate virtual address: " + addr_result.error());
    }
    
    // create encrypted metadata
    auto enc_addr_result = encrypt_address(addr_result.value());
    if (!enc_addr_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to encrypt address: " + enc_addr_result.error());
    }
    
    auto enc_size_result = encrypt_size(size);
    if (!enc_size_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to encrypt size: " + enc_size_result.error());
    }
    
    auto enc_align_result = encrypt_size(static_cast<size_t>(alignment));
    if (!enc_align_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to encrypt alignment: " + enc_align_result.error());
    }
    
    // create memory block
    auto block = std::make_unique<MemoryBlock>(enc_addr_result.value(), 
                                              enc_size_result.value(),
                                              enc_align_result.value(), 
                                              pattern);
    
    // update free regions
    if (region_size > aligned_size) {
        // split region
        free_it->first = region_offset + aligned_size;
        free_it->second = region_size - aligned_size;
    } else {
        // use entire region
        free_regions_.erase(free_it);
    }
    
    // update used size
    auto current_used = decrypt_size(current_used_size_);
    if (!current_used.has_value()) {
        return Result<const MemoryBlock*>("Failed to decrypt current used size");
    }
    
    auto new_used_result = encrypt_size(current_used.value() + aligned_size);
    if (!new_used_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to encrypt new used size");
    }
    current_used_size_ = new_used_result.value();
    
    // store block
    uint64_t addr_key = addr_result.value();
    const MemoryBlock* result_ptr = block.get();
    allocated_blocks_[addr_key] = std::move(block);
    
    allocation_count_.fetch_add(1);
    
    log_debug_info("Allocated block: addr=" + std::to_string(addr_key) + 
                   ", size=" + std::to_string(size) + 
                   ", alignment=" + std::to_string(static_cast<size_t>(alignment)));
    
    return Result<const MemoryBlock*>(result_ptr);
}

Result<void> VirtualMemoryPool::deallocate(const EncryptedAddress& address) {
    if (!initialized_.load()) {
        return Result<void>("Pool not initialized");
    }
    
    auto addr_result = decrypt_address(address);
    if (!addr_result.has_value()) {
        return Result<void>("Failed to decrypt address: " + addr_result.error());
    }
    
    std::unique_lock<std::mutex> alloc_lock(allocation_mutex_);
    
    uint64_t addr_key = addr_result.value();
    auto block_it = allocated_blocks_.find(addr_key);
    if (block_it == allocated_blocks_.end()) {
        return Result<void>("Address not found in allocated blocks");
    }
    
    // get block size for free region update
    auto size_result = decrypt_size(block_it->second->size);
    if (!size_result.has_value()) {
        return Result<void>("Failed to decrypt block size: " + size_result.error());
    }
    
    size_t block_size = size_result.value();
    
    // update used size
    auto current_used = decrypt_size(current_used_size_);
    if (!current_used.has_value()) {
        return Result<void>("Failed to decrypt current used size");
    }
    
    auto new_used_result = encrypt_size(current_used.value() - block_size);
    if (!new_used_result.has_value()) {
        return Result<void>("Failed to encrypt new used size");
    }
    current_used_size_ = new_used_result.value();
    
    // add back to free regions (simplified - would need merging in real implementation)
    free_regions_.emplace_back(addr_key - next_virtual_address_.load(), block_size);
    
    // remove from allocated blocks
    allocated_blocks_.erase(block_it);
    
    deallocation_count_.fetch_add(1);
    
    log_debug_info("Deallocated block: addr=" + std::to_string(addr_key) + 
                   ", size=" + std::to_string(block_size));
    
    return Result<void>::success();
}

Result<const MemoryBlock*> VirtualMemoryPool::reallocate(const EncryptedAddress& address, size_t new_size) {
    if (!initialized_.load()) {
        return Result<const MemoryBlock*>("Pool not initialized");
    }
    
    auto addr_result = decrypt_address(address);
    if (!addr_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to decrypt address: " + addr_result.error());
    }
    
    std::unique_lock<std::mutex> alloc_lock(allocation_mutex_);
    
    uint64_t addr_key = addr_result.value();
    auto block_it = allocated_blocks_.find(addr_key);
    if (block_it == allocated_blocks_.end()) {
        return Result<const MemoryBlock*>("Address not found in allocated blocks");
    }
    
    // get current block info
    auto current_size = decrypt_size(block_it->second->size);
    if (!current_size.has_value()) {
        return Result<const MemoryBlock*>("Failed to decrypt current size");
    }
    
    auto current_align = decrypt_size(block_it->second->alignment);
    if (!current_align.has_value()) {
        return Result<const MemoryBlock*>("Failed to decrypt current alignment");
    }
    
    AccessPattern pattern = block_it->second->access_pattern;
    
    // deallocate current block
    auto dealloc_result = deallocate(address);
    if (!dealloc_result.has_value()) {
        return Result<const MemoryBlock*>("Failed to deallocate current block: " + dealloc_result.error());
    }
    
    // allocate new block
    return allocate(new_size, static_cast<Alignment>(current_align.value()), pattern);
}

Result<std::chrono::nanoseconds> VirtualMemoryPool::simulate_access(const EncryptedAddress& address,
                                                                   size_t access_size,
                                                                   AccessPattern pattern) {
    if (!initialized_.load()) {
        return Result<std::chrono::nanoseconds>("Pool not initialized");
    }
    
    if (!config_.enable_access_tracking) {
        return Result<std::chrono::nanoseconds>(config_.base_latency);
    }
    
    auto addr_result = decrypt_address(address);
    if (!addr_result.has_value()) {
        return Result<std::chrono::nanoseconds>("Failed to decrypt address: " + addr_result.error());
    }
    
    // determine memory level based on access pattern and cache simulation
    MemoryLevel level = determine_memory_level(address);
    
    // calculate latency
    auto latency = calculate_access_latency(level, pattern);
    
    // update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        access_stats_.total_accesses.fetch_add(1);
        
        if (level == MemoryLevel::L1_CACHE || level == MemoryLevel::L2_CACHE || level == MemoryLevel::L3_CACHE) {
            access_stats_.cache_hits.fetch_add(1);
        } else {
            access_stats_.cache_misses.fetch_add(1);
        }
        
        if (pattern == AccessPattern::SEQUENTIAL) {
            access_stats_.sequential_accesses.fetch_add(1);
        } else {
            access_stats_.random_accesses.fetch_add(1);
        }
        
        access_stats_.total_latency += latency;
        
        uint64_t total_accesses = access_stats_.total_accesses.load();
        access_stats_.avg_latency = access_stats_.total_latency / total_accesses;
    }
    
    // update block access count
    uint64_t addr_key = addr_result.value();
    auto block_it = allocated_blocks_.find(addr_key);
    if (block_it != allocated_blocks_.end()) {
        block_it->second->access_count.fetch_add(1);
    }
    
    return Result<std::chrono::nanoseconds>(latency);
}

Result<void> VirtualMemoryPool::prefetch(const EncryptedAddress& address, size_t size) {
    if (!initialized_.load()) {
        return Result<void>("Pool not initialized");
    }
    
    // simulate prefetch by adjusting cache hit probability
    log_debug_info("Prefetching " + std::to_string(size) + " bytes");
    
    return Result<void>::success();
}

Result<EncryptedSize> VirtualMemoryPool::total_size() const {
    if (!initialized_.load()) {
        return Result<EncryptedSize>("Pool not initialized");
    }
    
    return Result<EncryptedSize>(total_pool_size_);
}

Result<EncryptedSize> VirtualMemoryPool::used_size() const {
    if (!initialized_.load()) {
        return Result<EncryptedSize>("Pool not initialized");
    }
    
    return Result<EncryptedSize>(current_used_size_);
}

Result<EncryptedSize> VirtualMemoryPool::free_size() const {
    if (!initialized_.load()) {
        return Result<EncryptedSize>("Pool not initialized");
    }
    
    auto total = decrypt_size(total_pool_size_);
    auto used = decrypt_size(current_used_size_);
    
    if (!total.has_value() || !used.has_value()) {
        return Result<EncryptedSize>("Failed to decrypt sizes");
    }
    
    return encrypt_size(total.value() - used.value());
}

Result<FragmentationInfo> VirtualMemoryPool::fragmentation_info() const {
    if (!initialized_.load()) {
        return Result<FragmentationInfo>("Pool not initialized");
    }
    
    std::shared_lock<std::shared_mutex> lock(pool_mutex_);
    
    FragmentationInfo info;
    info.free_block_count = free_regions_.size();
    info.total_free_space = 0;
    info.largest_free_block = 0;
    
    for (const auto& region : free_regions_) {
        info.total_free_space += region.second;
        info.largest_free_block = std::max(info.largest_free_block, region.second);
        info.free_block_sizes.push_back(region.second);
    }
    
    // calculate fragmentation metrics
    if (info.total_free_space > 0) {
        info.external_fragmentation = info.free_block_count > 1 ? 
            (1.0 - static_cast<double>(info.largest_free_block) / info.total_free_space) * 100.0 : 0.0;
    } else {
        info.external_fragmentation = 0.0;
    }
    
    // internal fragmentation calculation would require tracking actual vs requested sizes
    info.internal_fragmentation = 5.0; // simplified estimate
    
    return Result<FragmentationInfo>(info);
}

void VirtualMemoryPool::reset_statistics() {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    access_stats_.reset();
    allocation_count_.store(0);
    deallocation_count_.store(0);
}

Result<std::vector<const MemoryBlock*>> VirtualMemoryPool::allocated_blocks() const {
    if (!initialized_.load()) {
        return Result<std::vector<const MemoryBlock*>>("Pool not initialized");
    }
    
    std::shared_lock<std::shared_mutex> lock(pool_mutex_);
    
    std::vector<const MemoryBlock*> blocks;
    blocks.reserve(allocated_blocks_.size());
    
    for (const auto& [addr, block_ptr] : allocated_blocks_) {
        blocks.push_back(block_ptr.get());
    }
    
    return Result<std::vector<const MemoryBlock*>>(std::move(blocks));
}

Result<std::vector<std::pair<size_t, size_t>>> VirtualMemoryPool::free_regions() const {
    if (!initialized_.load()) {
        return Result<std::vector<std::pair<size_t, size_t>>>("Pool not initialized");
    }
    
    std::shared_lock<std::shared_mutex> lock(pool_mutex_);
    
    return Result<std::vector<std::pair<size_t, size_t>>>(free_regions_);
}

std::string VirtualMemoryPool::pool_status_string() const {
    if (!initialized_.load()) {
        return "Pool not initialized";
    }
    
    std::ostringstream oss;
    
    auto total = decrypt_size(total_pool_size_);
    auto used = decrypt_size(current_used_size_);
    
    if (total.has_value() && used.has_value()) {
        double utilization = total.value() > 0 ? 
            static_cast<double>(used.value()) / total.value() * 100.0 : 0.0;
        
        oss << "Memory Pool Status:\n";
        oss << "  Total Size: " << total.value() << " bytes\n";
        oss << "  Used Size: " << used.value() << " bytes\n";
        oss << "  Free Size: " << (total.value() - used.value()) << " bytes\n";
        oss << "  Utilization: " << std::fixed << std::setprecision(1) << utilization << "%\n";
        oss << "  Allocated Blocks: " << allocated_blocks_.size() << "\n";
        oss << "  Free Regions: " << free_regions_.size() << "\n";
        oss << "  Allocations: " << allocation_count_.load() << "\n";
        oss << "  Deallocations: " << deallocation_count_.load() << "\n";
        oss << "  Cache Hit Ratio: " << std::fixed << std::setprecision(2) 
            << access_stats_.cache_hit_ratio() * 100.0 << "%\n";
    } else {
        oss << "Pool status unavailable (encryption error)";
    }
    
    return oss.str();
}

Result<void> VirtualMemoryPool::validate_integrity() const {
    if (!initialized_.load()) {
        return Result<void>("Pool not initialized");
    }
    
    std::shared_lock<std::shared_mutex> lock(pool_mutex_);
    
    // validate that all encrypted values can be decrypted
    auto total_check = decrypt_size(total_pool_size_);
    if (!total_check.has_value()) {
        return Result<void>("Failed to decrypt total pool size");
    }
    
    auto used_check = decrypt_size(current_used_size_);
    if (!used_check.has_value()) {
        return Result<void>("Failed to decrypt current used size");
    }
    
    auto base_addr_check = decrypt_address(base_address_);
    if (!base_addr_check.has_value()) {
        return Result<void>("Failed to decrypt base address");
    }
    
    // validate block consistency
    size_t calculated_used = 0;
    for (const auto& [addr, block_ptr] : allocated_blocks_) {
        auto block_size = decrypt_size(block_ptr->size);
        if (!block_size.has_value()) {
            return Result<void>("Failed to decrypt block size");
        }
        calculated_used += block_size.value();
        
        auto block_addr = decrypt_address(block_ptr->virtual_address);
        if (!block_addr.has_value()) {
            return Result<void>("Failed to decrypt block address");
        }
        
        if (block_addr.value() != addr) {
            return Result<void>("Block address mismatch");
        }
    }
    
    if (calculated_used != used_check.value()) {
        return Result<void>("Used size mismatch: calculated=" + std::to_string(calculated_used) +
                           ", stored=" + std::to_string(used_check.value()));
    }
    
    return Result<void>::success();
}

// ========== Private Methods ==========

Result<uint64_t> VirtualMemoryPool::generate_virtual_address(size_t size, Alignment alignment) {
    uint64_t addr = next_virtual_address_.fetch_add(size);
    
    // keep addresses within reasonable bounds for encryption (max ~30K to be safe)
    const uint64_t MAX_VIRTUAL_ADDR = 30000;
    if (addr > MAX_VIRTUAL_ADDR) {
        // wrap around to beginning of address space
        next_virtual_address_.store(0x1000);
        addr = next_virtual_address_.fetch_add(size);
    }
    
    // apply alignment
    size_t align_val = static_cast<size_t>(alignment);
    if (align_val > 1) {
        addr = (addr + align_val - 1) & ~(align_val - 1);
    }
    
    // check bounds
    auto base_addr = decrypt_address(base_address_);
    if (!base_addr.has_value()) {
        return Result<uint64_t>("Failed to decrypt base address");
    }
    
    if (addr + size > base_addr.value() + config_.total_size) {
        return Result<uint64_t>("Address would exceed pool bounds");
    }
    
    return Result<uint64_t>(addr);
}

Result<void> VirtualMemoryPool::update_fragmentation_info() const {
    // implementation would update internal fragmentation metrics
    return Result<void>::success();
}

MemoryLevel VirtualMemoryPool::determine_memory_level(const EncryptedAddress& address) const {
    // simulate cache behavior based on configured hit ratio
    double random_val = latency_distribution_(random_generator_);
    
    if (random_val < config_.cache_hit_ratio * 0.6) {
        return MemoryLevel::L1_CACHE;
    } else if (random_val < config_.cache_hit_ratio * 0.8) {
        return MemoryLevel::L2_CACHE;
    } else if (random_val < config_.cache_hit_ratio) {
        return MemoryLevel::L3_CACHE;
    } else {
        return MemoryLevel::RAM;
    }
}

std::chrono::nanoseconds VirtualMemoryPool::calculate_access_latency(MemoryLevel level, 
                                                                    AccessPattern pattern) const {
    std::chrono::nanoseconds base_latency;
    
    switch (level) {
        case MemoryLevel::L1_CACHE:
            base_latency = std::chrono::nanoseconds(1);
            break;
        case MemoryLevel::L2_CACHE:
            base_latency = std::chrono::nanoseconds(3);
            break;
        case MemoryLevel::L3_CACHE:
            base_latency = std::chrono::nanoseconds(12);
            break;
        case MemoryLevel::RAM:
            base_latency = config_.base_latency;
            break;
        case MemoryLevel::STORAGE:
            base_latency = std::chrono::nanoseconds(10000000); // 10ms
            break;
    }
    
    // adjust for access pattern
    double pattern_multiplier = 1.0;
    switch (pattern) {
        case AccessPattern::SEQUENTIAL:
            pattern_multiplier = 0.8; // faster due to prefetching
            break;
        case AccessPattern::RANDOM:
            pattern_multiplier = 1.2; // slower due to cache misses
            break;
        case AccessPattern::LOCALITY:
            pattern_multiplier = 0.9; // good cache utilization
            break;
        case AccessPattern::STRIDED:
            pattern_multiplier = 1.1; // predictable but not sequential
            break;
        case AccessPattern::MIXED:
            pattern_multiplier = 1.0; // average case
            break;
    }
    
    // add some random variation
    double variation = latency_distribution_(random_generator_);
    
    auto final_latency = std::chrono::nanoseconds(
        static_cast<long>(base_latency.count() * pattern_multiplier * variation));
    
    return final_latency;
}

Result<void> VirtualMemoryPool::verify_address_bounds(const EncryptedAddress& address) const {
    auto addr_result = decrypt_address(address);
    if (!addr_result.has_value()) {
        return Result<void>("Failed to decrypt address: " + addr_result.error());
    }
    
    auto base_addr = decrypt_address(base_address_);
    if (!base_addr.has_value()) {
        return Result<void>("Failed to decrypt base address");
    }
    
    uint64_t addr = addr_result.value();
    uint64_t base = base_addr.value();
    
    if (addr < base || addr >= base + config_.total_size) {
        return Result<void>("Address " + std::to_string(addr) + " outside pool bounds [" +
                           std::to_string(base) + ", " + std::to_string(base + config_.total_size) + ")");
    }
    
    return Result<void>::success();
}

void VirtualMemoryPool::log_debug_info(const std::string& message) const {
    if (debug_mode_.load()) {
        std::cout << "[MemoryPool DEBUG] " << message << std::endl;
    }
}

Result<EncryptedAddress> VirtualMemoryPool::encrypt_address(uint64_t address) const {
    try {
        return Result<EncryptedAddress>(EncryptedAddress(uintptr_t(address), context_));
    } catch (const std::exception& e) {
        return Result<EncryptedAddress>("Failed to encrypt address: " + std::string(e.what()));
    }
}

Result<EncryptedSize> VirtualMemoryPool::encrypt_size(size_t size) const {
    try {
        return Result<EncryptedSize>(EncryptedSize(static_cast<int64_t>(size), context_));
    } catch (const std::exception& e) {
        return Result<EncryptedSize>("Failed to encrypt size: " + std::string(e.what()));
    }
}

Result<uint64_t> VirtualMemoryPool::decrypt_address(const EncryptedAddress& encrypted_addr) const {
    auto result = encrypted_addr.decrypt();
    if (!result.has_value()) {
        return Result<uint64_t>("Failed to decrypt address: " + result.error());
    }
    return Result<uint64_t>(static_cast<uint64_t>(result.value()));
}

Result<size_t> VirtualMemoryPool::decrypt_size(const EncryptedSize& encrypted_size) const {
    auto result = encrypted_size.decrypt();
    if (!result.has_value()) {
        return Result<size_t>("Failed to decrypt size: " + result.error());
    }
    return Result<size_t>(static_cast<size_t>(result.value()));
}

// ========== MemoryBlockVisualizer Implementation ==========

MemoryBlockVisualizer::MemoryBlockVisualizer(const VirtualMemoryPool& pool)
    : pool_(pool) {
}

std::string MemoryBlockVisualizer::generate_memory_map(size_t width) const {
    if (!pool_.is_initialized()) {
        return "Pool not initialized";
    }
    
    std::ostringstream oss;
    
    auto total_size_result = pool_.total_size();
    if (!total_size_result.has_value()) {
        return "Failed to get pool size";
    }
    
    auto allocated_blocks_result = pool_.allocated_blocks();
    if (!allocated_blocks_result.has_value()) {
        return "Failed to get allocated blocks";
    }
    
    auto free_regions_result = pool_.free_regions();
    if (!free_regions_result.has_value()) {
        return "Failed to get free regions";
    }
    
    oss << "Memory Pool Layout (" << width << " chars wide)\n";
    oss << std::string(width + 2, '=') << "\n";
    
    // create visualization grid
    std::vector<char> grid(width, '.');
    
    const auto& blocks = allocated_blocks_result.value();
    const auto& free_regions = free_regions_result.value();
    
    // mark allocated blocks
    for (const auto& block : blocks) {
        auto addr_result = pool_.decrypt_address(block->virtual_address);
        auto size_result = pool_.decrypt_size(block->size);
        
        if (addr_result.has_value() && size_result.has_value()) {
            // simplified mapping to grid (using 32K address space)
            size_t start_pos = (addr_result.value() % 32768) * width / 32768;
            size_t block_width = std::max(1UL, size_result.value() * width / 32768);
            
            for (size_t i = start_pos; i < std::min(start_pos + block_width, width); ++i) {
                grid[i] = '#';
            }
        }
    }
    
    // mark free regions
    for (const auto& region : free_regions) {
        size_t start_pos = region.first * width / 32768;
        size_t region_width = std::max(1UL, region.second * width / 32768);
        
        for (size_t i = start_pos; i < std::min(start_pos + region_width, width); ++i) {
            if (grid[i] == '.') {
                grid[i] = '-';
            }
        }
    }
    
    // output grid
    oss << "|";
    for (char c : grid) {
        oss << c;
    }
    oss << "|\n";
    
    oss << std::string(width + 2, '=') << "\n";
    oss << "Legend: # = allocated, - = free, . = untracked\n";
    
    return oss.str();
}

std::string MemoryBlockVisualizer::generate_fragmentation_chart() const {
    auto frag_info_result = pool_.fragmentation_info();
    if (!frag_info_result.has_value()) {
        return "Failed to get fragmentation info";
    }
    
    const auto& info = frag_info_result.value();
    
    std::ostringstream oss;
    oss << "Fragmentation Analysis\n";
    oss << "=====================\n";
    oss << "External Fragmentation: " << std::fixed << std::setprecision(1) 
        << info.external_fragmentation << "%\n";
    oss << "Internal Fragmentation: " << std::fixed << std::setprecision(1) 
        << info.internal_fragmentation << "%\n";
    oss << "Free Blocks: " << info.free_block_count << "\n";
    oss << "Total Free Space: " << format_size(info.total_free_space) << "\n";
    oss << "Largest Free Block: " << format_size(info.largest_free_block) << "\n";
    
    if (!info.free_block_sizes.empty()) {
        oss << "\nFree Block Size Distribution:\n";
        std::map<size_t, size_t> size_histogram;
        
        for (size_t size : info.free_block_sizes) {
            // group into size categories
            size_t category = 1;
            while (category < size) category *= 2;
            size_histogram[category]++;
        }
        
        for (const auto& [size, count] : size_histogram) {
            oss << "  " << format_size(size/2) << "-" << format_size(size) << ": " 
                << count << " blocks " << std::string(count, '*') << "\n";
        }
    }
    
    return oss.str();
}

std::string MemoryBlockVisualizer::generate_access_pattern_heatmap() const {
    const auto& stats = pool_.access_statistics();
    
    std::ostringstream oss;
    oss << "Access Pattern Heatmap\n";
    oss << "======================\n";
    oss << "Total Accesses: " << stats.total_accesses.load() << "\n";
    oss << "Cache Hit Ratio: " << std::fixed << std::setprecision(1) 
        << stats.cache_hit_ratio() * 100.0 << "%\n";
    oss << "Sequential Ratio: " << std::fixed << std::setprecision(1) 
        << stats.sequential_ratio() * 100.0 << "%\n";
    oss << "Average Latency: " << stats.avg_latency.count() << "ns\n";
    
    // simple heatmap representation
    const size_t heatmap_width = 60;
    const size_t heatmap_height = 10;
    
    oss << "\nAccess Heatmap (simplified):\n";
    for (size_t row = 0; row < heatmap_height; ++row) {
        oss << "|";
        for (size_t col = 0; col < heatmap_width; ++col) {
            // simulate access density (would be based on actual data)
            double density = static_cast<double>(row * col) / (heatmap_width * heatmap_height);
            char heat_char = density > 0.8 ? '#' : density > 0.6 ? '+' : density > 0.4 ? 'o' : density > 0.2 ? '.' : ' ';
            oss << heat_char;
        }
        oss << "|\n";
    }
    
    return oss.str();
}

std::string MemoryBlockVisualizer::generate_allocation_timeline() const {
    std::ostringstream oss;
    oss << "Allocation Timeline\n";
    oss << "==================\n";
    
    auto allocated_blocks_result = pool_.allocated_blocks();
    if (!allocated_blocks_result.has_value()) {
        return "Failed to get allocated blocks";
    }
    
    const auto& blocks = allocated_blocks_result.value();
    
    // sort blocks by allocation time
    std::vector<const MemoryBlock*> sorted_blocks;
    for (const auto& block : blocks) {
        sorted_blocks.push_back(block);
    }
    
    std::sort(sorted_blocks.begin(), sorted_blocks.end(),
        [](const MemoryBlock* a, const MemoryBlock* b) {
            return a->allocated_at < b->allocated_at;
        });
    
    auto start_time = sorted_blocks.empty() ? std::chrono::steady_clock::now() : sorted_blocks[0]->allocated_at;
    
    for (size_t i = 0; i < std::min(sorted_blocks.size(), 20UL); ++i) {
        const auto* block = sorted_blocks[i];
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            block->allocated_at - start_time).count();
        
        auto size_result = pool_.decrypt_size(block->size);
        std::string size_str = size_result.has_value() ? format_size(size_result.value()) : "?";
        
        oss << std::setw(6) << duration << "ms: Allocated " << size_str 
            << " (accesses: " << block->access_count.load() << ")\n";
    }
    
    if (sorted_blocks.size() > 20) {
        oss << "... and " << (sorted_blocks.size() - 20) << " more blocks\n";
    }
    
    return oss.str();
}

Result<void> MemoryBlockVisualizer::export_memory_map_svg(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return Result<void>("Failed to open file: " + filename);
    }
    
    // simple SVG export
    file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    file << "<svg width=\"800\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\">\n";
    file << "<rect width=\"800\" height=\"200\" fill=\"lightgray\"/>\n";
    
    auto allocated_blocks_result = pool_.allocated_blocks();
    if (allocated_blocks_result.has_value()) {
        const auto& blocks = allocated_blocks_result.value();
        
        for (const auto& block : blocks) {
            auto addr_result = pool_.decrypt_address(block->virtual_address);
            auto size_result = pool_.decrypt_size(block->size);
            
            if (addr_result.has_value() && size_result.has_value()) {
                double x = (addr_result.value() % 32768) * 800.0 / 32768.0;
                double width = std::max(1.0, size_result.value() * 800.0 / 32768.0);
                
                file << "<rect x=\"" << x << "\" y=\"50\" width=\"" << width 
                     << "\" height=\"100\" fill=\"blue\" opacity=\"0.7\"/>\n";
            }
        }
    }
    
    file << "</svg>\n";
    file.close();
    
    return Result<void>::success();
}

Result<void> MemoryBlockVisualizer::export_statistics_json(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return Result<void>("Failed to open file: " + filename);
    }
    
    const auto& stats = pool_.access_statistics();
    
    file << "{\n";
    file << "  \"total_accesses\": " << stats.total_accesses.load() << ",\n";
    file << "  \"cache_hits\": " << stats.cache_hits.load() << ",\n";
    file << "  \"cache_misses\": " << stats.cache_misses.load() << ",\n";
    file << "  \"cache_hit_ratio\": " << stats.cache_hit_ratio() << ",\n";
    file << "  \"sequential_accesses\": " << stats.sequential_accesses.load() << ",\n";
    file << "  \"random_accesses\": " << stats.random_accesses.load() << ",\n";
    file << "  \"sequential_ratio\": " << stats.sequential_ratio() << ",\n";
    file << "  \"avg_latency_ns\": " << stats.avg_latency.count() << "\n";
    file << "}\n";
    
    file.close();
    
    return Result<void>::success();
}

Result<void> MemoryBlockVisualizer::export_allocation_trace(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return Result<void>("Failed to open file: " + filename);
    }
    
    auto allocated_blocks_result = pool_.allocated_blocks();
    if (!allocated_blocks_result.has_value()) {
        return Result<void>("Failed to get allocated blocks");
    }
    
    file << "timestamp_ms,address,size,alignment,access_count,thread_id\n";
    
    const auto& blocks = allocated_blocks_result.value();
    auto start_time = std::chrono::steady_clock::now();
    
    for (const auto& block : blocks) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            block->allocated_at - start_time).count();
        
        auto addr_result = pool_.decrypt_address(block->virtual_address);
        auto size_result = pool_.decrypt_size(block->size);
        auto align_result = pool_.decrypt_size(block->alignment);
        
        if (addr_result.has_value() && size_result.has_value() && align_result.has_value()) {
            file << duration_ms << "," << addr_result.value() << "," << size_result.value() 
                 << "," << align_result.value() << "," << block->access_count.load() 
                 << "," << std::hash<std::thread::id>{}(block->owner_thread) << "\n";
        }
    }
    
    file.close();
    
    return Result<void>::success();
}

std::string MemoryBlockVisualizer::format_size(size_t size) const {
    const char* units[] = {"B", "KB", "MB", "GB"};
    size_t unit_index = 0;
    double display_size = static_cast<double>(size);
    
    while (display_size >= 1024.0 && unit_index < 3) {
        display_size /= 1024.0;
        unit_index++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << display_size << units[unit_index];
    return oss.str();
}

std::string MemoryBlockVisualizer::format_address(uint64_t address) const {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << address;
    return oss.str();
}

char MemoryBlockVisualizer::get_fragmentation_char(double fragmentation) const {
    if (fragmentation < 10.0) return '.';
    if (fragmentation < 25.0) return 'o';
    if (fragmentation < 50.0) return '+';
    if (fragmentation < 75.0) return '*';
    return '#';
}

// ========== PoolStatistics Implementation ==========

PoolStatistics::PoolStatistics(const VirtualMemoryPool& pool)
    : pool_(pool) {
}

void PoolStatistics::start_monitoring(std::chrono::milliseconds interval) {
    if (monitoring_.load()) {
        return; // already monitoring
    }
    
    monitoring_.store(true);
    monitoring_thread_ = std::thread(&PoolStatistics::monitoring_loop, this, interval);
}

void PoolStatistics::stop_monitoring() {
    if (!monitoring_.load()) {
        return; // not monitoring
    }
    
    monitoring_.store(false);
    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }
}

std::vector<PoolStatistics::PoolSnapshot> PoolStatistics::get_snapshots() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    return snapshots_;
}

PoolStatistics::PoolSnapshot PoolStatistics::get_current_snapshot() const {
    PoolSnapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    
    auto total_size_result = pool_.total_size();
    auto used_size_result = pool_.used_size();
    auto frag_info_result = pool_.fragmentation_info();
    
    if (total_size_result.has_value()) {
        auto total_decrypted = pool_.decrypt_size(total_size_result.value());
        snapshot.total_size = total_decrypted.has_value() ? total_decrypted.value() : 0;
    }
    
    if (used_size_result.has_value()) {
        auto used_decrypted = pool_.decrypt_size(used_size_result.value());
        snapshot.used_size = used_decrypted.has_value() ? used_decrypted.value() : 0;
    }
    
    snapshot.free_size = snapshot.total_size - snapshot.used_size;
    
    if (frag_info_result.has_value()) {
        snapshot.fragmentation = frag_info_result.value().external_fragmentation;
    }
    
    // copy access statistics atomically
    const auto& access_stats = pool_.access_statistics();
    snapshot.total_accesses = access_stats.total_accesses.load();
    snapshot.cache_hits = access_stats.cache_hits.load();
    snapshot.cache_misses = access_stats.cache_misses.load();
    snapshot.sequential_accesses = access_stats.sequential_accesses.load();
    snapshot.random_accesses = access_stats.random_accesses.load();
    snapshot.total_latency = access_stats.total_latency;
    snapshot.avg_latency = access_stats.avg_latency;
    
    return snapshot;
}

double PoolStatistics::peak_memory_usage() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    
    if (snapshots_.empty()) {
        return 0.0;
    }
    
    size_t max_used = 0;
    size_t total_size = snapshots_[0].total_size;
    
    for (const auto& snapshot : snapshots_) {
        max_used = std::max(max_used, snapshot.used_size);
    }
    
    return total_size > 0 ? static_cast<double>(max_used) / total_size : 0.0;
}

double PoolStatistics::average_fragmentation() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    
    if (snapshots_.empty()) {
        return 0.0;
    }
    
    double total_fragmentation = 0.0;
    for (const auto& snapshot : snapshots_) {
        total_fragmentation += snapshot.fragmentation;
    }
    
    return total_fragmentation / snapshots_.size();
}

std::chrono::nanoseconds PoolStatistics::peak_access_latency() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    
    std::chrono::nanoseconds peak_latency{0};
    for (const auto& snapshot : snapshots_) {
        peak_latency = std::max(peak_latency, snapshot.avg_latency);
    }
    
    return peak_latency;
}

size_t PoolStatistics::allocation_rate_per_second() const {
    std::lock_guard<std::mutex> lock(snapshots_mutex_);
    
    if (snapshots_.size() < 2) {
        return 0;
    }
    
    const auto& first = snapshots_.front();
    const auto& last = snapshots_.back();
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        last.timestamp - first.timestamp);
    
    if (duration.count() == 0) {
        return 0;
    }
    
    size_t allocation_diff = last.allocation_count - first.allocation_count;
    return allocation_diff / duration.count();
}

void PoolStatistics::monitoring_loop(std::chrono::milliseconds interval) {
    while (monitoring_.load()) {
        auto snapshot = get_current_snapshot();
        
        {
            std::lock_guard<std::mutex> lock(snapshots_mutex_);
            snapshots_.push_back(snapshot);
            
            // limit history size
            if (snapshots_.size() > 1000) {
                snapshots_.erase(snapshots_.begin());
            }
        }
        
        std::this_thread::sleep_for(interval);
    }
}

// ========== Utility Functions ==========

namespace memory_pool_utils {

std::unique_ptr<VirtualMemoryPool> create_pool_for_workload(
    std::shared_ptr<BFVContext> context,
    const std::string& workload_type) {
    
    PoolConfig config;
    
    if (workload_type == "high_performance") {
        config = PoolConfig::performance_config();
    } else if (workload_type == "debug") {
        config = PoolConfig::debug_config();
    } else if (workload_type == "large_allocations") {
        config = PoolConfig::default_config();
        config.total_size = 1024 * 1024 * 1024; // 1GB
        config.max_block_size = 64 * 1024 * 1024; // 64MB
    } else if (workload_type == "fragmentation_test") {
        config = PoolConfig::default_config();
        config.enable_fragmentation_sim = true;
        config.min_block_size = 1;
        config.max_block_size = 1024;
    } else {
        config = PoolConfig::default_config();
    }
    
    return std::make_unique<VirtualMemoryPool>(context, config);
}

Result<void> stress_test_pool(VirtualMemoryPool& pool, 
                             size_t num_threads,
                             std::chrono::seconds duration) {
    
    if (!pool.is_initialized()) {
        auto init_result = pool.initialize();
        if (!init_result.has_value()) {
            return Result<void>("Failed to initialize pool: " + init_result.error());
        }
    }
    
    std::atomic<bool> stop_flag{false};
    std::vector<std::thread> threads;
    std::atomic<size_t> total_allocations{0};
    std::atomic<size_t> total_deallocations{0};
    std::atomic<size_t> allocation_failures{0};
    
    // start worker threads
    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back([&pool, &stop_flag, &total_allocations, &total_deallocations, &allocation_failures]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<size_t> size_dist(8, 1024);
            std::uniform_int_distribution<int> pattern_dist(0, 4);
            
            std::vector<EncryptedAddress> allocated_addresses;
            
            while (!stop_flag.load()) {
                if (allocated_addresses.size() < 100 && gen() % 3 != 0) {
                    // allocate
                    size_t size = size_dist(gen);
                    AccessPattern pattern = static_cast<AccessPattern>(pattern_dist(gen));
                    
                    auto result = pool.allocate(size, Alignment::BYTE_8, pattern);
                    if (result.has_value()) {
                        allocated_addresses.push_back(result.value()->virtual_address);
                        total_allocations.fetch_add(1);
                    } else {
                        allocation_failures.fetch_add(1);
                    }
                } else if (!allocated_addresses.empty()) {
                    // deallocate
                    size_t index = gen() % allocated_addresses.size();
                    auto addr = allocated_addresses[index];
                    allocated_addresses.erase(allocated_addresses.begin() + index);
                    
                    auto result = pool.deallocate(addr);
                    if (result.has_value()) {
                        total_deallocations.fetch_add(1);
                    }
                }
                
                // occasionally simulate memory access
                if (!allocated_addresses.empty() && gen() % 10 == 0) {
                    size_t index = gen() % allocated_addresses.size();
                    pool.simulate_access(allocated_addresses[index]);
                }
            }
            
            // cleanup remaining allocations
            for (const auto& addr : allocated_addresses) {
                pool.deallocate(addr);
                total_deallocations.fetch_add(1);
            }
        });
    }
    
    // run for specified duration
    std::this_thread::sleep_for(duration);
    stop_flag.store(true);
    
    // wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // validate pool integrity
    auto integrity_result = pool.validate_integrity();
    if (!integrity_result.has_value()) {
        return Result<void>("Pool integrity validation failed: " + integrity_result.error());
    }
    
    return Result<void>::success();
}

Result<BenchmarkResults> benchmark_pool(VirtualMemoryPool& pool, size_t num_operations) {
    if (!pool.is_initialized()) {
        auto init_result = pool.initialize();
        if (!init_result.has_value()) {
            return Result<BenchmarkResults>("Failed to initialize pool: " + init_result.error());
        }
    }
    
    BenchmarkResults results{0, 0, std::chrono::nanoseconds(0), std::chrono::nanoseconds(0), 0.0};
    
    std::vector<const MemoryBlock*> allocated_blocks;
    allocated_blocks.reserve(num_operations / 2);
    
    // benchmark allocations
    auto alloc_start = std::chrono::high_resolution_clock::now();
    std::chrono::nanoseconds total_alloc_latency{0};
    
    for (size_t i = 0; i < num_operations / 2; ++i) {
        size_t size = 64 + (i % 1024);
        
        auto op_start = std::chrono::high_resolution_clock::now();
        auto result = pool.allocate(size);
        auto op_end = std::chrono::high_resolution_clock::now();
        
        if (result.has_value()) {
            allocated_blocks.push_back(result.value());
            total_alloc_latency += std::chrono::duration_cast<std::chrono::nanoseconds>(op_end - op_start);
        }
    }
    
    auto alloc_end = std::chrono::high_resolution_clock::now();
    auto alloc_duration = std::chrono::duration_cast<std::chrono::seconds>(alloc_end - alloc_start);
    
    results.allocations_per_second = static_cast<double>(allocated_blocks.size()) / alloc_duration.count();
    results.avg_allocation_latency = allocated_blocks.empty() ? 
        std::chrono::nanoseconds(0) : total_alloc_latency / static_cast<long>(allocated_blocks.size());
    
    // benchmark deallocations
    auto dealloc_start = std::chrono::high_resolution_clock::now();
    std::chrono::nanoseconds total_dealloc_latency{0};
    
    for (const auto& block : allocated_blocks) {
        auto op_start = std::chrono::high_resolution_clock::now();
        pool.deallocate(block->virtual_address);
        auto op_end = std::chrono::high_resolution_clock::now();
        
        total_dealloc_latency += std::chrono::duration_cast<std::chrono::nanoseconds>(op_end - op_start);
    }
    
    auto dealloc_end = std::chrono::high_resolution_clock::now();
    auto dealloc_duration = std::chrono::duration_cast<std::chrono::seconds>(dealloc_end - dealloc_start);
    
    results.deallocations_per_second = static_cast<double>(allocated_blocks.size()) / dealloc_duration.count();
    results.avg_deallocation_latency = allocated_blocks.empty() ? 
        std::chrono::nanoseconds(0) : total_dealloc_latency / static_cast<long>(allocated_blocks.size());
    
    // get fragmentation info
    auto frag_info = pool.fragmentation_info();
    if (frag_info.has_value()) {
        results.peak_fragmentation = frag_info.value().external_fragmentation;
    }
    
    return Result<BenchmarkResults>(results);
}

Result<void> validate_pool_correctness(std::shared_ptr<BFVContext> context) {
    // test different pool configurations
    std::vector<PoolConfig> configs = {
        PoolConfig::default_config(),
        PoolConfig::performance_config(),
        PoolConfig::debug_config()
    };
    
    for (const auto& config : configs) {
        VirtualMemoryPool pool(context, config);
        
        auto init_result = pool.initialize();
        if (!init_result.has_value()) {
            return Result<void>("Failed to initialize pool with config: " + init_result.error());
        }
        
        // test basic allocation/deallocation
        auto alloc_result = pool.allocate(64);
        if (!alloc_result.has_value()) {
            return Result<void>("Basic allocation failed: " + alloc_result.error());
        }
        
        auto dealloc_result = pool.deallocate(alloc_result.value()->virtual_address);
        if (!dealloc_result.has_value()) {
            return Result<void>("Basic deallocation failed: " + dealloc_result.error());
        }
        
        // test integrity
        auto integrity_result = pool.validate_integrity();
        if (!integrity_result.has_value()) {
            return Result<void>("Integrity validation failed: " + integrity_result.error());
        }
        
        auto shutdown_result = pool.shutdown();
        if (!shutdown_result.has_value()) {
            return Result<void>("Pool shutdown failed: " + shutdown_result.error());
        }
    }
    
    return Result<void>::success();
}

} // namespace memory_pool_utils

} // namespace cryptmalloc