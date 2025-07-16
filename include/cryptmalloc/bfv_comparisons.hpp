/**
 * @file bfv_comparisons.hpp
 * @brief homomorphic comparison operations and conditional logic for encrypted memory management
 */

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/bfv_operations.hpp"
#include "cryptmalloc/core.hpp"

namespace cryptmalloc {

/**
 * @brief encrypted boolean value with noise budget management
 */
class EncryptedBool {
public:
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    /**
     * @brief construct from plaintext boolean
     * @param value plaintext boolean value
     * @param context BFV context for encryption
     */
    EncryptedBool(bool value, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from existing ciphertext
     * @param ciphertext encrypted boolean data
     * @param context BFV context
     * @param initial_budget initial noise budget
     */
    EncryptedBool(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                  double initial_budget = 50.0);

    // copy and move constructors/operators
    EncryptedBool(const EncryptedBool& other);
    EncryptedBool(EncryptedBool&& other) noexcept;
    EncryptedBool& operator=(const EncryptedBool& other);
    EncryptedBool& operator=(EncryptedBool&& other) noexcept;

    /**
     * @brief decrypt to plaintext boolean
     * @return decrypted boolean or error
     */
    Result<bool> decrypt() const;

    /**
     * @brief get underlying ciphertext
     */
    const Ciphertext& ciphertext() const noexcept { return ciphertext_; }

    /**
     * @brief get BFV context
     */
    std::shared_ptr<BFVContext> context() const noexcept { return context_; }

    /**
     * @brief get current noise budget
     */
    const NoiseBudget& noise_budget() const noexcept { return noise_budget_; }

    /**
     * @brief validate ciphertext integrity
     */
    bool is_valid() const;

    /**
     * @brief check if refresh is needed
     */
    bool needs_refresh() const noexcept { return noise_budget_.needs_refresh(); }

    /**
     * @brief refresh ciphertext to restore noise budget
     */
    Result<void> refresh();

private:
    Ciphertext ciphertext_;
    std::shared_ptr<BFVContext> context_;
    NoiseBudget noise_budget_;
    mutable std::mutex mutex_;

    void update_noise_budget(double cost);
};

/**
 * @brief homomorphic comparison result cache entry
 */
struct ComparisonCacheEntry {
    EncryptedBool result;
    std::chrono::steady_clock::time_point created_at;
    uint64_t access_count;
    
    ComparisonCacheEntry(EncryptedBool res)
        : result(std::move(res))
        , created_at(std::chrono::steady_clock::now())
        , access_count(1) {}
};

/**
 * @brief homomorphic comparison operations with caching and optimization
 */
class BFVComparisons : public std::enable_shared_from_this<BFVComparisons> {
public:
    /**
     * @brief construct with BFV context and operations
     */
    explicit BFVComparisons(std::shared_ptr<BFVContext> context,
                           std::shared_ptr<BFVOperations> operations = nullptr);

    // non-copyable due to mutex and cache
    BFVComparisons(const BFVComparisons&) = delete;
    BFVComparisons& operator=(const BFVComparisons&) = delete;

    // movable
    BFVComparisons(BFVComparisons&&) noexcept = default;
    BFVComparisons& operator=(BFVComparisons&&) noexcept = default;

    // Core comparison operations

    /**
     * @brief homomorphic greater than comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> greater_than(const EncryptedInt& a, const EncryptedInt& b,
                                      bool constant_time = true);

    /**
     * @brief homomorphic less than comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> less_than(const EncryptedInt& a, const EncryptedInt& b,
                                   bool constant_time = true);

    /**
     * @brief homomorphic greater than or equal comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> greater_equal(const EncryptedInt& a, const EncryptedInt& b,
                                       bool constant_time = true);

    /**
     * @brief homomorphic less than or equal comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> less_equal(const EncryptedInt& a, const EncryptedInt& b,
                                    bool constant_time = true);

    /**
     * @brief homomorphic equality comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> equal(const EncryptedInt& a, const EncryptedInt& b,
                               bool constant_time = true);

    /**
     * @brief homomorphic inequality comparison
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> not_equal(const EncryptedInt& a, const EncryptedInt& b,
                                   bool constant_time = true);

    /**
     * @brief compare with plaintext constant
     * @param a encrypted operand
     * @param constant plaintext constant
     * @param comparison type of comparison ("gt", "lt", "eq", "ne", "ge", "le")
     * @param constant_time ensure constant-time execution
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> compare_constant(const EncryptedInt& a, int64_t constant,
                                          const std::string& comparison,
                                          bool constant_time = true);

    // Conditional operations

    /**
     * @brief homomorphic conditional selection (encrypted if-then-else)
     * @param condition encrypted boolean condition
     * @param true_value value to select if condition is true
     * @param false_value value to select if condition is false
     * @return selected encrypted value or error
     */
    Result<EncryptedInt> conditional_select(const EncryptedBool& condition,
                                           const EncryptedInt& true_value,
                                           const EncryptedInt& false_value);

    /**
     * @brief conditional selection with plaintext values
     * @param condition encrypted boolean condition
     * @param true_value plaintext value if true
     * @param false_value plaintext value if false
     * @return selected encrypted value or error
     */
    Result<EncryptedInt> conditional_select_constants(const EncryptedBool& condition,
                                                     int64_t true_value,
                                                     int64_t false_value);

    // Min/max operations

    /**
     * @brief homomorphic minimum of two values
     * @param a first value
     * @param b second value
     * @return encrypted minimum value or error
     */
    Result<EncryptedInt> min(const EncryptedInt& a, const EncryptedInt& b);

    /**
     * @brief homomorphic maximum of two values
     * @param a first value
     * @param b second value
     * @return encrypted maximum value or error
     */
    Result<EncryptedInt> max(const EncryptedInt& a, const EncryptedInt& b);

    /**
     * @brief find minimum in vector of encrypted values
     * @param values vector of encrypted integers
     * @return encrypted minimum value or error
     */
    Result<EncryptedInt> min_vector(const std::vector<EncryptedInt>& values);

    /**
     * @brief find maximum in vector of encrypted values
     * @param values vector of encrypted integers
     * @return encrypted maximum value or error
     */
    Result<EncryptedInt> max_vector(const std::vector<EncryptedInt>& values);

    /**
     * @brief find index of minimum value in vector
     * @param values vector of encrypted integers
     * @return encrypted index of minimum or error
     */
    Result<EncryptedInt> argmin(const std::vector<EncryptedInt>& values);

    /**
     * @brief find index of maximum value in vector
     * @param values vector of encrypted integers
     * @return encrypted index of maximum or error
     */
    Result<EncryptedInt> argmax(const std::vector<EncryptedInt>& values);

    // Sign and absolute value operations

    /**
     * @brief detect sign of encrypted value
     * @param value encrypted integer
     * @return encrypted boolean (true if positive, false if negative/zero)
     */
    Result<EncryptedBool> is_positive(const EncryptedInt& value);

    /**
     * @brief check if value is negative
     * @param value encrypted integer
     * @return encrypted boolean (true if negative, false if positive/zero)
     */
    Result<EncryptedBool> is_negative(const EncryptedInt& value);

    /**
     * @brief check if value is zero
     * @param value encrypted integer
     * @return encrypted boolean (true if zero, false otherwise)
     */
    Result<EncryptedBool> is_zero(const EncryptedInt& value);

    /**
     * @brief compute absolute value
     * @param value encrypted integer
     * @return encrypted absolute value or error
     */
    Result<EncryptedInt> abs(const EncryptedInt& value);

    /**
     * @brief get sign as integer (-1, 0, 1)
     * @param value encrypted integer
     * @return encrypted sign value or error
     */
    Result<EncryptedInt> sign(const EncryptedInt& value);

    // Boolean operations

    /**
     * @brief homomorphic logical AND
     * @param a first boolean operand
     * @param b second boolean operand
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> logical_and(const EncryptedBool& a, const EncryptedBool& b);

    /**
     * @brief homomorphic logical OR
     * @param a first boolean operand
     * @param b second boolean operand
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> logical_or(const EncryptedBool& a, const EncryptedBool& b);

    /**
     * @brief homomorphic logical NOT
     * @param a boolean operand
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> logical_not(const EncryptedBool& a);

    /**
     * @brief homomorphic logical XOR
     * @param a first boolean operand
     * @param b second boolean operand
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> logical_xor(const EncryptedBool& a, const EncryptedBool& b);

    // Range and boundary operations

    /**
     * @brief check if value is within range [min, max]
     * @param value encrypted value to check
     * @param min_val minimum boundary (plaintext)
     * @param max_val maximum boundary (plaintext)
     * @return encrypted boolean result or error
     */
    Result<EncryptedBool> in_range(const EncryptedInt& value, int64_t min_val, int64_t max_val);

    /**
     * @brief clamp value to range [min, max]
     * @param value encrypted value to clamp
     * @param min_val minimum boundary (plaintext)
     * @param max_val maximum boundary (plaintext)
     * @return clamped encrypted value or error
     */
    Result<EncryptedInt> clamp(const EncryptedInt& value, int64_t min_val, int64_t max_val);

    // Cache management

    /**
     * @brief enable/disable comparison result caching
     * @param enabled whether to cache results
     * @param max_cache_size maximum number of cached entries
     * @param ttl_seconds cache entry time-to-live in seconds
     */
    void configure_cache(bool enabled, size_t max_cache_size = 1000, 
                        uint32_t ttl_seconds = 300);

    /**
     * @brief clear comparison cache
     */
    void clear_cache();

    /**
     * @brief get cache statistics
     */
    struct CacheStats {
        size_t current_size;
        size_t max_size;
        uint64_t hits;
        uint64_t misses;
        double hit_rate;
        uint32_t ttl_seconds;
    };

    CacheStats cache_statistics() const;

    // Performance and diagnostics

    /**
     * @brief comparison operation statistics
     */
    struct ComparisonStats {
        uint64_t comparisons_performed;
        uint64_t conditional_selects_performed;
        uint64_t min_max_operations;
        uint64_t boolean_operations;
        uint64_t cache_hits;
        uint64_t cache_misses;
        uint64_t constant_time_operations;
        double average_comparison_time_ms;
        double average_noise_consumption;
        std::chrono::milliseconds total_operation_time;
    };

    /**
     * @brief get comparison operation statistics
     */
    const ComparisonStats& statistics() const noexcept { return stats_; }

    /**
     * @brief reset statistics counters
     */
    void reset_statistics();

    /**
     * @brief benchmark comparison operation performance
     * @param operation comparison operation name
     * @param iterations number of test iterations
     * @return average operation time in milliseconds
     */
    Result<double> benchmark_operation(const std::string& operation, size_t iterations = 100);

private:
    std::shared_ptr<BFVContext> context_;
    std::shared_ptr<BFVOperations> operations_;
    
    // comparison cache
    mutable std::unordered_map<std::string, ComparisonCacheEntry> cache_;
    bool cache_enabled_;
    size_t max_cache_size_;
    uint32_t cache_ttl_seconds_;
    mutable std::mutex cache_mutex_;

    // statistics
    ComparisonStats stats_;
    mutable std::mutex stats_mutex_;

    // internal comparison circuit implementations
    
    /**
     * @brief core comparison circuit using subtraction and bit extraction
     * @param a left operand
     * @param b right operand
     * @param extract_sign whether to extract sign bit for comparison
     * @param constant_time ensure constant execution time
     * @return encrypted comparison result or error
     */
    Result<EncryptedBool> comparison_circuit(const EncryptedInt& a, const EncryptedInt& b,
                                           bool extract_sign, bool constant_time);

    /**
     * @brief optimized equality circuit using difference polynomial
     * @param a left operand
     * @param b right operand
     * @param constant_time ensure constant execution time
     * @return encrypted equality result or error
     */
    Result<EncryptedBool> equality_circuit(const EncryptedInt& a, const EncryptedInt& b,
                                          bool constant_time);

    /**
     * @brief sign bit extraction from encrypted integer
     * @param value encrypted integer
     * @param constant_time ensure constant execution time
     * @return encrypted sign bit or error
     */
    Result<EncryptedBool> extract_sign_bit(const EncryptedInt& value, bool constant_time);

    /**
     * @brief constant-time polynomial evaluation for comparison
     * @param coeffs polynomial coefficients
     * @param x evaluation point
     * @return polynomial result or error
     */
    Result<EncryptedInt> constant_time_polynomial(const std::vector<int64_t>& coeffs,
                                                 const EncryptedInt& x);

    // cache management helpers
    std::string create_cache_key(const std::string& operation,
                                const std::vector<int64_t>& operand_hashes) const;
    
    Result<EncryptedBool> check_cache(const std::string& cache_key);
    void store_in_cache(const std::string& cache_key, const EncryptedBool& result);
    void cleanup_expired_cache_entries();

    // noise management
    double calculate_comparison_noise_cost(const std::string& operation,
                                         const std::vector<double>& operand_budgets);

    // validation helpers
    bool validate_comparison_operands(const EncryptedInt& a, const EncryptedInt& b);
    bool validate_boolean_operands(const EncryptedBool& a, const EncryptedBool& b);

    // statistics helpers
    void record_comparison_operation(const std::string& operation,
                                   std::chrono::steady_clock::time_point start_time,
                                   bool success, bool cache_hit = false,
                                   double noise_consumed = 0.0);

    // constant-time operation helpers
    void add_constant_time_delay() const;
    std::chrono::steady_clock::time_point start_constant_time_operation() const;
    void end_constant_time_operation(std::chrono::steady_clock::time_point start,
                                   double target_time_ms = 50.0) const;
};

/**
 * @brief utility functions for encrypted boolean and comparison operations
 */
namespace encrypted_comparison_utils {

/**
 * @brief create encrypted boolean from plaintext
 * @param value plaintext boolean
 * @param context BFV context
 * @return encrypted boolean or error
 */
Result<EncryptedBool> encrypt_bool(bool value, std::shared_ptr<BFVContext> context);

/**
 * @brief batch comparison operations
 * @param values vector of encrypted integers to compare pairwise
 * @param comparison comparison type ("gt", "lt", "eq", etc.)
 * @param comparisons comparison engine
 * @return vector of comparison results or error
 */
Result<std::vector<EncryptedBool>> batch_compare(
    const std::vector<EncryptedInt>& values,
    const std::string& comparison,
    std::shared_ptr<BFVComparisons> comparisons);

/**
 * @brief tournament-style min/max finding for large datasets
 * @param values vector of encrypted integers
 * @param find_max true to find max, false to find min
 * @param comparisons comparison engine
 * @return minimum or maximum value or error
 */
Result<EncryptedInt> tournament_min_max(const std::vector<EncryptedInt>& values,
                                       bool find_max,
                                       std::shared_ptr<BFVComparisons> comparisons);

/**
 * @brief estimate noise consumption for comparison chain
 * @param initial_budget starting noise budget
 * @param comparison_operations list of comparison operations
 * @return estimated remaining budget
 */
double estimate_comparison_noise(double initial_budget,
                               const std::vector<std::string>& comparison_operations);

/**
 * @brief verify constant-time behavior by measuring operation times
 * @param operation_func function to test for constant-time behavior
 * @param test_inputs different inputs to measure timing with
 * @param tolerance_ms acceptable timing variation in milliseconds
 * @return true if timing is constant within tolerance
 */
bool verify_constant_time(std::function<void()> operation_func,
                         const std::vector<std::pair<EncryptedInt, EncryptedInt>>& test_inputs,
                         double tolerance_ms = 5.0);

} // namespace encrypted_comparison_utils

} // namespace cryptmalloc