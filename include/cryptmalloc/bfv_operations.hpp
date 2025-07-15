/**
 * @file bfv_operations.hpp
 * @brief comprehensive homomorphic arithmetic operations with noise budget management
 */

#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>

#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/core.hpp"

namespace cryptmalloc {

/**
 * @brief noise budget status and management
 */
struct NoiseBudget {
    double initial_budget;          ///< initial noise budget
    double current_budget;          ///< current remaining budget
    double critical_threshold;      ///< threshold for refresh operation
    uint32_t operations_count;      ///< number of operations performed
    std::chrono::steady_clock::time_point created_at;  ///< creation timestamp

    /**
     * @brief check if refresh is needed
     */
    bool needs_refresh() const noexcept {
        return current_budget < critical_threshold;
    }

    /**
     * @brief get budget utilization percentage
     */
    double utilization() const noexcept {
        if (initial_budget <= 0) return 100.0;
        return (1.0 - current_budget / initial_budget) * 100.0;
    }
};

/**
 * @brief encrypted integer with automatic noise budget management
 */
class EncryptedInt {
public:
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    /**
     * @brief construct from plaintext value
     * @param value plaintext integer value
     * @param context BFV context for encryption
     */
    EncryptedInt(int64_t value, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from existing ciphertext
     * @param ciphertext encrypted data
     * @param context BFV context
     * @param initial_budget initial noise budget
     */
    EncryptedInt(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                 double initial_budget = 50.0);

    /**
     * @brief copy constructor with noise budget preservation  
     */
    EncryptedInt(const EncryptedInt& other);

    /**
     * @brief move constructor
     */
    EncryptedInt(EncryptedInt&& other) noexcept;

    /**
     * @brief copy assignment operator
     */
    EncryptedInt& operator=(const EncryptedInt& other);

    /**
     * @brief move assignment operator
     */
    EncryptedInt& operator=(EncryptedInt&& other) noexcept;

    /**
     * @brief decrypt to plaintext value
     * @return decrypted integer or error
     */
    Result<int64_t> decrypt() const;

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
     * @return true if ciphertext is valid
     */
    bool is_valid() const;

    /**
     * @brief check if refresh is needed
     */
    bool needs_refresh() const noexcept { return noise_budget_.needs_refresh(); }

    /**
     * @brief refresh ciphertext to restore noise budget
     * @return result indicating success or failure
     */
    Result<void> refresh();

    /**
     * @brief get operation count
     */
    uint32_t operation_count() const noexcept { return noise_budget_.operations_count; }

private:
    Ciphertext ciphertext_;
    std::shared_ptr<BFVContext> context_;
    NoiseBudget noise_budget_;
    mutable std::mutex mutex_;

    void update_noise_budget(double cost);
    double estimate_current_noise() const;
};

/**
 * @brief batch of encrypted integers for vectorized operations
 */
class EncryptedIntBatch {
public:
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    /**
     * @brief construct from vector of plaintext values
     * @param values plaintext integer values
     * @param context BFV context for encryption
     */
    EncryptedIntBatch(const std::vector<int64_t>& values, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from existing ciphertext
     * @param ciphertext encrypted batch data
     * @param context BFV context
     * @param size number of elements in batch
     * @param initial_budget initial noise budget
     */
    EncryptedIntBatch(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                      size_t size, double initial_budget = 50.0);
    
    // copy and move constructors
    EncryptedIntBatch(const EncryptedIntBatch& other);
    EncryptedIntBatch(EncryptedIntBatch&& other) noexcept;
    EncryptedIntBatch& operator=(const EncryptedIntBatch& other);
    EncryptedIntBatch& operator=(EncryptedIntBatch&& other) noexcept;

    /**
     * @brief decrypt to plaintext values
     * @return decrypted integers or error
     */
    Result<std::vector<int64_t>> decrypt() const;

    /**
     * @brief get batch size
     */
    size_t size() const noexcept { return size_; }

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
     * @brief validate batch integrity
     */
    bool is_valid() const;

    /**
     * @brief check if refresh is needed
     */
    bool needs_refresh() const noexcept { return noise_budget_.needs_refresh(); }

    /**
     * @brief refresh batch to restore noise budget
     */
    Result<void> refresh();

private:
    Ciphertext ciphertext_;
    std::shared_ptr<BFVContext> context_;
    size_t size_;
    NoiseBudget noise_budget_;
    mutable std::mutex mutex_;

    void update_noise_budget(double cost);
};

/**
 * @brief arithmetic operations on encrypted integers
 */
class BFVOperations : public std::enable_shared_from_this<BFVOperations> {
public:
    /**
     * @brief construct with BFV context
     */
    explicit BFVOperations(std::shared_ptr<BFVContext> context);
    
    // non-copyable due to mutex member
    BFVOperations(const BFVOperations&) = delete;
    BFVOperations& operator=(const BFVOperations&) = delete;
    
    // movable
    BFVOperations(BFVOperations&&) noexcept = default;
    BFVOperations& operator=(BFVOperations&&) noexcept = default;

    // Single integer operations
    
    /**
     * @brief encrypted addition
     * @param a left operand
     * @param b right operand
     * @return encrypted result or error
     */
    Result<EncryptedInt> add(const EncryptedInt& a, const EncryptedInt& b);

    /**
     * @brief encrypted subtraction
     * @param a left operand (minuend)
     * @param b right operand (subtrahend)
     * @return encrypted result or error
     */
    Result<EncryptedInt> subtract(const EncryptedInt& a, const EncryptedInt& b);

    /**
     * @brief encrypted multiplication
     * @param a left operand
     * @param b right operand
     * @return encrypted result or error
     */
    Result<EncryptedInt> multiply(const EncryptedInt& a, const EncryptedInt& b);

    /**
     * @brief encrypted negation
     * @param a operand to negate
     * @return encrypted result or error
     */
    Result<EncryptedInt> negate(const EncryptedInt& a);

    /**
     * @brief add plaintext constant to encrypted value
     * @param a encrypted operand
     * @param constant plaintext constant
     * @return encrypted result or error
     */
    Result<EncryptedInt> add_constant(const EncryptedInt& a, int64_t constant);

    /**
     * @brief multiply encrypted value by plaintext constant
     * @param a encrypted operand
     * @param constant plaintext constant
     * @return encrypted result or error
     */
    Result<EncryptedInt> multiply_constant(const EncryptedInt& a, int64_t constant);

    // Batch operations

    /**
     * @brief batch addition
     * @param a left operand batch
     * @param b right operand batch
     * @return encrypted result batch or error
     */
    Result<EncryptedIntBatch> add_batch(const EncryptedIntBatch& a, const EncryptedIntBatch& b);

    /**
     * @brief batch subtraction
     * @param a left operand batch
     * @param b right operand batch
     * @return encrypted result batch or error
     */
    Result<EncryptedIntBatch> subtract_batch(const EncryptedIntBatch& a, const EncryptedIntBatch& b);

    /**
     * @brief batch multiplication
     * @param a left operand batch
     * @param b right operand batch
     * @return encrypted result batch or error
     */
    Result<EncryptedIntBatch> multiply_batch(const EncryptedIntBatch& a, const EncryptedIntBatch& b);

    /**
     * @brief batch negation
     * @param a operand batch to negate
     * @return encrypted result batch or error
     */
    Result<EncryptedIntBatch> negate_batch(const EncryptedIntBatch& a);

    // Advanced operations

    /**
     * @brief compute sum of encrypted values
     * @param values vector of encrypted integers
     * @return encrypted sum or error
     */
    Result<EncryptedInt> sum(const std::vector<EncryptedInt>& values);

    /**
     * @brief compute dot product of two encrypted vectors
     * @param a first vector
     * @param b second vector
     * @return encrypted dot product or error
     */
    Result<EncryptedInt> dot_product(const std::vector<EncryptedInt>& a,
                                     const std::vector<EncryptedInt>& b);

    /**
     * @brief compute polynomial evaluation at encrypted value
     * @param coefficients polynomial coefficients (plaintext)
     * @param x encrypted evaluation point
     * @return encrypted result or error
     */
    Result<EncryptedInt> evaluate_polynomial(const std::vector<int64_t>& coefficients,
                                             const EncryptedInt& x);

    // Operation chaining and optimization

    /**
     * @brief chain multiple operations with intermediate optimization
     */
    class OperationChain {
    public:
        OperationChain(std::shared_ptr<BFVOperations> ops, EncryptedInt initial_value);

        OperationChain& add(const EncryptedInt& value);
        OperationChain& add(int64_t constant);
        OperationChain& subtract(const EncryptedInt& value);
        OperationChain& subtract(int64_t constant);
        OperationChain& multiply(const EncryptedInt& value);
        OperationChain& multiply(int64_t constant);
        OperationChain& negate();

        /**
         * @brief execute chain and return result
         */
        Result<EncryptedInt> execute();

        /**
         * @brief get estimated noise cost before execution
         */
        double estimated_noise_cost() const;

    private:
        std::shared_ptr<BFVOperations> operations_;
        EncryptedInt current_value_;
        std::vector<std::function<Result<EncryptedInt>(const EncryptedInt&)>> chain_;
        double estimated_cost_;

        void optimize_chain();
    };

    /**
     * @brief create operation chain starting with given value
     */
    OperationChain chain(EncryptedInt initial_value);

    // Overflow and validation

    /**
     * @brief check if value is within safe range for operations
     * @param value encrypted value to check
     * @return true if safe for operations
     */
    Result<bool> is_in_safe_range(const EncryptedInt& value);

    /**
     * @brief detect potential overflow before operation
     * @param a first operand
     * @param b second operand
     * @param operation type of operation
     * @return true if overflow is likely
     */
    bool will_overflow(const EncryptedInt& a, const EncryptedInt& b, 
                       const std::string& operation);

    // Statistics and diagnostics

    /**
     * @brief operation statistics
     */
    struct OperationStats {
        uint64_t additions_performed;
        uint64_t subtractions_performed;
        uint64_t multiplications_performed;
        uint64_t negations_performed;
        uint64_t refreshes_performed;
        uint64_t validation_failures;
        double average_noise_consumption;
        std::chrono::milliseconds total_operation_time;
    };

    /**
     * @brief get operation statistics
     */
    const OperationStats& statistics() const noexcept { return stats_; }

    /**
     * @brief reset statistics counters
     */
    void reset_statistics();

private:
    std::shared_ptr<BFVContext> context_;
    OperationStats stats_;
    mutable std::mutex stats_mutex_;

    // Internal operation helpers
    Result<EncryptedInt> perform_binary_operation(
        const EncryptedInt& a, const EncryptedInt& b,
        std::function<Result<BFVContext::Ciphertext>(const BFVContext::Ciphertext&, 
                                                     const BFVContext::Ciphertext&)> operation,
        const std::string& operation_name, double noise_cost);

    Result<EncryptedInt> perform_unary_operation(
        const EncryptedInt& a,
        std::function<Result<BFVContext::Ciphertext>(const BFVContext::Ciphertext&)> operation,
        const std::string& operation_name, double noise_cost);

    // Noise management
    double calculate_noise_cost(const std::string& operation, 
                               const std::vector<double>& operand_budgets);
    
    bool should_auto_refresh(const EncryptedInt& value);
    Result<EncryptedInt> auto_refresh_if_needed(EncryptedInt value);

    // Validation
    bool validate_operands(const EncryptedInt& a, const EncryptedInt& b);
    bool validate_batch_operands(const EncryptedIntBatch& a, const EncryptedIntBatch& b);

    // Statistics helpers
    void record_operation(const std::string& operation, 
                         std::chrono::steady_clock::time_point start_time,
                         bool success, double noise_consumed = 0.0);
};

/**
 * @brief utility functions for encrypted integer operations
 */
namespace encrypted_int_utils {

/**
 * @brief create encrypted integer from plaintext
 * @param value plaintext value
 * @param context BFV context
 * @return encrypted integer or error
 */
Result<EncryptedInt> encrypt(int64_t value, std::shared_ptr<BFVContext> context);

/**
 * @brief create encrypted batch from plaintext vector
 * @param values plaintext values
 * @param context BFV context
 * @return encrypted batch or error
 */
Result<EncryptedIntBatch> encrypt_batch(const std::vector<int64_t>& values,
                                        std::shared_ptr<BFVContext> context);

/**
 * @brief compare two encrypted integers (requires decryption)
 * @param a first encrypted integer
 * @param b second encrypted integer
 * @return comparison result or error
 */
Result<int> compare(const EncryptedInt& a, const EncryptedInt& b);

/**
 * @brief get maximum safe integer value for current context parameters
 * @param context BFV context
 * @return maximum safe value
 */
int64_t max_safe_value(std::shared_ptr<BFVContext> context);

/**
 * @brief get minimum safe integer value for current context parameters
 * @param context BFV context
 * @return minimum safe value
 */
int64_t min_safe_value(std::shared_ptr<BFVContext> context);

/**
 * @brief estimate noise budget after operation chain
 * @param initial_budget starting noise budget
 * @param operations list of operations to perform
 * @return estimated remaining budget
 */
double estimate_noise_after_operations(double initial_budget,
                                       const std::vector<std::string>& operations);

} // namespace encrypted_int_utils

} // namespace cryptmalloc