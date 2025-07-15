#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>
#include "cryptmalloc/bfv_context.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

class EncryptedInt;
class EncryptedBatch;
class ArithmeticChain;

enum class OverflowBehavior {
    THROW_EXCEPTION,  // throw on overflow
    WRAP_AROUND,      // modular arithmetic
    SATURATE,         // clamp to max/min values
    IGNORE            // proceed without checks
};

struct NoiseInfo {
    double current_level = 0.0;       // current noise level
    double critical_threshold = 0.1;  // threshold for refresh
    int depth_remaining = 0;          // multiplicative depth remaining
    bool needs_refresh = false;       // whether refresh is needed
    std::chrono::steady_clock::time_point last_measured;
};

struct OperationResult {
    bool success = false;
    std::string error_message;
    double noise_increase = 0.0;
    std::chrono::milliseconds duration{0};
};

class EncryptedInt {
  public:
    EncryptedInt() = default;
    explicit EncryptedInt(std::shared_ptr<BFVContext> context);
    EncryptedInt(std::shared_ptr<BFVContext> context, int64_t value);
    EncryptedInt(std::shared_ptr<BFVContext> context,
                 const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext);

    EncryptedInt(const EncryptedInt& other);
    EncryptedInt& operator=(const EncryptedInt& other);
    EncryptedInt(EncryptedInt&& other) noexcept;
    EncryptedInt& operator=(EncryptedInt&& other) noexcept;

    EncryptedInt operator+(const EncryptedInt& other) const;
    EncryptedInt operator-(const EncryptedInt& other) const;
    EncryptedInt operator*(const EncryptedInt& other) const;
    EncryptedInt operator-() const;

    EncryptedInt& operator+=(const EncryptedInt& other);
    EncryptedInt& operator-=(const EncryptedInt& other);
    EncryptedInt& operator*=(const EncryptedInt& other);

    EncryptedInt operator+(int64_t value) const;
    EncryptedInt operator-(int64_t value) const;
    EncryptedInt operator*(int64_t value) const;

    EncryptedInt& operator+=(int64_t value);
    EncryptedInt& operator-=(int64_t value);
    EncryptedInt& operator*=(int64_t value);

    int64_t decrypt() const;
    bool is_valid() const;
    bool validate_integrity() const;

    NoiseInfo get_noise_info() const;
    bool needs_refresh() const;
    void refresh();
    void force_refresh();

    size_t get_ciphertext_size() const;
    int get_multiplicative_depth() const;
    std::shared_ptr<BFVContext> get_context() const {
        return context_;
    }

    bool serialize(const std::string& filepath) const;
    bool deserialize(const std::string& filepath);

    void print_diagnostics() const;
    std::string get_status_string() const;

  private:
    std::shared_ptr<BFVContext> context_;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    mutable NoiseInfo noise_info_;
    mutable std::optional<int64_t> cached_value_;  // for debugging/validation

    void update_noise_info() const;
    void check_overflow_protection(int64_t result, int64_t a, int64_t b, char op) const;
    OperationResult perform_operation(
        const std::function<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>()>& operation,
        const std::string& operation_name) const;
};

class EncryptedBatch {
  public:
    explicit EncryptedBatch(std::shared_ptr<BFVContext> context);
    EncryptedBatch(std::shared_ptr<BFVContext> context, const std::vector<int64_t>& values);

    // batch arithmetic operations
    EncryptedBatch operator+(const EncryptedBatch& other) const;
    EncryptedBatch operator-(const EncryptedBatch& other) const;
    EncryptedBatch operator*(const EncryptedBatch& other) const;

    // element-wise operations with scalars
    EncryptedBatch operator+(int64_t scalar) const;
    EncryptedBatch operator-(int64_t scalar) const;
    EncryptedBatch operator*(int64_t scalar) const;

    // rotation operations for SIMD
    EncryptedBatch rotate_left(int32_t positions) const;
    EncryptedBatch rotate_right(int32_t positions) const;

    // reduction operations
    EncryptedInt sum() const;
    EncryptedInt product() const;

    // access and modification
    size_t size() const;
    std::vector<int64_t> decrypt() const;
    void set_element(size_t index, const EncryptedInt& value);
    EncryptedInt get_element(size_t index) const;

    NoiseInfo get_noise_info() const;
    void refresh();

    // diagnostics
    void print_diagnostics() const;

  private:
    std::shared_ptr<BFVContext> context_;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    size_t batch_size_;
    mutable NoiseInfo noise_info_;

    void update_noise_info() const;
};

class ArithmeticChain {
  public:
    explicit ArithmeticChain(std::shared_ptr<BFVContext> context);

    // chain building
    ArithmeticChain& add(const EncryptedInt& value);
    ArithmeticChain& add(int64_t value);
    ArithmeticChain& subtract(const EncryptedInt& value);
    ArithmeticChain& subtract(int64_t value);
    ArithmeticChain& multiply(const EncryptedInt& value);
    ArithmeticChain& multiply(int64_t value);
    ArithmeticChain& negate();

    // batch operations
    ArithmeticChain& add_batch(const EncryptedBatch& batch);
    ArithmeticChain& multiply_batch(const EncryptedBatch& batch);

    // execution and optimization
    EncryptedInt execute();           // execute with automatic optimization
    EncryptedInt execute_parallel();  // parallel execution where possible

    // chain analysis
    int estimate_depth() const;
    double estimate_noise_growth() const;
    size_t operation_count() const;

    // optimization control
    void enable_intermediate_refresh(bool enable = true);
    void set_optimization_level(int level);  // 0=none, 1=basic, 2=aggressive

    // diagnostics
    std::string get_execution_plan() const;
    void print_chain_analysis() const;

  private:
    struct Operation {
        enum Type {
            ADD_ENCRYPTED,
            SUB_ENCRYPTED,
            MUL_ENCRYPTED,
            ADD_PLAINTEXT,
            SUB_PLAINTEXT,
            MUL_PLAINTEXT,
            NEGATE
        };
        Type type;
        std::optional<EncryptedInt> encrypted_operand;
        std::optional<int64_t> plaintext_operand;
        double estimated_noise_increase;
    };

    std::shared_ptr<BFVContext> context_;
    std::vector<Operation> operations_;
    std::optional<EncryptedInt> initial_value_;
    bool intermediate_refresh_enabled_ = true;
    int optimization_level_ = 1;

    void optimize_operations();
    EncryptedInt execute_optimized();
    double calculate_noise_increase(const Operation& op) const;
};

// utility functions for arithmetic operations
namespace arithmetic {

// basic operations with noise budget management
OperationResult safe_add(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result);
OperationResult safe_subtract(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result);
OperationResult safe_multiply(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result);

// batch operations
std::vector<EncryptedInt> batch_add(const std::vector<EncryptedInt>& a,
                                    const std::vector<EncryptedInt>& b);
std::vector<EncryptedInt> batch_multiply(const std::vector<EncryptedInt>& a,
                                         const std::vector<EncryptedInt>& b);

// convenience functions for common patterns
EncryptedInt compute_sum(const std::vector<EncryptedInt>& values);
EncryptedInt compute_product(const std::vector<EncryptedInt>& values);
EncryptedInt compute_dot_product(const std::vector<EncryptedInt>& a,
                                 const std::vector<EncryptedInt>& b);

// polynomial evaluation
EncryptedInt evaluate_polynomial(const EncryptedInt& x, const std::vector<int64_t>& coefficients);

// memory allocator specific operations
EncryptedInt compute_address_offset(const EncryptedInt& base_addr,
                                    const EncryptedInt& index,
                                    int64_t element_size);
EncryptedInt compute_aligned_size(const EncryptedInt& size, int64_t alignment);

}  // namespace arithmetic

// global configuration
class ArithmeticConfig {
  public:
    static ArithmeticConfig& instance();

    // noise management settings
    void set_noise_threshold(double threshold);
    double get_noise_threshold() const;

    void set_auto_refresh(bool enabled);
    bool get_auto_refresh() const;

    // overflow behavior
    void set_overflow_behavior(OverflowBehavior behavior);
    OverflowBehavior get_overflow_behavior() const;

    // performance settings
    void set_parallel_threshold(size_t threshold);
    size_t get_parallel_threshold() const;

    void enable_caching(bool enabled);
    bool is_caching_enabled() const;

    // diagnostics
    void enable_operation_logging(bool enabled);
    bool is_operation_logging_enabled() const;

    struct Statistics {
        size_t total_operations = 0;
        size_t refresh_count = 0;
        std::chrono::milliseconds total_time{0};
        double average_noise_level = 0.0;
    };

    Statistics get_statistics() const;
    void reset_statistics();

  private:
    ArithmeticConfig() = default;

    double noise_threshold_ = 0.1;
    bool auto_refresh_ = true;
    OverflowBehavior overflow_behavior_ = OverflowBehavior::THROW_EXCEPTION;
    size_t parallel_threshold_ = 100;
    bool caching_enabled_ = true;
    bool operation_logging_ = false;
    mutable Statistics stats_;
};

// exception classes
class ArithmeticException : public std::runtime_error {
  public:
    explicit ArithmeticException(const std::string& message) : std::runtime_error(message) {}
};

class OverflowException : public ArithmeticException {
  public:
    explicit OverflowException(const std::string& message) : ArithmeticException(message) {}
};

class NoiseException : public ArithmeticException {
  public:
    explicit NoiseException(const std::string& message) : ArithmeticException(message) {}
};

class ValidationException : public ArithmeticException {
  public:
    explicit ValidationException(const std::string& message) : ArithmeticException(message) {}
};

}