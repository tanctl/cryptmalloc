#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>
#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/bfv_operations.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

class EncryptedBool;
class ComparisonCache;

struct ComparisonResult {
    bool success = false;
    std::string error_message;
    double noise_increase = 0.0;
    std::chrono::milliseconds duration{0};
    bool constant_time_verified = true;
};

enum class ComparisonMethod {
    SIGN_DETECTION,        // use sign of (a-b) for comparison
    POLYNOMIAL_APPROX,     // polynomial approximation of comparison function
    BITWISE_COMPARISON,    // bit-by-bit comparison circuit
    OPTIMIZED_HYBRID       // adaptive method selection
};

class EncryptedBool {
  public:
    EncryptedBool() = default;
    explicit EncryptedBool(std::shared_ptr<BFVContext> context);
    EncryptedBool(std::shared_ptr<BFVContext> context, bool value);
    EncryptedBool(std::shared_ptr<BFVContext> context,
                  const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext);

    EncryptedBool(const EncryptedBool& other);
    EncryptedBool& operator=(const EncryptedBool& other);
    EncryptedBool(EncryptedBool&& other) noexcept;
    EncryptedBool& operator=(EncryptedBool&& other) noexcept;

    EncryptedBool operator&&(const EncryptedBool& other) const;
    EncryptedBool operator||(const EncryptedBool& other) const;
    EncryptedBool operator!() const;

    EncryptedBool operator&(const EncryptedBool& other) const;
    EncryptedBool operator|(const EncryptedBool& other) const;
    EncryptedBool operator^(const EncryptedBool& other) const;
    bool decrypt() const;
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

    void print_diagnostics() const;
    std::string get_status_string() const;

  private:
    std::shared_ptr<BFVContext> context_;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    mutable NoiseInfo noise_info_;
    mutable std::optional<bool> cached_value_;

    void update_noise_info() const;
    ComparisonResult perform_boolean_operation(
        const std::function<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>()>& operation,
        const std::string& operation_name) const;
};

namespace comparisons {
EncryptedBool greater_than(const EncryptedInt& a, const EncryptedInt& b,
                          ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedBool less_than(const EncryptedInt& a, const EncryptedInt& b,
                       ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedBool greater_equal(const EncryptedInt& a, const EncryptedInt& b,
                           ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedBool less_equal(const EncryptedInt& a, const EncryptedInt& b,
                        ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedBool equal(const EncryptedInt& a, const EncryptedInt& b,
                   ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedBool not_equal(const EncryptedInt& a, const EncryptedInt& b,
                       ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);

EncryptedInt conditional_select(const EncryptedBool& condition,
                               const EncryptedInt& true_value,
                               const EncryptedInt& false_value);

template<typename T>
T conditional_select(const EncryptedBool& condition, const T& true_value, const T& false_value);

EncryptedInt min(const EncryptedInt& a, const EncryptedInt& b,
                ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);
EncryptedInt max(const EncryptedInt& a, const EncryptedInt& b,
                ComparisonMethod method = ComparisonMethod::OPTIMIZED_HYBRID);

EncryptedBool is_positive(const EncryptedInt& value);
EncryptedBool is_negative(const EncryptedInt& value);
EncryptedBool is_zero(const EncryptedInt& value);
EncryptedInt absolute_value(const EncryptedInt& value);
EncryptedInt sign(const EncryptedInt& value);  // returns -1, 0, or 1

std::vector<EncryptedBool> batch_greater_than(const std::vector<EncryptedInt>& a,
                                              const std::vector<EncryptedInt>& b);
std::vector<EncryptedBool> batch_equal(const std::vector<EncryptedInt>& a,
                                       const std::vector<EncryptedInt>& b);

EncryptedInt find_min(const std::vector<EncryptedInt>& values);
EncryptedInt find_max(const std::vector<EncryptedInt>& values);
EncryptedInt find_median(const std::vector<EncryptedInt>& values);

EncryptedBool in_range(const EncryptedInt& value, const EncryptedInt& min_val,
                      const EncryptedInt& max_val);
EncryptedBool in_range(const EncryptedInt& value, int64_t min_val, int64_t max_val);

}  // namespace comparisons

class ComparisonCache {
  public:
    static ComparisonCache& instance();
    void set_max_size(size_t max_size);
    size_t get_max_size() const;
    
    void set_enabled(bool enabled);
    bool is_enabled() const;

    void clear();
    size_t size() const;

    // cache statistics
    struct Statistics {
        size_t hit_count = 0;
        size_t miss_count = 0;
        size_t eviction_count = 0;
        double hit_rate = 0.0;
        std::chrono::milliseconds total_lookup_time{0};
        std::chrono::milliseconds average_lookup_time{0};
    };

    Statistics get_statistics() const;
    void reset_statistics();

    // internal cache operations (used by comparison functions)
    std::optional<EncryptedBool> lookup_comparison(const std::string& cache_key);
    void store_comparison(const std::string& cache_key, const EncryptedBool& result);

  private:
    ComparisonCache() = default;

    // lru cache implementation
    struct CacheEntry {
        EncryptedBool result;
        std::chrono::steady_clock::time_point last_access;
        size_t access_count = 1;
    };

    std::unordered_map<std::string, CacheEntry> cache_;
    size_t max_size_ = 1000;
    bool enabled_ = true;
    mutable Statistics stats_;

    void evict_lru();
    std::string generate_cache_key(const std::string& operation,
                                  const EncryptedInt& a,
                                  const EncryptedInt& b) const;
};

// constant-time verification utilities
namespace timing {

struct TimingMeasurement {
    std::chrono::nanoseconds min_time{0};
    std::chrono::nanoseconds max_time{0};
    std::chrono::nanoseconds average_time{0};
    double variance = 0.0;
    bool is_constant_time = false;
    double confidence_level = 0.0;
};

TimingMeasurement measure_comparison_timing(
    const std::function<EncryptedBool()>& comparison_func,
    size_t num_iterations = 1000);

bool verify_constant_time(const std::function<EncryptedBool()>& func1,
                         const std::function<EncryptedBool()>& func2,
                         size_t num_iterations = 1000,
                         double threshold = 0.05);

}  // namespace timing

// comparison circuit implementations
namespace circuits {

// sign detection circuit using polynomial approximation
EncryptedBool sign_detection_circuit(const EncryptedInt& difference);

// polynomial approximation of comparison function
EncryptedBool polynomial_comparison_circuit(const EncryptedInt& a, const EncryptedInt& b);

// bitwise comparison circuit (higher depth but more precise)
EncryptedBool bitwise_comparison_circuit(const EncryptedInt& a, const EncryptedInt& b);

// zero-testing circuit using polynomial evaluation
EncryptedBool zero_test_circuit(const EncryptedInt& value);

// optimization utilities
ComparisonMethod select_optimal_method(const EncryptedInt& a, const EncryptedInt& b);
double estimate_circuit_noise(ComparisonMethod method, const NoiseInfo& input_noise);

}  // namespace circuits

// global comparison configuration
class ComparisonConfig {
  public:
    static ComparisonConfig& instance();

    // method selection
    void set_default_method(ComparisonMethod method);
    ComparisonMethod get_default_method() const;

    void set_adaptive_method_selection(bool enabled);
    bool is_adaptive_method_selection_enabled() const;

    // performance settings
    void set_performance_target_ms(double target_ms);
    double get_performance_target_ms() const;

    void set_constant_time_enforcement(bool enabled);
    bool is_constant_time_enforcement_enabled() const;

    // noise management
    void set_noise_threshold_for_refresh(double threshold);
    double get_noise_threshold_for_refresh() const;

    void set_auto_method_downgrade(bool enabled);
    bool is_auto_method_downgrade_enabled() const;

    // diagnostics
    void enable_timing_verification(bool enabled);
    bool is_timing_verification_enabled() const;

    void enable_performance_logging(bool enabled);
    bool is_performance_logging_enabled() const;

    struct PerformanceStatistics {
        size_t total_comparisons = 0;
        std::chrono::milliseconds total_time{0};
        std::chrono::milliseconds average_time{0};
        size_t constant_time_violations = 0;
        size_t noise_budget_violations = 0;
        std::unordered_map<ComparisonMethod, size_t> method_usage_count;
    };

    PerformanceStatistics get_performance_statistics() const;
    void reset_performance_statistics();

  private:
    ComparisonConfig() = default;

    ComparisonMethod default_method_ = ComparisonMethod::OPTIMIZED_HYBRID;
    bool adaptive_method_selection_ = true;
    double performance_target_ms_ = 50.0;
    bool constant_time_enforcement_ = true;
    double noise_threshold_for_refresh_ = 0.1;
    bool auto_method_downgrade_ = true;
    bool timing_verification_ = false;
    bool performance_logging_ = false;
    mutable PerformanceStatistics stats_;
};

// exception classes for comparison operations
class ComparisonException : public ArithmeticException {
  public:
    explicit ComparisonException(const std::string& message) : ArithmeticException(message) {}
};

class TimingViolationException : public ComparisonException {
  public:
    explicit TimingViolationException(const std::string& message) : ComparisonException(message) {}
};

class CircuitDepthException : public ComparisonException {
  public:
    explicit CircuitDepthException(const std::string& message) : ComparisonException(message) {}
};

}  // namespace cryptmalloc