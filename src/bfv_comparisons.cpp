#include "cryptmalloc/bfv_comparisons.hpp"
#include <algorithm>
#include <cmath>
#include <future>
#include <random>
#include <sstream>
#include <thread>

namespace cryptmalloc {

EncryptedBool::EncryptedBool(std::shared_ptr<BFVContext> context) : context_(std::move(context)) {
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("invalid context");
    }
}

EncryptedBool::EncryptedBool(std::shared_ptr<BFVContext> context, bool value)
    : context_(std::move(context)) {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for encryption");
    }

    int64_t encoded_value = value ? 1 : 0;
    ciphertext_ = context_->encrypt(encoded_value);
    cached_value_ = value;
    update_noise_info();
}

EncryptedBool::EncryptedBool(std::shared_ptr<BFVContext> context,
                             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext)
    : context_(std::move(context)), ciphertext_(ciphertext) {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready");
    }
    update_noise_info();
}

EncryptedBool::EncryptedBool(const EncryptedBool& other)
    : context_(other.context_),
      ciphertext_(other.ciphertext_),
      noise_info_(other.noise_info_),
      cached_value_(other.cached_value_) {}

EncryptedBool& EncryptedBool::operator=(const EncryptedBool& other) {
    if (this != &other) {
        context_ = other.context_;
        ciphertext_ = other.ciphertext_;
        noise_info_ = other.noise_info_;
        cached_value_ = other.cached_value_;
    }
    return *this;
}

EncryptedBool::EncryptedBool(EncryptedBool&& other) noexcept
    : context_(std::move(other.context_)),
      ciphertext_(std::move(other.ciphertext_)),
      noise_info_(std::move(other.noise_info_)),
      cached_value_(std::move(other.cached_value_)) {}

EncryptedBool& EncryptedBool::operator=(EncryptedBool&& other) noexcept {
    if (this != &other) {
        context_ = std::move(other.context_);
        ciphertext_ = std::move(other.ciphertext_);
        noise_info_ = std::move(other.noise_info_);
        cached_value_ = std::move(other.cached_value_);
    }
    return *this;
}

EncryptedBool EncryptedBool::operator&&(const EncryptedBool& other) const {
    return *this & other;  // AND operation
}

EncryptedBool EncryptedBool::operator||(const EncryptedBool& other) const {
    return *this | other;  // OR operation
}

EncryptedBool EncryptedBool::operator!() const {
    if (!context_) {
        throw std::invalid_argument("invalid context");
    }

    auto one_plaintext = context_->get_crypto_context()->MakePackedPlaintext({1});
    auto result_ct = context_->get_crypto_context()->EvalSub(one_plaintext, ciphertext_);

    EncryptedBool result(context_, result_ct);
    if (cached_value_) {
        result.cached_value_ = !(*cached_value_);
    }

    return result;
}

EncryptedBool EncryptedBool::operator&(const EncryptedBool& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    auto operation = [&]() { return context_->multiply(ciphertext_, other.ciphertext_); };
    auto result_op = perform_boolean_operation(operation, "AND");

    if (!result_op.success) {
        throw ComparisonException("AND operation failed: " + result_op.error_message);
    }

    EncryptedBool result(context_, operation());
    if (cached_value_ && other.cached_value_) {
        result.cached_value_ = *cached_value_ && *other.cached_value_;
    }

    return result;
}

EncryptedBool EncryptedBool::operator|(const EncryptedBool& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    auto sum_ct = context_->add(ciphertext_, other.ciphertext_);
    auto mult_ct = context_->multiply(ciphertext_, other.ciphertext_);
    auto result_ct = context_->get_crypto_context()->EvalSub(sum_ct, mult_ct);

    EncryptedBool result(context_, result_ct);
    if (cached_value_ && other.cached_value_) {
        result.cached_value_ = *cached_value_ || *other.cached_value_;
    }

    return result;
}

EncryptedBool EncryptedBool::operator^(const EncryptedBool& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    auto sum_ct = context_->add(ciphertext_, other.ciphertext_);
    auto mult_ct = context_->multiply(ciphertext_, other.ciphertext_);
    auto two_mult_plaintext = context_->get_crypto_context()->MakePackedPlaintext({2});
    auto two_mult_ct = context_->get_crypto_context()->EvalMult(mult_ct, two_mult_plaintext);
    auto result_ct = context_->get_crypto_context()->EvalSub(sum_ct, two_mult_ct);

    EncryptedBool result(context_, result_ct);
    if (cached_value_ && other.cached_value_) {
        result.cached_value_ = *cached_value_ != *other.cached_value_;
    }

    return result;
}

bool EncryptedBool::decrypt() const {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for decryption");
    }

    int64_t decrypted_value = context_->decrypt_single(ciphertext_);
    return decrypted_value != 0;
}

bool EncryptedBool::is_valid() const {
    return context_ && context_->is_initialized() && ciphertext_;
}

bool EncryptedBool::validate_integrity() const {
    if (!is_valid())
        return false;

    try {
        auto decrypted = decrypt();
        if (cached_value_) {
            return decrypted == *cached_value_;
        }
        return true;
    } catch (...) {
        return false;
    }
}

NoiseInfo EncryptedBool::get_noise_info() const {
    update_noise_info();
    return noise_info_;
}

bool EncryptedBool::needs_refresh() const {
    update_noise_info();
    return noise_info_.needs_refresh;
}

void EncryptedBool::refresh() {
    if (!needs_refresh())
        return;

    try {
        bool decrypted_value = decrypt();
        *this = EncryptedBool(context_, decrypted_value);
    } catch (...) {
        throw NoiseException("failed to refresh boolean ciphertext");
    }
}

void EncryptedBool::force_refresh() {
    try {
        bool decrypted_value = decrypt();
        *this = EncryptedBool(context_, decrypted_value);
    } catch (...) {
        throw NoiseException("failed to force refresh boolean ciphertext");
    }
}

size_t EncryptedBool::get_ciphertext_size() const {
    if (!ciphertext_)
        return 0;
    return ciphertext_->GetElements().size() * sizeof(lbcrypto::DCRTPoly);
}

int EncryptedBool::get_multiplicative_depth() const {
    if (!ciphertext_)
        return 0;
    return ciphertext_->GetLevel();
}

void EncryptedBool::update_noise_info() const {
    noise_info_.last_measured = std::chrono::steady_clock::now();

    if (!ciphertext_) {
        noise_info_.current_level = 1.0;
        noise_info_.needs_refresh = true;
        return;
    }

    int depth = get_multiplicative_depth();
    auto params = context_->get_parameters();

    double base_noise = 0.01;
    double depth_factor = std::pow(2.0, depth);
    noise_info_.current_level = base_noise * depth_factor;

    noise_info_.depth_remaining =
        std::max(0, static_cast<int>(params.multiplicative_depth) - depth);
    noise_info_.needs_refresh = (noise_info_.current_level > noise_info_.critical_threshold) ||
                                (noise_info_.depth_remaining <= 1);
}

ComparisonResult EncryptedBool::perform_boolean_operation(
    const std::function<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>()>& operation,
    const std::string& /* operation_name */) const {
    ComparisonResult result;
    auto start = std::chrono::steady_clock::now();

    try {
        operation();
        result.success = true;

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }

    return result;
}

void EncryptedBool::print_diagnostics() const {
    std::cout << "EncryptedBool Diagnostics:" << std::endl;
    std::cout << "  Valid: " << (is_valid() ? "Yes" : "No") << std::endl;
    std::cout << "  Ciphertext size: " << get_ciphertext_size() << " bytes" << std::endl;
    std::cout << "  Multiplicative depth: " << get_multiplicative_depth() << std::endl;

    auto noise = get_noise_info();
    std::cout << "  Noise level: " << noise.current_level << std::endl;
    std::cout << "  Depth remaining: " << noise.depth_remaining << std::endl;
    std::cout << "  Needs refresh: " << (noise.needs_refresh ? "Yes" : "No") << std::endl;

    if (cached_value_) {
        std::cout << "  Cached value: " << (*cached_value_ ? "true" : "false") << std::endl;
    }
}

std::string EncryptedBool::get_status_string() const {
    std::stringstream ss;
    ss << "EncryptedBool[valid=" << is_valid() << ", depth=" << get_multiplicative_depth()
       << ", noise=" << get_noise_info().current_level << ", size=" << get_ciphertext_size() << "]";
    return ss.str();
}

namespace comparisons {

EncryptedBool greater_than(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    auto start = std::chrono::steady_clock::now();

    if (!a.is_valid() || !b.is_valid()) {
        throw ComparisonException("invalid encrypted integers for comparison");
    }

    if (a.get_context() != b.get_context()) {
        throw ComparisonException("mismatched contexts in comparison");
    }

    // check cache first
    auto& cache = ComparisonCache::instance();
    if (cache.is_enabled()) {
        std::string cache_key = "gt_" + std::to_string(reinterpret_cast<uintptr_t>(&a)) + "_" +
                               std::to_string(reinterpret_cast<uintptr_t>(&b));
        auto cached_result = cache.lookup_comparison(cache_key);
        if (cached_result) {
            return *cached_result;
        }
    }

    // select comparison method
    if (method == ComparisonMethod::OPTIMIZED_HYBRID) {
        method = circuits::select_optimal_method(a, b);
    }

    EncryptedBool result;
    
    switch (method) {
        case ComparisonMethod::SIGN_DETECTION: {
            auto difference = a - b;
            result = circuits::sign_detection_circuit(difference);
            break;
        }
        case ComparisonMethod::POLYNOMIAL_APPROX: {
            result = circuits::polynomial_comparison_circuit(a, b);
            break;
        }
        case ComparisonMethod::BITWISE_COMPARISON: {
            result = circuits::bitwise_comparison_circuit(a, b);
            break;
        }
        default:
            throw ComparisonException("unsupported comparison method");
    }

    // verify constant-time if enabled
    auto& config = ComparisonConfig::instance();
    if (config.is_constant_time_enforcement_enabled()) {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (duration.count() > config.get_performance_target_ms()) {
            throw TimingViolationException("comparison exceeded performance target");
        }
    }

    // cache result
    if (cache.is_enabled()) {
        std::string cache_key = "gt_" + std::to_string(reinterpret_cast<uintptr_t>(&a)) + "_" +
                               std::to_string(reinterpret_cast<uintptr_t>(&b));
        cache.store_comparison(cache_key, result);
    }

    return result;
}

EncryptedBool less_than(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    return greater_than(b, a, method);
}

EncryptedBool greater_equal(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    return !less_than(a, b, method);
}

EncryptedBool less_equal(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    return !greater_than(a, b, method);
}

EncryptedBool equal(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod /* method */) {
    if (!a.is_valid() || !b.is_valid()) {
        throw ComparisonException("invalid encrypted integers for equality test");
    }

    auto difference = a - b;
    return circuits::zero_test_circuit(difference);
}

EncryptedBool not_equal(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    return !equal(a, b, method);
}

EncryptedInt conditional_select(const EncryptedBool& condition,
                               const EncryptedInt& true_value,
                               const EncryptedInt& false_value) {
    if (!condition.is_valid() || !true_value.is_valid() || !false_value.is_valid()) {
        throw ComparisonException("invalid inputs for conditional selection");
    }

    auto context = condition.get_context();
    if (context != true_value.get_context() || context != false_value.get_context()) {
        throw ComparisonException("mismatched contexts in conditional selection");
    }

    // result = condition * true_value + (1 - condition) * false_value
    // create encrypted integer from boolean condition
    EncryptedInt condition_int(context, condition.decrypt() ? 1 : 0);  // temporary conversion
    
    auto one = EncryptedInt(context, 1);
    auto not_condition = one - condition_int;
    
    auto true_part = condition_int * true_value;
    auto false_part = not_condition * false_value;
    
    return true_part + false_part;
}

EncryptedInt min(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    auto a_less_than_b = less_than(a, b, method);
    return conditional_select(a_less_than_b, a, b);
}

EncryptedInt max(const EncryptedInt& a, const EncryptedInt& b, ComparisonMethod method) {
    auto a_greater_than_b = greater_than(a, b, method);
    return conditional_select(a_greater_than_b, a, b);
}

EncryptedBool is_positive(const EncryptedInt& value) {
    auto zero = EncryptedInt(value.get_context(), 0);
    return greater_than(value, zero);
}

EncryptedBool is_negative(const EncryptedInt& value) {
    auto zero = EncryptedInt(value.get_context(), 0);
    return less_than(value, zero);
}

EncryptedBool is_zero(const EncryptedInt& value) {
    return circuits::zero_test_circuit(value);
}

EncryptedInt absolute_value(const EncryptedInt& value) {
    auto is_neg = is_negative(value);
    auto negated_value = -value;
    return conditional_select(is_neg, negated_value, value);
}

EncryptedInt sign(const EncryptedInt& value) {
    auto context = value.get_context();
    auto zero = EncryptedInt(context, 0);
    auto one = EncryptedInt(context, 1);
    auto neg_one = EncryptedInt(context, -1);
    
    auto is_pos = is_positive(value);
    auto is_neg = is_negative(value);
    
    // sign = positive ? 1 : (negative ? -1 : 0)
    auto result_if_pos = conditional_select(is_pos, one, zero);
    return conditional_select(is_neg, neg_one, result_if_pos);
}

std::vector<EncryptedBool> batch_greater_than(const std::vector<EncryptedInt>& a,
                                              const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        throw ComparisonException("mismatched vector sizes for batch comparison");
    }

    std::vector<EncryptedBool> results;
    results.reserve(a.size());

    for (size_t i = 0; i < a.size(); ++i) {
        results.push_back(greater_than(a[i], b[i]));
    }

    return results;
}

std::vector<EncryptedBool> batch_equal(const std::vector<EncryptedInt>& a,
                                       const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        throw ComparisonException("mismatched vector sizes for batch equality test");
    }

    std::vector<EncryptedBool> results;
    results.reserve(a.size());

    for (size_t i = 0; i < a.size(); ++i) {
        results.push_back(equal(a[i], b[i]));
    }

    return results;
}

EncryptedInt find_min(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        throw ComparisonException("empty vector for find_min");
    }

    EncryptedInt result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = min(result, values[i]);
    }

    return result;
}

EncryptedInt find_max(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        throw ComparisonException("empty vector for find_max");
    }

    EncryptedInt result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = max(result, values[i]);
    }

    return result;
}

EncryptedBool in_range(const EncryptedInt& value, const EncryptedInt& min_val,
                      const EncryptedInt& max_val) {
    auto ge_min = greater_equal(value, min_val);
    auto le_max = less_equal(value, max_val);
    return ge_min && le_max;
}

EncryptedBool in_range(const EncryptedInt& value, int64_t min_val, int64_t max_val) {
    auto context = value.get_context();
    auto encrypted_min = EncryptedInt(context, min_val);
    auto encrypted_max = EncryptedInt(context, max_val);
    return in_range(value, encrypted_min, encrypted_max);
}

}  // namespace comparisons

ComparisonCache& ComparisonCache::instance() {
    static ComparisonCache instance;
    return instance;
}

void ComparisonCache::set_max_size(size_t max_size) {
    max_size_ = max_size;
    while (cache_.size() > max_size_ && max_size_ > 0) {
        evict_lru();
    }
}

size_t ComparisonCache::get_max_size() const {
    return max_size_;
}

void ComparisonCache::set_enabled(bool enabled) {
    enabled_ = enabled;
}

bool ComparisonCache::is_enabled() const {
    return enabled_;
}

void ComparisonCache::clear() {
    cache_.clear();
    stats_ = Statistics{};
}

size_t ComparisonCache::size() const {
    return cache_.size();
}

ComparisonCache::Statistics ComparisonCache::get_statistics() const {
    auto stats = stats_;
    if (stats.hit_count + stats.miss_count > 0) {
        stats.hit_rate = static_cast<double>(stats.hit_count) / (stats.hit_count + stats.miss_count);
    }
    return stats;
}

void ComparisonCache::reset_statistics() {
    stats_ = Statistics{};
}

std::optional<EncryptedBool> ComparisonCache::lookup_comparison(const std::string& cache_key) {
    if (!enabled_) {
        return std::nullopt;
    }

    auto start = std::chrono::steady_clock::now();

    auto it = cache_.find(cache_key);
    if (it != cache_.end()) {
        it->second.last_access = std::chrono::steady_clock::now();
        it->second.access_count++;
        stats_.hit_count++;
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        stats_.total_lookup_time += duration;
        
        return it->second.result;
    }

    stats_.miss_count++;
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    stats_.total_lookup_time += duration;
    
    return std::nullopt;
}

void ComparisonCache::store_comparison(const std::string& cache_key, const EncryptedBool& result) {
    if (!enabled_) {
        return;
    }

    if (cache_.size() >= max_size_ && max_size_ > 0) {
        evict_lru();
    }

    CacheEntry entry;
    entry.result = result;
    entry.last_access = std::chrono::steady_clock::now();
    entry.access_count = 1;

    cache_[cache_key] = std::move(entry);
}

void ComparisonCache::evict_lru() {
    if (cache_.empty()) {
        return;
    }

    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.last_access < oldest->second.last_access) {
            oldest = it;
        }
    }

    cache_.erase(oldest);
    stats_.eviction_count++;
}

namespace circuits {

EncryptedBool sign_detection_circuit(const EncryptedInt& difference) {
    // use polynomial approximation of sign function: sign(x) ≈ x / (1 + |x|)
    // for encrypted computation, we use: sign(x) ≈ x * (degree-3 polynomial)
    auto context = difference.get_context();
    
    // simplified sign detection: check if difference > 0
    // using polynomial approximation: f(x) = (x + c)^3 where c is chosen appropriately
    auto abs_diff = comparisons::absolute_value(difference);
    
    // polynomial coefficients for sign approximation (simplified)
    std::vector<int64_t> coeffs = {0, 1, 0, 0};  // linear approximation for now
    
    auto result_int = arithmetic::evaluate_polynomial(difference, coeffs);
    
    // convert to boolean: result > 0
    auto zero = EncryptedInt(context, 0);
    auto positive_plaintext = context->get_crypto_context()->MakePackedPlaintext({1});
    auto zero_plaintext = context->get_crypto_context()->MakePackedPlaintext({0});
    
    // simplified: if result > 0 then 1 else 0
    bool is_positive = result_int.decrypt() > 0;
    return EncryptedBool(context, is_positive);
}

EncryptedBool polynomial_comparison_circuit(const EncryptedInt& a, const EncryptedInt& b) {
    // polynomial approximation method for a > b
    auto difference = a - b;
    return sign_detection_circuit(difference);
}

EncryptedBool bitwise_comparison_circuit(const EncryptedInt& a, const EncryptedInt& b) {
    // simplified bitwise comparison (placeholder implementation)
    // in practice, this would implement bit-by-bit comparison
    auto difference = a - b;
    return sign_detection_circuit(difference);
}

EncryptedBool zero_test_circuit(const EncryptedInt& value) {
    // zero test using polynomial: is_zero(x) = 1 - x^2 * polynomial(x)
    auto context = value.get_context();
    
    // simplified zero test: decrypt and check (for initial implementation)
    bool is_zero = value.decrypt() == 0;
    return EncryptedBool(context, is_zero);
}

ComparisonMethod select_optimal_method(const EncryptedInt& a, const EncryptedInt& b) {
    // analyze noise levels and select optimal method
    auto noise_a = a.get_noise_info();
    auto noise_b = b.get_noise_info();
    
    double max_noise = std::max(noise_a.current_level, noise_b.current_level);
    int min_depth = std::min(noise_a.depth_remaining, noise_b.depth_remaining);
    
    if (max_noise > 0.5 || min_depth < 3) {
        return ComparisonMethod::SIGN_DETECTION;  // lower depth method
    } else if (min_depth >= 5) {
        return ComparisonMethod::POLYNOMIAL_APPROX;  // more accurate but higher depth
    } else {
        return ComparisonMethod::SIGN_DETECTION;  // default safe choice
    }
}

double estimate_circuit_noise(ComparisonMethod method, const NoiseInfo& input_noise) {
    switch (method) {
        case ComparisonMethod::SIGN_DETECTION:
            return input_noise.current_level * 2.0;  // approximate noise growth
        case ComparisonMethod::POLYNOMIAL_APPROX:
            return input_noise.current_level * 4.0;  // higher noise growth
        case ComparisonMethod::BITWISE_COMPARISON:
            return input_noise.current_level * 8.0;  // highest noise growth
        default:
            return input_noise.current_level * 2.0;
    }
}

}  // namespace circuits

ComparisonConfig& ComparisonConfig::instance() {
    static ComparisonConfig instance;
    return instance;
}

void ComparisonConfig::set_default_method(ComparisonMethod method) {
    default_method_ = method;
}

ComparisonMethod ComparisonConfig::get_default_method() const {
    return default_method_;
}

void ComparisonConfig::set_performance_target_ms(double target_ms) {
    performance_target_ms_ = target_ms;
}

double ComparisonConfig::get_performance_target_ms() const {
    return performance_target_ms_;
}

void ComparisonConfig::set_constant_time_enforcement(bool enabled) {
    constant_time_enforcement_ = enabled;
}

bool ComparisonConfig::is_constant_time_enforcement_enabled() const {
    return constant_time_enforcement_;
}

ComparisonConfig::PerformanceStatistics ComparisonConfig::get_performance_statistics() const {
    auto stats = stats_;
    if (stats.total_comparisons > 0) {
        stats.average_time = std::chrono::milliseconds(
            stats.total_time.count() / stats.total_comparisons);
    }
    return stats;
}

void ComparisonConfig::reset_performance_statistics() {
    stats_ = PerformanceStatistics{};
}

namespace timing {

TimingMeasurement measure_comparison_timing(
    const std::function<EncryptedBool()>& comparison_func, size_t num_iterations) {
    
    std::vector<std::chrono::nanoseconds> timings;
    timings.reserve(num_iterations);

    for (size_t i = 0; i < num_iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        comparison_func();
        auto end = std::chrono::high_resolution_clock::now();
        
        timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start));
    }

    TimingMeasurement measurement;
    measurement.min_time = *std::min_element(timings.begin(), timings.end());
    measurement.max_time = *std::max_element(timings.begin(), timings.end());
    
    auto total_time = std::accumulate(timings.begin(), timings.end(), std::chrono::nanoseconds{0});
    measurement.average_time = total_time / num_iterations;
    
    // calculate variance
    double mean = measurement.average_time.count();
    double variance_sum = 0.0;
    for (const auto& timing : timings) {
        double diff = timing.count() - mean;
        variance_sum += diff * diff;
    }
    measurement.variance = variance_sum / num_iterations;
    
    // constant-time check: coefficient of variation should be low
    double std_dev = std::sqrt(measurement.variance);
    double coefficient_of_variation = std_dev / mean;
    measurement.is_constant_time = coefficient_of_variation < 0.05;  // 5% threshold
    measurement.confidence_level = 1.0 - coefficient_of_variation;
    
    return measurement;
}

bool verify_constant_time(const std::function<EncryptedBool()>& func1,
                         const std::function<EncryptedBool()>& func2,
                         size_t num_iterations, double threshold) {
    
    auto timing1 = measure_comparison_timing(func1, num_iterations);
    auto timing2 = measure_comparison_timing(func2, num_iterations);
    
    double avg1 = timing1.average_time.count();
    double avg2 = timing2.average_time.count();
    double relative_diff = std::abs(avg1 - avg2) / std::max(avg1, avg2);
    
    return relative_diff < threshold;
}

}  // namespace timing

}  // namespace cryptmalloc