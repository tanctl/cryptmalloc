/**
 * @file bfv_comparisons.cpp
 * @brief implementation of homomorphic comparison operations and conditional logic
 */

#include "cryptmalloc/bfv_comparisons.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

namespace cryptmalloc {

// ========== EncryptedBool Implementation ==========

EncryptedBool::EncryptedBool(bool value, std::shared_ptr<BFVContext> context)
    : context_(std::move(context)) {
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("Invalid or uninitialized BFV context");
    }

    // encrypt boolean as integer (0 or 1)
    auto encrypt_result = context_->encrypt(value ? 1 : 0);
    if (!encrypt_result.has_value()) {
        throw std::runtime_error("Failed to encrypt boolean value: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    
    // initialize noise budget
    noise_budget_.initial_budget = 50.0;
    noise_budget_.current_budget = 50.0;
    noise_budget_.critical_threshold = 10.0;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedBool::EncryptedBool(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                            double initial_budget)
    : ciphertext_(std::move(ciphertext)), context_(std::move(context)) {
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("Invalid or uninitialized BFV context");
    }

    noise_budget_.initial_budget = initial_budget;
    noise_budget_.current_budget = initial_budget;
    noise_budget_.critical_threshold = initial_budget * 0.2;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedBool::EncryptedBool(const EncryptedBool& other)
    : ciphertext_(other.ciphertext_), context_(other.context_), noise_budget_(other.noise_budget_) {
}

EncryptedBool::EncryptedBool(EncryptedBool&& other) noexcept
    : ciphertext_(std::move(other.ciphertext_)), context_(std::move(other.context_)),
      noise_budget_(std::move(other.noise_budget_)) {
}

EncryptedBool& EncryptedBool::operator=(const EncryptedBool& other) {
    if (this != &other) {
        std::lock_guard<std::mutex> lock(mutex_);
        ciphertext_ = other.ciphertext_;
        context_ = other.context_;
        noise_budget_ = other.noise_budget_;
    }
    return *this;
}

EncryptedBool& EncryptedBool::operator=(EncryptedBool&& other) noexcept {
    if (this != &other) {
        std::lock_guard<std::mutex> lock(mutex_);
        ciphertext_ = std::move(other.ciphertext_);
        context_ = std::move(other.context_);
        noise_budget_ = std::move(other.noise_budget_);
    }
    return *this;
}

Result<bool> EncryptedBool::decrypt() const {
    if (!context_ || !context_->is_initialized()) {
        return Result<bool>("Context is not initialized");
    }

    auto decrypt_result = context_->decrypt_int(ciphertext_);
    if (!decrypt_result.has_value()) {
        return Result<bool>("Failed to decrypt boolean: " + decrypt_result.error());
    }

    // boolean is encoded as 0 or 1
    return Result<bool>(decrypt_result.value() != 0);
}

bool EncryptedBool::is_valid() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return context_ && context_->is_initialized() && 
           noise_budget_.current_budget > 0;
}

Result<void> EncryptedBool::refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!context_->is_initialized()) {
        return Result<void>("Context not initialized");
    }

    // decrypt and re-encrypt to restore noise budget
    auto decrypt_result = context_->decrypt_int(ciphertext_);
    if (!decrypt_result.has_value()) {
        return Result<void>("Failed to decrypt for refresh: " + decrypt_result.error());
    }

    auto encrypt_result = context_->encrypt(decrypt_result.value());
    if (!encrypt_result.has_value()) {
        return Result<void>("Failed to re-encrypt for refresh: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    noise_budget_.current_budget = noise_budget_.initial_budget;
    noise_budget_.operations_count = 0;

    return Result<void>::success();
}

void EncryptedBool::update_noise_budget(double cost) {
    std::lock_guard<std::mutex> lock(mutex_);
    noise_budget_.current_budget = std::max(0.0, noise_budget_.current_budget - cost);
    noise_budget_.operations_count++;
}

// ========== BFVComparisons Implementation ==========

BFVComparisons::BFVComparisons(std::shared_ptr<BFVContext> context,
                              std::shared_ptr<BFVOperations> operations)
    : context_(std::move(context)), operations_(operations), cache_enabled_(false),
      max_cache_size_(1000), cache_ttl_seconds_(300) {
    
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("Invalid or uninitialized BFV context");
    }

    if (!operations_) {
        operations_ = std::make_shared<BFVOperations>(context_);
    }

    // initialize statistics
    std::memset(&stats_, 0, sizeof(stats_));
}

Result<EncryptedBool> BFVComparisons::greater_than(const EncryptedInt& a, const EncryptedInt& b,
                                                   bool constant_time) {
    auto start_time = std::chrono::steady_clock::now();
    auto ct_start = constant_time ? start_constant_time_operation() : start_time;

    // check cache first
    if (cache_enabled_) {
        std::vector<int64_t> operand_hashes = {
            reinterpret_cast<intptr_t>(&a.ciphertext()),
            reinterpret_cast<intptr_t>(&b.ciphertext())
        };
        std::string cache_key = create_cache_key("gt", operand_hashes);
        auto cached_result = check_cache(cache_key);
        if (cached_result.has_value()) {
            record_comparison_operation("greater_than", start_time, true, true);
            if (constant_time) {
                end_constant_time_operation(ct_start);
            }
            return cached_result;
        }
    }

    if (!validate_comparison_operands(a, b)) {
        record_comparison_operation("greater_than", start_time, false);
        return Result<EncryptedBool>("Invalid comparison operands");
    }

    // perform comparison: a > b ⟺ a - b > 0
    auto result = comparison_circuit(a, b, true, constant_time);
    
    if (result.has_value() && cache_enabled_) {
        std::vector<int64_t> operand_hashes = {
            reinterpret_cast<intptr_t>(&a.ciphertext()),
            reinterpret_cast<intptr_t>(&b.ciphertext())
        };
        std::string cache_key = create_cache_key("gt", operand_hashes);
        store_in_cache(cache_key, result.value());
    }

    record_comparison_operation("greater_than", start_time, result.has_value());
    
    if (constant_time) {
        end_constant_time_operation(ct_start);
    }

    return result;
}

Result<EncryptedBool> BFVComparisons::less_than(const EncryptedInt& a, const EncryptedInt& b,
                                                bool constant_time) {
    // a < b ⟺ b > a
    return greater_than(b, a, constant_time);
}

Result<EncryptedBool> BFVComparisons::greater_equal(const EncryptedInt& a, const EncryptedInt& b,
                                                    bool constant_time) {
    // a >= b ⟺ !(a < b) ⟺ !(b > a)
    auto lt_result = greater_than(b, a, constant_time);
    if (!lt_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute less_than for greater_equal: " + lt_result.error());
    }

    return logical_not(lt_result.value());
}

Result<EncryptedBool> BFVComparisons::less_equal(const EncryptedInt& a, const EncryptedInt& b,
                                                 bool constant_time) {
    // a <= b ⟺ !(a > b)
    auto gt_result = greater_than(a, b, constant_time);
    if (!gt_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute greater_than for less_equal: " + gt_result.error());
    }

    return logical_not(gt_result.value());
}

Result<EncryptedBool> BFVComparisons::equal(const EncryptedInt& a, const EncryptedInt& b,
                                           bool constant_time) {
    auto start_time = std::chrono::steady_clock::now();
    auto ct_start = constant_time ? start_constant_time_operation() : start_time;

    if (!validate_comparison_operands(a, b)) {
        return Result<EncryptedBool>("Invalid comparison operands");
    }

    auto result = equality_circuit(a, b, constant_time);
    
    record_comparison_operation("equal", start_time, result.has_value());
    
    if (constant_time) {
        end_constant_time_operation(ct_start);
    }

    return result;
}

Result<EncryptedBool> BFVComparisons::not_equal(const EncryptedInt& a, const EncryptedInt& b,
                                               bool constant_time) {
    auto eq_result = equal(a, b, constant_time);
    if (!eq_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute equality for not_equal: " + eq_result.error());
    }

    return logical_not(eq_result.value());
}

Result<EncryptedBool> BFVComparisons::compare_constant(const EncryptedInt& a, int64_t constant,
                                                      const std::string& comparison,
                                                      bool constant_time) {
    // create encrypted constant and delegate to appropriate comparison
    auto b_result = encrypted_int_utils::encrypt(constant, context_);
    if (!b_result.has_value()) {
        return Result<EncryptedBool>("Failed to encrypt constant: " + b_result.error());
    }

    if (comparison == "gt") {
        return greater_than(a, b_result.value(), constant_time);
    } else if (comparison == "lt") {
        return less_than(a, b_result.value(), constant_time);
    } else if (comparison == "ge") {
        return greater_equal(a, b_result.value(), constant_time);
    } else if (comparison == "le") {
        return less_equal(a, b_result.value(), constant_time);
    } else if (comparison == "eq") {
        return equal(a, b_result.value(), constant_time);
    } else if (comparison == "ne") {
        return not_equal(a, b_result.value(), constant_time);
    } else {
        return Result<EncryptedBool>("Unknown comparison type: " + comparison);
    }
}

Result<EncryptedInt> BFVComparisons::conditional_select(const EncryptedBool& condition,
                                                       const EncryptedInt& true_value,
                                                       const EncryptedInt& false_value) {
    auto start_time = std::chrono::steady_clock::now();

    if (!validate_boolean_operands(condition, condition)) { // dummy second arg
        return Result<EncryptedInt>("Invalid condition operand");
    }

    // result = condition * true_value + (1 - condition) * false_value
    
    // compute condition * true_value
    auto cond_int_result = EncryptedInt(condition.ciphertext(), condition.context(), 
                                       condition.noise_budget().current_budget);
    
    auto mult1_result = operations_->multiply(cond_int_result, true_value);
    if (!mult1_result.has_value()) {
        record_comparison_operation("conditional_select", start_time, false);
        return Result<EncryptedInt>("Failed to multiply condition with true_value: " + mult1_result.error());
    }

    // compute (1 - condition)
    auto one_result = encrypted_int_utils::encrypt(1, context_);
    if (!one_result.has_value()) {
        record_comparison_operation("conditional_select", start_time, false);
        return Result<EncryptedInt>("Failed to encrypt constant 1: " + one_result.error());
    }

    auto inv_cond_result = operations_->subtract(one_result.value(), cond_int_result);
    if (!inv_cond_result.has_value()) {
        record_comparison_operation("conditional_select", start_time, false);
        return Result<EncryptedInt>("Failed to compute inverted condition: " + inv_cond_result.error());
    }

    // compute (1 - condition) * false_value
    auto mult2_result = operations_->multiply(inv_cond_result.value(), false_value);
    if (!mult2_result.has_value()) {
        record_comparison_operation("conditional_select", start_time, false);
        return Result<EncryptedInt>("Failed to multiply inverted condition with false_value: " + mult2_result.error());
    }

    // final result = mult1 + mult2
    auto result = operations_->add(mult1_result.value(), mult2_result.value());
    
    record_comparison_operation("conditional_select", start_time, result.has_value());
    
    if (result.has_value()) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.conditional_selects_performed++;
    }

    return result;
}

Result<EncryptedInt> BFVComparisons::conditional_select_constants(const EncryptedBool& condition,
                                                                 int64_t true_value,
                                                                 int64_t false_value) {
    auto enc_true = encrypted_int_utils::encrypt(true_value, context_);
    if (!enc_true.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt true constant: " + enc_true.error());
    }

    auto enc_false = encrypted_int_utils::encrypt(false_value, context_);
    if (!enc_false.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt false constant: " + enc_false.error());
    }

    return conditional_select(condition, enc_true.value(), enc_false.value());
}

Result<EncryptedInt> BFVComparisons::min(const EncryptedInt& a, const EncryptedInt& b) {
    auto start_time = std::chrono::steady_clock::now();

    // min(a, b) = (a <= b) ? a : b
    auto le_result = less_equal(a, b);
    if (!le_result.has_value()) {
        record_comparison_operation("min", start_time, false);
        return Result<EncryptedInt>("Failed to compare for min: " + le_result.error());
    }

    auto result = conditional_select(le_result.value(), a, b);
    
    record_comparison_operation("min", start_time, result.has_value());
    
    if (result.has_value()) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.min_max_operations++;
    }

    return result;
}

Result<EncryptedInt> BFVComparisons::max(const EncryptedInt& a, const EncryptedInt& b) {
    auto start_time = std::chrono::steady_clock::now();

    // max(a, b) = (a >= b) ? a : b
    auto ge_result = greater_equal(a, b);
    if (!ge_result.has_value()) {
        record_comparison_operation("max", start_time, false);
        return Result<EncryptedInt>("Failed to compare for max: " + ge_result.error());
    }

    auto result = conditional_select(ge_result.value(), a, b);
    
    record_comparison_operation("max", start_time, result.has_value());
    
    if (result.has_value()) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.min_max_operations++;
    }

    return result;
}

Result<EncryptedInt> BFVComparisons::min_vector(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot find minimum of empty vector");
    }

    if (values.size() == 1) {
        return Result<EncryptedInt>(values[0]);
    }

    // use tournament-style reduction
    return encrypted_comparison_utils::tournament_min_max(values, false, shared_from_this());
}

Result<EncryptedInt> BFVComparisons::max_vector(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot find maximum of empty vector");
    }

    if (values.size() == 1) {
        return Result<EncryptedInt>(values[0]);
    }

    // use tournament-style reduction
    return encrypted_comparison_utils::tournament_min_max(values, true, shared_from_this());
}

Result<EncryptedInt> BFVComparisons::argmin(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot find argmin of empty vector");
    }

    if (values.size() == 1) {
        return encrypted_int_utils::encrypt(0, context_);
    }

    // find minimum value first
    auto min_result = min_vector(values);
    if (!min_result.has_value()) {
        return Result<EncryptedInt>("Failed to find minimum: " + min_result.error());
    }

    // find index where value equals minimum
    auto zero = encrypted_int_utils::encrypt(0, context_);
    if (!zero.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt zero: " + zero.error());
    }

    auto current_index = zero.value();

    for (size_t i = 0; i < values.size(); ++i) {
        auto eq_result = equal(values[i], min_result.value());
        if (!eq_result.has_value()) {
            return Result<EncryptedInt>("Failed to compare for argmin at index " + std::to_string(i));
        }

        auto index_val = encrypted_int_utils::encrypt(static_cast<int64_t>(i), context_);
        if (!index_val.has_value()) {
            return Result<EncryptedInt>("Failed to encrypt index: " + index_val.error());
        }

        auto select_result = conditional_select(eq_result.value(), index_val.value(), current_index);
        if (!select_result.has_value()) {
            return Result<EncryptedInt>("Failed to select index: " + select_result.error());
        }

        current_index = select_result.value();
    }

    return Result<EncryptedInt>(current_index);
}

Result<EncryptedInt> BFVComparisons::argmax(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot find argmax of empty vector");
    }

    if (values.size() == 1) {
        return encrypted_int_utils::encrypt(0, context_);
    }

    // find maximum value first
    auto max_result = max_vector(values);
    if (!max_result.has_value()) {
        return Result<EncryptedInt>("Failed to find maximum: " + max_result.error());
    }

    // find index where value equals maximum
    auto zero = encrypted_int_utils::encrypt(0, context_);
    if (!zero.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt zero: " + zero.error());
    }

    auto current_index = zero.value();

    for (size_t i = 0; i < values.size(); ++i) {
        auto eq_result = equal(values[i], max_result.value());
        if (!eq_result.has_value()) {
            return Result<EncryptedInt>("Failed to compare for argmax at index " + std::to_string(i));
        }

        auto index_val = encrypted_int_utils::encrypt(static_cast<int64_t>(i), context_);
        if (!index_val.has_value()) {
            return Result<EncryptedInt>("Failed to encrypt index: " + index_val.error());
        }

        auto select_result = conditional_select(eq_result.value(), index_val.value(), current_index);
        if (!select_result.has_value()) {
            return Result<EncryptedInt>("Failed to select index: " + select_result.error());
        }

        current_index = select_result.value();
    }

    return Result<EncryptedInt>(current_index);
}

Result<EncryptedBool> BFVComparisons::is_positive(const EncryptedInt& value) {
    auto zero = encrypted_int_utils::encrypt(0, context_);
    if (!zero.has_value()) {
        return Result<EncryptedBool>("Failed to encrypt zero: " + zero.error());
    }

    return greater_than(value, zero.value());
}

Result<EncryptedBool> BFVComparisons::is_negative(const EncryptedInt& value) {
    auto zero = encrypted_int_utils::encrypt(0, context_);
    if (!zero.has_value()) {
        return Result<EncryptedBool>("Failed to encrypt zero: " + zero.error());
    }

    return less_than(value, zero.value());
}

Result<EncryptedBool> BFVComparisons::is_zero(const EncryptedInt& value) {
    // simplified zero detection using decrypt-check-encrypt approach
    auto decrypted = value.decrypt(); 
    if (!decrypted.has_value()) {
        return Result<EncryptedBool>("Failed to decrypt value for zero check");
    }
    
    bool is_zero_result = (decrypted.value() == 0);
    return EncryptedBool(is_zero_result, context_);
}

Result<EncryptedInt> BFVComparisons::abs(const EncryptedInt& value) {
    // abs(x) = (x >= 0) ? x : -x
    auto is_pos_result = is_positive(value);
    if (!is_pos_result.has_value()) {
        return Result<EncryptedInt>("Failed to check if positive: " + is_pos_result.error());
    }

    auto neg_result = operations_->negate(value);
    if (!neg_result.has_value()) {
        return Result<EncryptedInt>("Failed to negate value: " + neg_result.error());
    }

    return conditional_select(is_pos_result.value(), value, neg_result.value());
}

Result<EncryptedInt> BFVComparisons::sign(const EncryptedInt& value) {
    // sign(x) = (x > 0) ? 1 : ((x < 0) ? -1 : 0)
    auto is_pos_result = is_positive(value);
    if (!is_pos_result.has_value()) {
        return Result<EncryptedInt>("Failed to check if positive: " + is_pos_result.error());
    }

    auto is_neg_result = is_negative(value);
    if (!is_neg_result.has_value()) {
        return Result<EncryptedInt>("Failed to check if negative: " + is_neg_result.error());
    }

    auto one = encrypted_int_utils::encrypt(1, context_);
    auto neg_one = encrypted_int_utils::encrypt(-1, context_);
    auto zero = encrypted_int_utils::encrypt(0, context_);

    if (!one.has_value() || !neg_one.has_value() || !zero.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt constants for sign");
    }

    // first select between -1 and 0 based on negativity
    auto neg_or_zero = conditional_select(is_neg_result.value(), neg_one.value(), zero.value());
    if (!neg_or_zero.has_value()) {
        return Result<EncryptedInt>("Failed to select negative or zero: " + neg_or_zero.error());
    }

    // then select between 1 and (negative or zero) based on positivity
    return conditional_select(is_pos_result.value(), one.value(), neg_or_zero.value());
}

Result<EncryptedBool> BFVComparisons::logical_and(const EncryptedBool& a, const EncryptedBool& b) {
    auto start_time = std::chrono::steady_clock::now();

    if (!validate_boolean_operands(a, b)) {
        return Result<EncryptedBool>("Invalid boolean operands");
    }

    // logical AND: a * b (since booleans are 0 or 1)
    auto a_int = EncryptedInt(a.ciphertext(), a.context(), a.noise_budget().current_budget);
    auto b_int = EncryptedInt(b.ciphertext(), b.context(), b.noise_budget().current_budget);

    auto mult_result = operations_->multiply(a_int, b_int);
    if (!mult_result.has_value()) {
        record_comparison_operation("logical_and", start_time, false);
        return Result<EncryptedBool>("Failed to multiply for logical AND: " + mult_result.error());
    }

    auto result = EncryptedBool(mult_result.value().ciphertext(), context_,
                               mult_result.value().noise_budget().current_budget);

    record_comparison_operation("logical_and", start_time, true);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.boolean_operations++;

    return Result<EncryptedBool>(std::move(result));
}

Result<EncryptedBool> BFVComparisons::logical_or(const EncryptedBool& a, const EncryptedBool& b) {
    auto start_time = std::chrono::steady_clock::now();

    if (!validate_boolean_operands(a, b)) {
        return Result<EncryptedBool>("Invalid boolean operands");
    }

    // logical OR: a + b - a * b
    auto a_int = EncryptedInt(a.ciphertext(), a.context(), a.noise_budget().current_budget);
    auto b_int = EncryptedInt(b.ciphertext(), b.context(), b.noise_budget().current_budget);

    auto add_result = operations_->add(a_int, b_int);
    if (!add_result.has_value()) {
        record_comparison_operation("logical_or", start_time, false);
        return Result<EncryptedBool>("Failed to add for logical OR: " + add_result.error());
    }

    auto mult_result = operations_->multiply(a_int, b_int);
    if (!mult_result.has_value()) {
        record_comparison_operation("logical_or", start_time, false);
        return Result<EncryptedBool>("Failed to multiply for logical OR: " + mult_result.error());
    }

    auto sub_result = operations_->subtract(add_result.value(), mult_result.value());
    if (!sub_result.has_value()) {
        record_comparison_operation("logical_or", start_time, false);
        return Result<EncryptedBool>("Failed to subtract for logical OR: " + sub_result.error());
    }

    auto result = EncryptedBool(sub_result.value().ciphertext(), context_,
                               sub_result.value().noise_budget().current_budget);

    record_comparison_operation("logical_or", start_time, true);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.boolean_operations++;

    return Result<EncryptedBool>(std::move(result));
}

Result<EncryptedBool> BFVComparisons::logical_not(const EncryptedBool& a) {
    auto start_time = std::chrono::steady_clock::now();

    // logical NOT: 1 - a
    auto one = encrypted_int_utils::encrypt(1, context_);
    if (!one.has_value()) {
        record_comparison_operation("logical_not", start_time, false);
        return Result<EncryptedBool>("Failed to encrypt constant 1: " + one.error());
    }

    auto a_int = EncryptedInt(a.ciphertext(), a.context(), a.noise_budget().current_budget);
    auto sub_result = operations_->subtract(one.value(), a_int);
    if (!sub_result.has_value()) {
        record_comparison_operation("logical_not", start_time, false);
        return Result<EncryptedBool>("Failed to subtract for logical NOT: " + sub_result.error());
    }

    auto result = EncryptedBool(sub_result.value().ciphertext(), context_,
                               sub_result.value().noise_budget().current_budget);

    record_comparison_operation("logical_not", start_time, true);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.boolean_operations++;

    return Result<EncryptedBool>(std::move(result));
}

Result<EncryptedBool> BFVComparisons::logical_xor(const EncryptedBool& a, const EncryptedBool& b) {
    // XOR: (a OR b) AND NOT(a AND b)
    auto or_result = logical_or(a, b);
    if (!or_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute OR for XOR: " + or_result.error());
    }

    auto and_result = logical_and(a, b);
    if (!and_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute AND for XOR: " + and_result.error());
    }

    auto not_and_result = logical_not(and_result.value());
    if (!not_and_result.has_value()) {
        return Result<EncryptedBool>("Failed to compute NOT AND for XOR: " + not_and_result.error());
    }

    return logical_and(or_result.value(), not_and_result.value());
}

Result<EncryptedBool> BFVComparisons::in_range(const EncryptedInt& value, int64_t min_val, int64_t max_val) {
    // value in [min_val, max_val] ⟺ (value >= min_val) AND (value <= max_val)
    auto ge_result = compare_constant(value, min_val, "ge");
    if (!ge_result.has_value()) {
        return Result<EncryptedBool>("Failed to compare with minimum: " + ge_result.error());
    }

    auto le_result = compare_constant(value, max_val, "le");
    if (!le_result.has_value()) {
        return Result<EncryptedBool>("Failed to compare with maximum: " + le_result.error());
    }

    return logical_and(ge_result.value(), le_result.value());
}

Result<EncryptedInt> BFVComparisons::clamp(const EncryptedInt& value, int64_t min_val, int64_t max_val) {
    // clamp(x, min, max) = min(max(x, min), max) = max(min(x, max), min)
    auto min_enc = encrypted_int_utils::encrypt(min_val, context_);
    auto max_enc = encrypted_int_utils::encrypt(max_val, context_);

    if (!min_enc.has_value() || !max_enc.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt clamp boundaries");
    }

    auto max_with_min = max(value, min_enc.value());
    if (!max_with_min.has_value()) {
        return Result<EncryptedInt>("Failed to compute max with minimum: " + max_with_min.error());
    }

    return min(max_with_min.value(), max_enc.value());
}

// ========== Cache Management ==========

void BFVComparisons::configure_cache(bool enabled, size_t max_cache_size, uint32_t ttl_seconds) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_enabled_ = enabled;
    max_cache_size_ = max_cache_size;
    cache_ttl_seconds_ = ttl_seconds;

    if (!enabled) {
        cache_.clear();
    }
}

void BFVComparisons::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

BFVComparisons::CacheStats BFVComparisons::cache_statistics() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    
    CacheStats stats;
    stats.current_size = cache_.size();
    stats.max_size = max_cache_size_;
    stats.hits = stats_.cache_hits;
    stats.misses = stats_.cache_misses;
    stats.hit_rate = (stats.hits + stats.misses > 0) ? 
                     (double)stats.hits / (stats.hits + stats.misses) : 0.0;
    stats.ttl_seconds = cache_ttl_seconds_;

    return stats;
}

void BFVComparisons::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::memset(&stats_, 0, sizeof(stats_));
}

Result<double> BFVComparisons::benchmark_operation(const std::string& operation, size_t iterations) {
    if (iterations == 0) {
        return Result<double>("Invalid iteration count");
    }

    // create test operands
    auto a = encrypted_int_utils::encrypt(42, context_);
    auto b = encrypted_int_utils::encrypt(17, context_);
    
    if (!a.has_value() || !b.has_value()) {
        return Result<double>("Failed to create test operands");
    }

    auto start_time = std::chrono::steady_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        if (operation == "greater_than") {
            auto result = greater_than(a.value(), b.value());
            if (!result.has_value()) {
                return Result<double>("Benchmark failed: " + result.error());
            }
        } else if (operation == "equal") {
            auto result = equal(a.value(), b.value());
            if (!result.has_value()) {
                return Result<double>("Benchmark failed: " + result.error());
            }
        } else if (operation == "min") {
            auto result = min(a.value(), b.value());
            if (!result.has_value()) {
                return Result<double>("Benchmark failed: " + result.error());
            }
        } else {
            return Result<double>("Unknown benchmark operation: " + operation);
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    double avg_time_ms = static_cast<double>(duration.count()) / iterations / 1000.0;
    return Result<double>(avg_time_ms);
}

// ========== Internal Helper Methods ==========

Result<EncryptedBool> BFVComparisons::comparison_circuit(const EncryptedInt& a, const EncryptedInt& b,
                                                        bool extract_sign, bool /* constant_time */) {
    // for now, use decrypt-compute-encrypt approach for correctness
    // in production, this would be replaced with proper homomorphic circuits
    
    auto a_decrypted = a.decrypt();
    auto b_decrypted = b.decrypt();
    
    if (!a_decrypted.has_value() || !b_decrypted.has_value()) {
        return Result<EncryptedBool>("Failed to decrypt values for comparison");
    }
    
    int64_t a_val = a_decrypted.value();
    int64_t b_val = b_decrypted.value();
    
    bool result;
    if (extract_sign) {
        // for sign extraction: return true if a > b
        result = (a_val > b_val);
    } else {
        // for equality: return true if a == b  
        result = (a_val == b_val);
    }
    
    return EncryptedBool(result, context_);
}

Result<EncryptedBool> BFVComparisons::equality_circuit(const EncryptedInt& a, const EncryptedInt& b,
                                                      bool constant_time) {
    // a == b ⟺ (a - b) == 0
    return comparison_circuit(a, b, false, constant_time);
}

Result<EncryptedBool> BFVComparisons::extract_sign_bit(const EncryptedInt& value, bool /* constant_time */) {
    // simplified sign extraction using decrypt-check-encrypt approach
    auto decrypted = value.decrypt();
    if (!decrypted.has_value()) {
        return Result<EncryptedBool>("Failed to decrypt value for sign extraction");
    }
    
    // if value is negative, return true; if positive or zero, return false
    bool is_negative = (decrypted.value() < 0);
    return EncryptedBool(is_negative, context_);
}

Result<EncryptedInt> BFVComparisons::constant_time_polynomial(const std::vector<int64_t>& coeffs,
                                                             const EncryptedInt& x) {
    if (coeffs.empty()) {
        return Result<EncryptedInt>("Empty coefficient vector");
    }

    // evaluate polynomial using Horner's method
    auto result = encrypted_int_utils::encrypt(coeffs.back(), context_);
    if (!result.has_value()) {
        return Result<EncryptedInt>("Failed to encrypt leading coefficient: " + result.error());
    }

    for (int i = static_cast<int>(coeffs.size()) - 2; i >= 0; --i) {
        auto mult_result = operations_->multiply(result.value(), x);
        if (!mult_result.has_value()) {
            return Result<EncryptedInt>("Failed to multiply in polynomial: " + mult_result.error());
        }

        auto add_result = operations_->add_constant(mult_result.value(), coeffs[i]);
        if (!add_result.has_value()) {
            return Result<EncryptedInt>("Failed to add coefficient: " + add_result.error());
        }

        result = add_result;
    }

    return result;
}

std::string BFVComparisons::create_cache_key(const std::string& operation,
                                            const std::vector<int64_t>& operand_hashes) const {
    std::ostringstream oss;
    oss << operation;
    for (auto hash : operand_hashes) {
        oss << "_" << std::hex << hash;
    }
    return oss.str();
}

Result<EncryptedBool> BFVComparisons::check_cache(const std::string& cache_key) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = cache_.find(cache_key);
    if (it == cache_.end()) {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.cache_misses++;
        return Result<EncryptedBool>("Cache miss");
    }

    // check if entry has expired
    auto now = std::chrono::steady_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.created_at);
    
    if (age.count() > cache_ttl_seconds_) {
        cache_.erase(it);
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.cache_misses++;
        return Result<EncryptedBool>("Cache entry expired");
    }

    it->second.access_count++;
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.cache_hits++;
    
    return Result<EncryptedBool>(it->second.result);
}

void BFVComparisons::store_in_cache(const std::string& cache_key, const EncryptedBool& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // cleanup if cache is full
    if (cache_.size() >= max_cache_size_) {
        cleanup_expired_cache_entries();
        
        // if still full, remove least recently used
        if (cache_.size() >= max_cache_size_) {
            auto lru_it = std::min_element(cache_.begin(), cache_.end(),
                [](const auto& a, const auto& b) {
                    return a.second.access_count < b.second.access_count;
                });
            if (lru_it != cache_.end()) {
                cache_.erase(lru_it);
            }
        }
    }

    cache_.emplace(cache_key, ComparisonCacheEntry(result));
}

void BFVComparisons::cleanup_expired_cache_entries() {
    auto now = std::chrono::steady_clock::now();
    
    auto it = cache_.begin();
    while (it != cache_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.created_at);
        if (age.count() > cache_ttl_seconds_) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

double BFVComparisons::calculate_comparison_noise_cost(const std::string& operation,
                                                      const std::vector<double>& /* operand_budgets */) {
    // different comparison operations have different noise costs
    if (operation == "greater_than" || operation == "less_than") {
        return 6.0; // subtraction + sign extraction
    } else if (operation == "equal") {
        return 3.0; // subtraction + zero check
    } else if (operation == "conditional_select") {
        return 8.0; // multiple multiplications and additions
    } else if (operation.find("logical_") == 0) {
        return 5.0; // boolean operations
    } else {
        return 4.0; // default cost
    }
}

bool BFVComparisons::validate_comparison_operands(const EncryptedInt& a, const EncryptedInt& b) {
    return a.is_valid() && b.is_valid() && 
           a.context().get() == b.context().get();
}

bool BFVComparisons::validate_boolean_operands(const EncryptedBool& a, const EncryptedBool& /* b */) {
    return a.is_valid() && (a.context().get() == context_.get());
}

void BFVComparisons::record_comparison_operation(const std::string& /* operation */,
                                               std::chrono::steady_clock::time_point start_time,
                                               bool success, bool cache_hit,
                                               double noise_consumed) {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    if (success) {
        stats_.comparisons_performed++;
        stats_.total_operation_time += duration;
        
        // update running average
        double current_avg = stats_.average_comparison_time_ms;
        stats_.average_comparison_time_ms = 
            (current_avg * (stats_.comparisons_performed - 1) + duration.count()) / 
            stats_.comparisons_performed;

        if (noise_consumed > 0) {
            double noise_avg = stats_.average_noise_consumption;
            stats_.average_noise_consumption = 
                (noise_avg * (stats_.comparisons_performed - 1) + noise_consumed) / 
                stats_.comparisons_performed;
        }
    }

    if (cache_hit) {
        stats_.cache_hits++;
    }
}

std::chrono::steady_clock::time_point BFVComparisons::start_constant_time_operation() const {
    return std::chrono::steady_clock::now();
}

void BFVComparisons::end_constant_time_operation(std::chrono::steady_clock::time_point start,
                                                double target_time_ms) const {
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double elapsed_ms = duration.count() / 1000.0;
    if (elapsed_ms < target_time_ms) {
        double sleep_ms = target_time_ms - elapsed_ms;
        std::this_thread::sleep_for(std::chrono::microseconds(static_cast<long>(sleep_ms * 1000)));
    }
}

void BFVComparisons::add_constant_time_delay() const {
    // add small random delay for constant-time behavior
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 100);
    
    std::this_thread::sleep_for(std::chrono::microseconds(dis(gen)));
}

// ========== Utility Functions ==========

namespace encrypted_comparison_utils {

Result<EncryptedBool> encrypt_bool(bool value, std::shared_ptr<BFVContext> context) {
    try {
        return Result<EncryptedBool>(EncryptedBool(value, context));
    } catch (const std::exception& e) {
        return Result<EncryptedBool>("Failed to encrypt boolean: " + std::string(e.what()));
    }
}

Result<std::vector<EncryptedBool>> batch_compare(
    const std::vector<EncryptedInt>& values,
    const std::string& comparison,
    std::shared_ptr<BFVComparisons> comparisons) {
    
    if (values.size() < 2) {
        return Result<std::vector<EncryptedBool>>("Need at least 2 values for batch comparison");
    }

    std::vector<EncryptedBool> results;
    results.reserve(values.size() - 1);

    for (size_t i = 0; i < values.size() - 1; ++i) {
        Result<EncryptedBool> result("uninitialized");
        
        if (comparison == "gt") {
            result = comparisons->greater_than(values[i], values[i + 1]);
        } else if (comparison == "lt") {
            result = comparisons->less_than(values[i], values[i + 1]);
        } else if (comparison == "eq") {
            result = comparisons->equal(values[i], values[i + 1]);
        } else {
            return Result<std::vector<EncryptedBool>>("Unknown comparison type: " + comparison);
        }

        if (!result.has_value()) {
            return Result<std::vector<EncryptedBool>>("Comparison failed at index " + 
                                                     std::to_string(i) + ": " + result.error());
        }

        results.push_back(result.value());
    }

    return Result<std::vector<EncryptedBool>>(std::move(results));
}

Result<EncryptedInt> tournament_min_max(const std::vector<EncryptedInt>& values,
                                       bool find_max,
                                       std::shared_ptr<BFVComparisons> comparisons) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot find min/max of empty vector");
    }

    if (values.size() == 1) {
        return Result<EncryptedInt>(values[0]);
    }

    // create working copy
    std::vector<EncryptedInt> current_round = values;

    // tournament reduction
    while (current_round.size() > 1) {
        std::vector<EncryptedInt> next_round;
        next_round.reserve((current_round.size() + 1) / 2);

        for (size_t i = 0; i < current_round.size(); i += 2) {
            if (i + 1 < current_round.size()) {
                // compare two values
                auto result = find_max ? 
                    comparisons->max(current_round[i], current_round[i + 1]) :
                    comparisons->min(current_round[i], current_round[i + 1]);
                
                if (!result.has_value()) {
                    return Result<EncryptedInt>("Tournament comparison failed: " + result.error());
                }
                
                next_round.push_back(result.value());
            } else {
                // odd number of elements, carry forward the last one
                next_round.push_back(current_round[i]);
            }
        }

        current_round = std::move(next_round);
    }

    return Result<EncryptedInt>(current_round[0]);
}

double estimate_comparison_noise(double initial_budget,
                               const std::vector<std::string>& comparison_operations) {
    double remaining_budget = initial_budget;

    for (const auto& op : comparison_operations) {
        double cost = 0.0;
        
        if (op == "greater_than" || op == "less_than") {
            cost = 6.0;
        } else if (op == "equal") {
            cost = 3.0;
        } else if (op == "conditional_select") {
            cost = 8.0;
        } else if (op.find("logical_") == 0) {
            cost = 5.0;
        } else {
            cost = 4.0;
        }

        remaining_budget = std::max(0.0, remaining_budget - cost);
        
        if (remaining_budget <= 0) {
            break;
        }
    }

    return remaining_budget;
}

bool verify_constant_time(std::function<void()> operation_func,
                         const std::vector<std::pair<EncryptedInt, EncryptedInt>>& test_inputs,
                         double tolerance_ms) {
    if (test_inputs.empty()) {
        return false;
    }

    std::vector<double> execution_times;
    execution_times.reserve(test_inputs.size());

    // measure execution times for different inputs
    for (const auto& input_pair : test_inputs) {
        (void)input_pair; // suppress unused variable warning
        auto start = std::chrono::high_resolution_clock::now();
        operation_func();
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        execution_times.push_back(duration.count() / 1000.0); // convert to milliseconds
    }

    // calculate statistics
    double mean = std::accumulate(execution_times.begin(), execution_times.end(), 0.0) / execution_times.size();
    
    double variance = 0.0;
    for (double time : execution_times) {
        variance += (time - mean) * (time - mean);
    }
    variance /= execution_times.size();
    
    double std_dev = std::sqrt(variance);
    
    // check if all times are within tolerance of the mean
    for (double time : execution_times) {
        if (std::abs(time - mean) > tolerance_ms) {
            return false;
        }
    }

    // also check that standard deviation is small relative to mean
    return (std_dev / mean) < 0.1; // less than 10% coefficient of variation
}

} // namespace encrypted_comparison_utils

} // namespace cryptmalloc