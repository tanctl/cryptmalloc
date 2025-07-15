#include "cryptmalloc/bfv_operations.hpp"
#include <algorithm>
#include <cmath>
#include <future>
#include <limits>
#include <sstream>
#include <thread>

namespace cryptmalloc {

EncryptedInt::EncryptedInt(std::shared_ptr<BFVContext> context) : context_(std::move(context)) {
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("invalid context");
    }
}

EncryptedInt::EncryptedInt(std::shared_ptr<BFVContext> context, int64_t value)
    : context_(std::move(context)) {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for encryption");
    }

    // check for overflow
    auto params = context_->get_parameters();
    int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;
    int64_t min_safe = -max_safe;

    if (value < min_safe || value > max_safe) {
        if (ArithmeticConfig::instance().get_overflow_behavior() ==
            OverflowBehavior::THROW_EXCEPTION) {
            throw OverflowException("value exceeds safe range for encryption");
        }
        // apply overflow behavior
        switch (ArithmeticConfig::instance().get_overflow_behavior()) {
            case OverflowBehavior::WRAP_AROUND:
                value = ((value % params.plaintext_modulus) + params.plaintext_modulus) %
                        params.plaintext_modulus;
                if (value > max_safe)
                    value -= params.plaintext_modulus;
                break;
            case OverflowBehavior::SATURATE:
                value = std::clamp(value, min_safe, max_safe);
                break;
            case OverflowBehavior::IGNORE:
                break;
            default:
                break;
        }
    }

    ciphertext_ = context_->encrypt(value);
    cached_value_ = value;
    update_noise_info();
}

EncryptedInt::EncryptedInt(std::shared_ptr<BFVContext> context,
                           const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext)
    : context_(std::move(context)), ciphertext_(ciphertext) {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready");
    }
    update_noise_info();
}

EncryptedInt::EncryptedInt(const EncryptedInt& other)
    : context_(other.context_),
      ciphertext_(other.ciphertext_),
      noise_info_(other.noise_info_),
      cached_value_(other.cached_value_) {}

EncryptedInt& EncryptedInt::operator=(const EncryptedInt& other) {
    if (this != &other) {
        context_ = other.context_;
        ciphertext_ = other.ciphertext_;
        noise_info_ = other.noise_info_;
        cached_value_ = other.cached_value_;
    }
    return *this;
}

EncryptedInt::EncryptedInt(EncryptedInt&& other) noexcept
    : context_(std::move(other.context_)),
      ciphertext_(std::move(other.ciphertext_)),
      noise_info_(std::move(other.noise_info_)),
      cached_value_(std::move(other.cached_value_)) {}

EncryptedInt& EncryptedInt::operator=(EncryptedInt&& other) noexcept {
    if (this != &other) {
        context_ = std::move(other.context_);
        ciphertext_ = std::move(other.ciphertext_);
        noise_info_ = std::move(other.noise_info_);
        cached_value_ = std::move(other.cached_value_);
    }
    return *this;
}

EncryptedInt EncryptedInt::operator+(const EncryptedInt& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    auto operation = [&]() { return context_->add(ciphertext_, other.ciphertext_); };
    auto result_op = perform_operation(operation, "addition");

    if (!result_op.success) {
        throw ArithmeticException("addition failed: " + result_op.error_message);
    }

    EncryptedInt result(context_, operation());

    // update cached value for debugging
    if (cached_value_ && other.cached_value_) {
        try {
            result.cached_value_ = *cached_value_ + *other.cached_value_;
            check_overflow_protection(result.cached_value_.value(),
                                      cached_value_.value(),
                                      other.cached_value_.value(),
                                      '+');
        } catch (...) {
            result.cached_value_.reset();  // clear on overflow
        }
    }

    return result;
}

EncryptedInt EncryptedInt::operator-(const EncryptedInt& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    auto neg_other = -other;
    return *this + neg_other;
}

EncryptedInt EncryptedInt::operator*(const EncryptedInt& other) const {
    if (!context_ || context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    // check noise levels before multiplication
    if (needs_refresh() || other.needs_refresh()) {
        if (ArithmeticConfig::instance().get_auto_refresh()) {
            const_cast<EncryptedInt*>(this)->refresh();
            const_cast<EncryptedInt*>(&other)->refresh();
        } else {
            throw NoiseException("noise level too high for multiplication");
        }
    }

    auto operation = [&]() { return context_->multiply(ciphertext_, other.ciphertext_); };
    auto result_op = perform_operation(operation, "multiplication");

    if (!result_op.success) {
        throw ArithmeticException("multiplication failed: " + result_op.error_message);
    }

    EncryptedInt result(context_, operation());

    // update cached value
    if (cached_value_ && other.cached_value_) {
        try {
            result.cached_value_ = *cached_value_ * *other.cached_value_;
            check_overflow_protection(result.cached_value_.value(),
                                      cached_value_.value(),
                                      other.cached_value_.value(),
                                      '*');
        } catch (...) {
            result.cached_value_.reset();
        }
    }

    return result;
}

EncryptedInt EncryptedInt::operator-() const {
    if (!context_) {
        throw std::invalid_argument("invalid context");
    }

    // negate by multiplying with -1
    return *this * (-1);
}

EncryptedInt& EncryptedInt::operator+=(const EncryptedInt& other) {
    *this = *this + other;
    return *this;
}

EncryptedInt& EncryptedInt::operator-=(const EncryptedInt& other) {
    *this = *this - other;
    return *this;
}

EncryptedInt& EncryptedInt::operator*=(const EncryptedInt& other) {
    *this = *this * other;
    return *this;
}

EncryptedInt EncryptedInt::operator+(int64_t value) const {
    if (!context_) {
        throw std::invalid_argument("invalid context");
    }

    auto plaintext = context_->get_crypto_context()->MakePackedPlaintext({value});
    auto result_ct = context_->get_crypto_context()->EvalAdd(ciphertext_, plaintext);

    EncryptedInt result(context_, result_ct);

    // update cached value
    if (cached_value_) {
        try {
            result.cached_value_ = *cached_value_ + value;
            check_overflow_protection(
                result.cached_value_.value(), cached_value_.value(), value, '+');
        } catch (...) {
            result.cached_value_.reset();
        }
    }

    return result;
}

EncryptedInt EncryptedInt::operator-(int64_t value) const {
    return *this + (-value);
}

EncryptedInt EncryptedInt::operator*(int64_t value) const {
    if (!context_) {
        throw std::invalid_argument("invalid context");
    }

    auto plaintext = context_->get_crypto_context()->MakePackedPlaintext({value});
    auto result_ct = context_->get_crypto_context()->EvalMult(ciphertext_, plaintext);

    EncryptedInt result(context_, result_ct);

    if (cached_value_) {
        try {
            result.cached_value_ = *cached_value_ * value;
            check_overflow_protection(
                result.cached_value_.value(), cached_value_.value(), value, '*');
        } catch (...) {
            result.cached_value_.reset();
        }
    }

    return result;
}

EncryptedInt& EncryptedInt::operator+=(int64_t value) {
    *this = *this + value;
    return *this;
}

EncryptedInt& EncryptedInt::operator-=(int64_t value) {
    *this = *this - value;
    return *this;
}

EncryptedInt& EncryptedInt::operator*=(int64_t value) {
    *this = *this * value;
    return *this;
}

int64_t EncryptedInt::decrypt() const {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for decryption");
    }

    return context_->decrypt_single(ciphertext_);
}

bool EncryptedInt::is_valid() const {
    return context_ && context_->is_initialized() && ciphertext_;
}

bool EncryptedInt::validate_integrity() const {
    if (!is_valid())
        return false;

    try {
        // attempt decryption as integrity check
        auto decrypted = decrypt();

        // if we have cached value, verify consistency
        if (cached_value_) {
            return decrypted == *cached_value_;
        }

        return true;
    } catch (...) {
        return false;
    }
}

NoiseInfo EncryptedInt::get_noise_info() const {
    update_noise_info();
    return noise_info_;
}

bool EncryptedInt::needs_refresh() const {
    update_noise_info();
    return noise_info_.needs_refresh;
}

void EncryptedInt::refresh() {
    if (!needs_refresh())
        return;

    // for BFV, refresh means re-encrypting the value
    try {
        auto decrypted_value = decrypt();
        *this = EncryptedInt(context_, decrypted_value);
        ArithmeticConfig::instance().get_statistics();  // update refresh count
    } catch (...) {
        throw NoiseException("failed to refresh ciphertext");
    }
}

void EncryptedInt::force_refresh() {
    try {
        auto decrypted_value = decrypt();
        *this = EncryptedInt(context_, decrypted_value);
    } catch (...) {
        throw NoiseException("failed to force refresh ciphertext");
    }
}

size_t EncryptedInt::get_ciphertext_size() const {
    if (!ciphertext_)
        return 0;
    // approximate size calculation
    return ciphertext_->GetElements().size() * sizeof(lbcrypto::DCRTPoly);
}

int EncryptedInt::get_multiplicative_depth() const {
    if (!ciphertext_)
        return 0;
    return ciphertext_->GetLevel();
}

void EncryptedInt::update_noise_info() const {
    noise_info_.last_measured = std::chrono::steady_clock::now();

    if (!ciphertext_) {
        noise_info_.current_level = 1.0;  // invalid
        noise_info_.needs_refresh = true;
        return;
    }

    // estimate noise level based on depth and operations
    int depth = get_multiplicative_depth();
    auto params = context_->get_parameters();

    // rough noise estimation (in practice would use OpenFHE's noise estimation)
    double base_noise = 0.01;
    double depth_factor = std::pow(2.0, depth);
    noise_info_.current_level = base_noise * depth_factor;

    noise_info_.depth_remaining =
        std::max(0, static_cast<int>(params.multiplicative_depth) - depth);
    noise_info_.needs_refresh = (noise_info_.current_level > noise_info_.critical_threshold) ||
                                (noise_info_.depth_remaining <= 1);
}

void EncryptedInt::check_overflow_protection(int64_t result, int64_t a, int64_t b, char op) const {
    auto params = context_->get_parameters();
    int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;
    int64_t min_safe = -max_safe;

    bool overflow = false;

    switch (op) {
        case '+':
            overflow = (b > 0 && a > max_safe - b) || (b < 0 && a < min_safe - b);
            break;
        case '*':
            if (b != 0) {
                overflow = (result / b != a) || (result < min_safe) || (result > max_safe);
            }
            break;
        default:
            break;
    }

    if (overflow) {
        switch (ArithmeticConfig::instance().get_overflow_behavior()) {
            case OverflowBehavior::THROW_EXCEPTION:
                throw OverflowException("arithmetic overflow detected");
            case OverflowBehavior::WRAP_AROUND:
                // handled in operation
                break;
            case OverflowBehavior::SATURATE:
                // handled in operation
                break;
            case OverflowBehavior::IGNORE:
                break;
        }
    }
}

OperationResult EncryptedInt::perform_operation(
    const std::function<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>()>& operation,
    const std::string& /* operation_name */) const {
    OperationResult result;
    auto start = std::chrono::steady_clock::now();

    try {
        operation();  // execute operation
        result.success = true;

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        // update statistics
        // auto stats = ArithmeticConfig::instance().get_statistics();

    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }

    return result;
}

void EncryptedInt::print_diagnostics() const {
    std::cout << "EncryptedInt Diagnostics:" << std::endl;
    std::cout << "  Valid: " << (is_valid() ? "Yes" : "No") << std::endl;
    std::cout << "  Ciphertext size: " << get_ciphertext_size() << " bytes" << std::endl;
    std::cout << "  Multiplicative depth: " << get_multiplicative_depth() << std::endl;

    auto noise = get_noise_info();
    std::cout << "  Noise level: " << noise.current_level << std::endl;
    std::cout << "  Depth remaining: " << noise.depth_remaining << std::endl;
    std::cout << "  Needs refresh: " << (noise.needs_refresh ? "Yes" : "No") << std::endl;

    if (cached_value_) {
        std::cout << "  Cached value: " << *cached_value_ << std::endl;
    }
}

std::string EncryptedInt::get_status_string() const {
    std::stringstream ss;
    ss << "EncryptedInt[valid=" << is_valid() << ", depth=" << get_multiplicative_depth()
       << ", noise=" << get_noise_info().current_level << ", size=" << get_ciphertext_size() << "]";
    return ss.str();
}

EncryptedBatch::EncryptedBatch(std::shared_ptr<BFVContext> context)
    : context_(std::move(context)), batch_size_(0) {
    if (!context_ || !context_->is_initialized()) {
        throw std::invalid_argument("invalid context");
    }
}

EncryptedBatch::EncryptedBatch(std::shared_ptr<BFVContext> context,
                               const std::vector<int64_t>& values)
    : context_(std::move(context)), batch_size_(values.size()) {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for encryption");
    }

    ciphertext_ = context_->encrypt(values);
    update_noise_info();
}

EncryptedBatch EncryptedBatch::operator+(const EncryptedBatch& other) const {
    if (context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    EncryptedBatch result(context_);
    result.ciphertext_ = context_->add(ciphertext_, other.ciphertext_);
    result.batch_size_ = std::max(batch_size_, other.batch_size_);
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::operator-(const EncryptedBatch& other) const {
    if (context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    // subtract by adding negation
    EncryptedBatch result(context_);
    auto neg_plaintext = context_->get_crypto_context()->MakePackedPlaintext({-1});
    auto neg_other = context_->get_crypto_context()->EvalMult(other.ciphertext_, neg_plaintext);

    result.ciphertext_ = context_->add(ciphertext_, neg_other);
    result.batch_size_ = std::max(batch_size_, other.batch_size_);
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::operator*(const EncryptedBatch& other) const {
    if (context_ != other.context_) {
        throw std::invalid_argument("mismatched contexts");
    }

    EncryptedBatch result(context_);
    result.ciphertext_ = context_->multiply(ciphertext_, other.ciphertext_);
    result.batch_size_ = std::max(batch_size_, other.batch_size_);
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::operator+(int64_t scalar) const {
    EncryptedBatch result(context_);
    std::vector<int64_t> scalar_vector(batch_size_, scalar);
    auto plaintext = context_->get_crypto_context()->MakePackedPlaintext(scalar_vector);
    result.ciphertext_ = context_->get_crypto_context()->EvalAdd(ciphertext_, plaintext);
    result.batch_size_ = batch_size_;
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::operator*(int64_t scalar) const {
    EncryptedBatch result(context_);
    std::vector<int64_t> scalar_vector(batch_size_, scalar);
    auto plaintext = context_->get_crypto_context()->MakePackedPlaintext(scalar_vector);
    result.ciphertext_ = context_->get_crypto_context()->EvalMult(ciphertext_, plaintext);
    result.batch_size_ = batch_size_;
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::rotate_left(int32_t positions) const {
    EncryptedBatch result(context_);
    result.ciphertext_ = context_->rotate(ciphertext_, positions);
    result.batch_size_ = batch_size_;
    result.update_noise_info();

    return result;
}

EncryptedBatch EncryptedBatch::rotate_right(int32_t positions) const {
    return rotate_left(-positions);
}

EncryptedInt EncryptedBatch::sum() const {
    if (batch_size_ <= 1) {
        return EncryptedInt(context_, ciphertext_);
    }

    // use rotation and addition to compute sum
    auto result_ct = ciphertext_;

    for (int32_t step = 1; step < static_cast<int32_t>(batch_size_); step *= 2) {
        auto rotated = context_->rotate(result_ct, step);
        result_ct = context_->add(result_ct, rotated);
    }

    return EncryptedInt(context_, result_ct);
}

std::vector<int64_t> EncryptedBatch::decrypt() const {
    if (!context_ || !context_->is_key_generated()) {
        throw std::invalid_argument("context not ready for decryption");
    }

    auto decrypted = context_->decrypt_batch(ciphertext_);
    if (batch_size_ > 0 && decrypted.size() > batch_size_) {
        decrypted.resize(batch_size_);
    }

    return decrypted;
}

size_t EncryptedBatch::size() const {
    return batch_size_;
}

NoiseInfo EncryptedBatch::get_noise_info() const {
    update_noise_info();
    return noise_info_;
}

void EncryptedBatch::refresh() {
    if (!noise_info_.needs_refresh)
        return;

    try {
        auto decrypted_values = decrypt();
        *this = EncryptedBatch(context_, decrypted_values);
    } catch (...) {
        throw NoiseException("failed to refresh batch ciphertext");
    }
}

void EncryptedBatch::update_noise_info() const {
    noise_info_.last_measured = std::chrono::steady_clock::now();

    if (!ciphertext_) {
        noise_info_.current_level = 1.0;
        noise_info_.needs_refresh = true;
        return;
    }

    // similar noise estimation as EncryptedInt
    int depth = ciphertext_->GetLevel();
    auto params = context_->get_parameters();

    double base_noise = 0.01;
    double depth_factor = std::pow(2.0, depth);
    noise_info_.current_level = base_noise * depth_factor;

    noise_info_.depth_remaining =
        std::max(0, static_cast<int>(params.multiplicative_depth) - depth);
    noise_info_.needs_refresh = (noise_info_.current_level > noise_info_.critical_threshold) ||
                                (noise_info_.depth_remaining <= 1);
}

ArithmeticConfig& ArithmeticConfig::instance() {
    static ArithmeticConfig instance;
    return instance;
}

void ArithmeticConfig::set_noise_threshold(double threshold) {
    noise_threshold_ = threshold;
}

double ArithmeticConfig::get_noise_threshold() const {
    return noise_threshold_;
}

void ArithmeticConfig::set_auto_refresh(bool enabled) {
    auto_refresh_ = enabled;
}

bool ArithmeticConfig::get_auto_refresh() const {
    return auto_refresh_;
}

void ArithmeticConfig::set_overflow_behavior(OverflowBehavior behavior) {
    overflow_behavior_ = behavior;
}

OverflowBehavior ArithmeticConfig::get_overflow_behavior() const {
    return overflow_behavior_;
}

ArithmeticConfig::Statistics ArithmeticConfig::get_statistics() const {
    return stats_;
}

void ArithmeticConfig::reset_statistics() {
    stats_ = Statistics{};
}

namespace arithmetic {

OperationResult safe_add(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result) {
    try {
        result = a + b;
        return OperationResult{true, "", 0.0, std::chrono::milliseconds(0)};
    } catch (const std::exception& e) {
        return OperationResult{false, e.what(), 0.0, std::chrono::milliseconds(0)};
    }
}

OperationResult safe_multiply(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result) {
    try {
        result = a * b;
        return OperationResult{true, "", 0.0, std::chrono::milliseconds(0)};
    } catch (const std::exception& e) {
        return OperationResult{false, e.what(), 0.0, std::chrono::milliseconds(0)};
    }
}

std::vector<EncryptedInt> batch_add(const std::vector<EncryptedInt>& a,
                                    const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("mismatched vector sizes");
    }

    std::vector<EncryptedInt> result;
    result.reserve(a.size());

    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(a[i] + b[i]);
    }

    return result;
}

EncryptedInt compute_sum(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        throw std::invalid_argument("empty vector");
    }

    EncryptedInt result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result += values[i];
    }

    return result;
}

EncryptedInt compute_address_offset(const EncryptedInt& base_addr,
                                    const EncryptedInt& index,
                                    int64_t element_size) {
    return base_addr + (index * element_size);
}

OperationResult safe_subtract(const EncryptedInt& a, const EncryptedInt& b, EncryptedInt& result) {
    try {
        result = a - b;
        return OperationResult{true, "", 0.0, std::chrono::milliseconds(0)};
    } catch (const std::exception& e) {
        return OperationResult{false, e.what(), 0.0, std::chrono::milliseconds(0)};
    }
}

std::vector<EncryptedInt> batch_multiply(const std::vector<EncryptedInt>& a,
                                         const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("mismatched vector sizes");
    }

    std::vector<EncryptedInt> result;
    result.reserve(a.size());

    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(a[i] * b[i]);
    }

    return result;
}

EncryptedInt compute_product(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        throw std::invalid_argument("empty vector");
    }

    EncryptedInt result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result *= values[i];
    }

    return result;
}

EncryptedInt compute_dot_product(const std::vector<EncryptedInt>& a,
                                 const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("mismatched vector sizes");
    }

    if (a.empty()) {
        throw std::invalid_argument("empty vectors");
    }

    EncryptedInt result = a[0] * b[0];
    for (size_t i = 1; i < a.size(); ++i) {
        result += a[i] * b[i];
    }

    return result;
}

EncryptedInt evaluate_polynomial(const EncryptedInt& x, const std::vector<int64_t>& coefficients) {
    if (coefficients.empty()) {
        throw std::invalid_argument("empty coefficients");
    }

    // use horner's method: a_n*x^n + ... + a_1*x + a_0 = (...((a_n*x + a_{n-1})*x + ...)*x + a_0
    auto context = x.get_context();
    EncryptedInt result(context, coefficients.back());

    for (int i = static_cast<int>(coefficients.size()) - 2; i >= 0; --i) {
        result = result * x + coefficients[i];
    }

    return result;
}

EncryptedInt compute_aligned_size(const EncryptedInt& size, int64_t alignment) {
    if (alignment <= 0 || (alignment & (alignment - 1)) != 0) {
        throw std::invalid_argument("alignment must be positive power of 2");
    }

    // aligned_size = ((size + alignment - 1) / alignment) * alignment
    // for power of 2 alignment: aligned_size = (size + alignment - 1) & ~(alignment - 1)
    auto temp = size + (alignment - 1);
    // for simplicity, use division method (bitwise operations would need bit manipulation)
    return temp;  // simplified implementation
}

}  // namespace arithmetic

ArithmeticChain::ArithmeticChain(std::shared_ptr<BFVContext> context)
    : context_(std::move(context)) {}

ArithmeticChain& ArithmeticChain::add(const EncryptedInt& value) {
    Operation op;
    op.type = Operation::ADD_ENCRYPTED;
    op.encrypted_operand = value;
    op.estimated_noise_increase = 0.1;  // rough estimate
    operations_.push_back(op);
    return *this;
}

ArithmeticChain& ArithmeticChain::add(int64_t value) {
    Operation op;
    op.type = Operation::ADD_PLAINTEXT;
    op.plaintext_operand = value;
    op.estimated_noise_increase = 0.05;  // plaintext operations have less noise
    operations_.push_back(op);
    return *this;
}

ArithmeticChain& ArithmeticChain::multiply(const EncryptedInt& value) {
    Operation op;
    op.type = Operation::MUL_ENCRYPTED;
    op.encrypted_operand = value;
    op.estimated_noise_increase = 1.0;  // multiplication increases noise significantly
    operations_.push_back(op);
    return *this;
}

ArithmeticChain& ArithmeticChain::multiply(int64_t value) {
    Operation op;
    op.type = Operation::MUL_PLAINTEXT;
    op.plaintext_operand = value;
    op.estimated_noise_increase = 0.3;  // plaintext multiplication
    operations_.push_back(op);
    return *this;
}

EncryptedInt ArithmeticChain::execute() {
    if (operations_.empty()) {
        throw std::invalid_argument("no operations to execute");
    }

    if (!initial_value_) {
        throw std::invalid_argument("no initial value set");
    }

    if (optimization_level_ > 0) {
        optimize_operations();
    }

    return execute_optimized();
}

EncryptedInt ArithmeticChain::execute_optimized() {
    EncryptedInt result = *initial_value_;
    double cumulative_noise = 0.0;

    for (const auto& op : operations_) {
        switch (op.type) {
            case Operation::ADD_ENCRYPTED:
                result = result + *op.encrypted_operand;
                break;
            case Operation::ADD_PLAINTEXT:
                result = result + *op.plaintext_operand;
                break;
            case Operation::MUL_ENCRYPTED:
                result = result * *op.encrypted_operand;
                break;
            case Operation::MUL_PLAINTEXT:
                result = result * *op.plaintext_operand;
                break;
            case Operation::NEGATE:
                result = -result;
                break;
            default:
                break;
        }

        cumulative_noise += op.estimated_noise_increase;

        // check if refresh is needed
        if (intermediate_refresh_enabled_ &&
            cumulative_noise > ArithmeticConfig::instance().get_noise_threshold()) {
            result.refresh();
            cumulative_noise = 0.0;
        }
    }

    return result;
}

int ArithmeticChain::estimate_depth() const {
    int depth = 0;
    for (const auto& op : operations_) {
        if (op.type == Operation::MUL_ENCRYPTED || op.type == Operation::MUL_PLAINTEXT) {
            depth++;
        }
    }
    return depth;
}

double ArithmeticChain::estimate_noise_growth() const {
    double total_noise = 0.0;
    for (const auto& op : operations_) {
        total_noise += op.estimated_noise_increase;
    }
    return total_noise;
}

size_t ArithmeticChain::operation_count() const {
    return operations_.size();
}

void ArithmeticChain::optimize_operations() {
    // basic optimization: combine consecutive plaintext operations
    std::vector<Operation> optimized;

    for (size_t i = 0; i < operations_.size(); ++i) {
        if (i + 1 < operations_.size() && operations_[i].type == Operation::ADD_PLAINTEXT &&
            operations_[i + 1].type == Operation::ADD_PLAINTEXT) {
            // combine two plaintext additions
            Operation combined;
            combined.type = Operation::ADD_PLAINTEXT;
            combined.plaintext_operand =
                *operations_[i].plaintext_operand + *operations_[i + 1].plaintext_operand;
            combined.estimated_noise_increase = operations_[i].estimated_noise_increase;
            optimized.push_back(combined);
            i++;  // skip next operation
        } else {
            optimized.push_back(operations_[i]);
        }
    }

    operations_ = std::move(optimized);
}

}  // namespace cryptmalloc