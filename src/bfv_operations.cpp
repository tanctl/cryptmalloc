/**
 * @file bfv_operations.cpp
 * @brief implementation of comprehensive homomorphic arithmetic operations
 */

#include "cryptmalloc/bfv_operations.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <limits>

namespace cryptmalloc {

// EncryptedInt implementation
EncryptedInt::EncryptedInt(int64_t value, std::shared_ptr<BFVContext> context)
    : context_(context) {
    if (!context || !context->is_initialized()) {
        throw std::invalid_argument("Context must be initialized");
    }

    auto encrypt_result = context->encrypt(value);
    if (!encrypt_result.has_value()) {
        throw std::runtime_error("Failed to encrypt value: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    
    // initialize noise budget
    noise_budget_.initial_budget = 50.0;  // default budget for fresh ciphertext
    noise_budget_.current_budget = noise_budget_.initial_budget;
    noise_budget_.critical_threshold = 10.0;  // refresh when budget drops below 20%
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedInt::EncryptedInt(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                           double initial_budget)
    : ciphertext_(ciphertext), context_(context) {
    if (!context || !context->is_initialized()) {
        throw std::invalid_argument("Context must be initialized");
    }

    noise_budget_.initial_budget = initial_budget;
    noise_budget_.current_budget = initial_budget;
    noise_budget_.critical_threshold = initial_budget * 0.2;  // 20% threshold
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedInt::EncryptedInt(const EncryptedInt& other)
    : ciphertext_(other.ciphertext_), context_(other.context_), noise_budget_(other.noise_budget_) {
}

EncryptedInt::EncryptedInt(EncryptedInt&& other) noexcept
    : ciphertext_(std::move(other.ciphertext_)), context_(std::move(other.context_)),
      noise_budget_(other.noise_budget_) {
}

EncryptedInt& EncryptedInt::operator=(const EncryptedInt& other) {
    if (this != &other) {
        std::lock_guard<std::mutex> lock(mutex_);
        ciphertext_ = other.ciphertext_;
        context_ = other.context_;
        noise_budget_ = other.noise_budget_;
    }
    return *this;
}

EncryptedInt& EncryptedInt::operator=(EncryptedInt&& other) noexcept {
    if (this != &other) {
        std::lock_guard<std::mutex> lock(mutex_);
        ciphertext_ = std::move(other.ciphertext_);
        context_ = std::move(other.context_);
        noise_budget_ = other.noise_budget_;
    }
    return *this;
}

Result<int64_t> EncryptedInt::decrypt() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_ || !context_->is_initialized()) {
        return Result<int64_t>("Context not initialized");
    }

    return context_->decrypt_int(ciphertext_);
}

bool EncryptedInt::is_valid() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_ || !context_->is_initialized() || !ciphertext_) {
        return false;
    }

    // basic validation - check if we can estimate noise
    auto noise_estimate = context_->estimate_noise(ciphertext_);
    return noise_estimate.has_value();
}

Result<void> EncryptedInt::refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // decrypt and re-encrypt to refresh noise budget
    auto decrypt_result = context_->decrypt_int(ciphertext_);
    if (!decrypt_result.has_value()) {
        return Result<void>("Failed to decrypt for refresh: " + decrypt_result.error());
    }

    auto encrypt_result = context_->encrypt(decrypt_result.value());
    if (!encrypt_result.has_value()) {
        return Result<void>("Failed to re-encrypt for refresh: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    
    // reset noise budget
    noise_budget_.current_budget = noise_budget_.initial_budget;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();

    return Result<void>::success();
}

void EncryptedInt::update_noise_budget(double cost) {
    std::lock_guard<std::mutex> lock(mutex_);
    noise_budget_.current_budget = std::max(0.0, noise_budget_.current_budget - cost);
    noise_budget_.operations_count++;
}

double EncryptedInt::estimate_current_noise() const {
    // simplified noise estimation based on operation count and elapsed time
    auto elapsed = std::chrono::steady_clock::now() - noise_budget_.created_at;
    auto elapsed_minutes = std::chrono::duration_cast<std::chrono::minutes>(elapsed).count();
    
    // noise grows with operations and time
    double time_factor = 1.0 + (elapsed_minutes * 0.1);
    double operation_factor = 1.0 + (noise_budget_.operations_count * 0.5);
    
    return noise_budget_.initial_budget - (noise_budget_.current_budget * time_factor * operation_factor);
}

// EncryptedIntBatch implementation
EncryptedIntBatch::EncryptedIntBatch(const std::vector<int64_t>& values,
                                     std::shared_ptr<BFVContext> context)
    : context_(context), size_(values.size()) {
    if (!context || !context->is_initialized()) {
        throw std::invalid_argument("Context must be initialized");
    }

    if (values.size() > context->parameters().batch_size) {
        throw std::invalid_argument("Vector size exceeds batch capacity");
    }

    auto encrypt_result = context->encrypt(values);
    if (!encrypt_result.has_value()) {
        throw std::runtime_error("Failed to encrypt batch: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    
    // initialize noise budget
    noise_budget_.initial_budget = 50.0;
    noise_budget_.current_budget = noise_budget_.initial_budget;
    noise_budget_.critical_threshold = 10.0;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedIntBatch::EncryptedIntBatch(Ciphertext ciphertext, std::shared_ptr<BFVContext> context,
                                     size_t size, double initial_budget)
    : ciphertext_(ciphertext), context_(context), size_(size) {
    if (!context || !context->is_initialized()) {
        throw std::invalid_argument("Context must be initialized");
    }

    noise_budget_.initial_budget = initial_budget;
    noise_budget_.current_budget = initial_budget;
    noise_budget_.critical_threshold = initial_budget * 0.2;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();
}

EncryptedIntBatch::EncryptedIntBatch(const EncryptedIntBatch& other)
    : ciphertext_(other.ciphertext_), context_(other.context_), size_(other.size_), 
      noise_budget_(other.noise_budget_) {
}

EncryptedIntBatch::EncryptedIntBatch(EncryptedIntBatch&& other) noexcept
    : ciphertext_(std::move(other.ciphertext_)), context_(std::move(other.context_)),
      size_(other.size_), noise_budget_(other.noise_budget_) {
}

EncryptedIntBatch& EncryptedIntBatch::operator=(const EncryptedIntBatch& other) {
    if (this != &other) {
        ciphertext_ = other.ciphertext_;
        context_ = other.context_;
        size_ = other.size_;
        noise_budget_ = other.noise_budget_;
    }
    return *this;
}

EncryptedIntBatch& EncryptedIntBatch::operator=(EncryptedIntBatch&& other) noexcept {
    if (this != &other) {
        ciphertext_ = std::move(other.ciphertext_);
        context_ = std::move(other.context_);
        size_ = other.size_;
        noise_budget_ = other.noise_budget_;
    }
    return *this;
}

Result<std::vector<int64_t>> EncryptedIntBatch::decrypt() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_ || !context_->is_initialized()) {
        return Result<std::vector<int64_t>>("Context not initialized");
    }

    return context_->decrypt_vector(ciphertext_, size_);
}

bool EncryptedIntBatch::is_valid() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_ || !context_->is_initialized() || !ciphertext_) {
        return false;
    }

    auto noise_estimate = context_->estimate_noise(ciphertext_);
    return noise_estimate.has_value();
}

Result<void> EncryptedIntBatch::refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto decrypt_result = context_->decrypt_vector(ciphertext_, size_);
    if (!decrypt_result.has_value()) {
        return Result<void>("Failed to decrypt batch for refresh: " + decrypt_result.error());
    }

    auto encrypt_result = context_->encrypt(decrypt_result.value());
    if (!encrypt_result.has_value()) {
        return Result<void>("Failed to re-encrypt batch for refresh: " + encrypt_result.error());
    }

    ciphertext_ = encrypt_result.value();
    
    // reset noise budget
    noise_budget_.current_budget = noise_budget_.initial_budget;
    noise_budget_.operations_count = 0;
    noise_budget_.created_at = std::chrono::steady_clock::now();

    return Result<void>::success();
}

void EncryptedIntBatch::update_noise_budget(double cost) {
    std::lock_guard<std::mutex> lock(mutex_);
    noise_budget_.current_budget = std::max(0.0, noise_budget_.current_budget - cost);
    noise_budget_.operations_count++;
}

// BFVOperations implementation
BFVOperations::BFVOperations(std::shared_ptr<BFVContext> context)
    : context_(context), stats_{} {
    if (!context || !context->is_initialized()) {
        throw std::invalid_argument("Context must be initialized");
    }
}

Result<EncryptedInt> BFVOperations::add(const EncryptedInt& a, const EncryptedInt& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_operands(a, b)) {
        record_operation("add", start_time, false);
        return Result<EncryptedInt>("Invalid operands");
    }

    auto operation = [this](const BFVContext::Ciphertext& x, const BFVContext::Ciphertext& y) {
        return context_->add(x, y);
    };

    auto result = perform_binary_operation(a, b, operation, "add", 1.0);
    record_operation("add", start_time, result.has_value(), 1.0);
    
    if (result.has_value()) {
        stats_.additions_performed++;
    }
    
    return result;
}

Result<EncryptedInt> BFVOperations::subtract(const EncryptedInt& a, const EncryptedInt& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_operands(a, b)) {
        record_operation("subtract", start_time, false);
        return Result<EncryptedInt>("Invalid operands");
    }

    auto operation = [this](const BFVContext::Ciphertext& x, const BFVContext::Ciphertext& y) {
        return context_->subtract(x, y);
    };

    auto result = perform_binary_operation(a, b, operation, "subtract", 1.0);
    record_operation("subtract", start_time, result.has_value(), 1.0);
    
    if (result.has_value()) {
        stats_.subtractions_performed++;
    }
    
    return result;
}

Result<EncryptedInt> BFVOperations::multiply(const EncryptedInt& a, const EncryptedInt& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_operands(a, b)) {
        record_operation("multiply", start_time, false);
        return Result<EncryptedInt>("Invalid operands");
    }

    // multiplication is more expensive in terms of noise
    double noise_cost = 5.0;
    
    auto operation = [this](const BFVContext::Ciphertext& x, const BFVContext::Ciphertext& y) {
        return context_->multiply(x, y);
    };

    auto result = perform_binary_operation(a, b, operation, "multiply", noise_cost);
    record_operation("multiply", start_time, result.has_value(), noise_cost);
    
    if (result.has_value()) {
        stats_.multiplications_performed++;
    }
    
    return result;
}

Result<EncryptedInt> BFVOperations::negate(const EncryptedInt& a) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!a.is_valid()) {
        record_operation("negate", start_time, false);
        return Result<EncryptedInt>("Invalid operand");
    }

    auto operation = [this](const BFVContext::Ciphertext& x) {
        // negate by multiplying with -1
        auto neg_one = context_->encrypt(-1);
        if (!neg_one.has_value()) {
            return Result<BFVContext::Ciphertext>(neg_one.error());
        }
        return context_->multiply(x, neg_one.value());
    };

    auto result = perform_unary_operation(a, operation, "negate", 2.0);
    record_operation("negate", start_time, result.has_value(), 2.0);
    
    if (result.has_value()) {
        stats_.negations_performed++;
    }
    
    return result;
}

Result<EncryptedInt> BFVOperations::add_constant(const EncryptedInt& a, int64_t constant) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!a.is_valid()) {
        record_operation("add_constant", start_time, false);
        return Result<EncryptedInt>("Invalid operand");
    }

    try {
        // encrypt the constant
        auto encrypted_constant = context_->encrypt(constant);
        if (!encrypted_constant.has_value()) {
            record_operation("add_constant", start_time, false);
            return Result<EncryptedInt>("Failed to encrypt constant: " + encrypted_constant.error());
        }

        EncryptedInt const_int(encrypted_constant.value(), context_, 50.0);
        auto result = add(a, const_int);
        
        record_operation("add_constant", start_time, result.has_value(), 1.0);
        return result;
        
    } catch (const std::exception& e) {
        record_operation("add_constant", start_time, false);
        return Result<EncryptedInt>(std::string("Operation failed: ") + e.what());
    }
}

Result<EncryptedInt> BFVOperations::multiply_constant(const EncryptedInt& a, int64_t constant) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!a.is_valid()) {
        record_operation("multiply_constant", start_time, false);
        return Result<EncryptedInt>("Invalid operand");
    }

    try {
        // encrypt the constant
        auto encrypted_constant = context_->encrypt(constant);
        if (!encrypted_constant.has_value()) {
            record_operation("multiply_constant", start_time, false);
            return Result<EncryptedInt>("Failed to encrypt constant: " + encrypted_constant.error());
        }

        EncryptedInt const_int(encrypted_constant.value(), context_, 50.0);
        auto result = multiply(a, const_int);
        
        record_operation("multiply_constant", start_time, result.has_value(), 5.0);
        return result;
        
    } catch (const std::exception& e) {
        record_operation("multiply_constant", start_time, false);
        return Result<EncryptedInt>(std::string("Operation failed: ") + e.what());
    }
}

// Batch operations
Result<EncryptedIntBatch> BFVOperations::add_batch(const EncryptedIntBatch& a, 
                                                   const EncryptedIntBatch& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_batch_operands(a, b)) {
        record_operation("add_batch", start_time, false);
        return Result<EncryptedIntBatch>("Invalid batch operands");
    }

    try {
        auto result_ciphertext = context_->add(a.ciphertext(), b.ciphertext());
        if (!result_ciphertext.has_value()) {
            record_operation("add_batch", start_time, false);
            return Result<EncryptedIntBatch>("Batch addition failed: " + result_ciphertext.error());
        }

        // calculate noise budget for result
        double result_budget = std::min(a.noise_budget().current_budget, 
                                       b.noise_budget().current_budget) - 1.0;
        
        EncryptedIntBatch result(result_ciphertext.value(), context_, a.size(), result_budget);
        
        record_operation("add_batch", start_time, true, 1.0);
        return Result<EncryptedIntBatch>(std::move(result));
        
    } catch (const std::exception& e) {
        record_operation("add_batch", start_time, false);
        return Result<EncryptedIntBatch>(std::string("Batch operation failed: ") + e.what());
    }
}

Result<EncryptedIntBatch> BFVOperations::subtract_batch(const EncryptedIntBatch& a,
                                                        const EncryptedIntBatch& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_batch_operands(a, b)) {
        record_operation("subtract_batch", start_time, false);
        return Result<EncryptedIntBatch>("Invalid batch operands");
    }

    try {
        auto result_ciphertext = context_->subtract(a.ciphertext(), b.ciphertext());
        if (!result_ciphertext.has_value()) {
            record_operation("subtract_batch", start_time, false);
            return Result<EncryptedIntBatch>("Batch subtraction failed: " + result_ciphertext.error());
        }

        double result_budget = std::min(a.noise_budget().current_budget,
                                       b.noise_budget().current_budget) - 1.0;
        
        EncryptedIntBatch result(result_ciphertext.value(), context_, a.size(), result_budget);
        
        record_operation("subtract_batch", start_time, true, 1.0);
        return Result<EncryptedIntBatch>(std::move(result));
        
    } catch (const std::exception& e) {
        record_operation("subtract_batch", start_time, false);
        return Result<EncryptedIntBatch>(std::string("Batch operation failed: ") + e.what());
    }
}

Result<EncryptedIntBatch> BFVOperations::multiply_batch(const EncryptedIntBatch& a,
                                                        const EncryptedIntBatch& b) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validate_batch_operands(a, b)) {
        record_operation("multiply_batch", start_time, false);
        return Result<EncryptedIntBatch>("Invalid batch operands");
    }

    try {
        auto result_ciphertext = context_->multiply(a.ciphertext(), b.ciphertext());
        if (!result_ciphertext.has_value()) {
            record_operation("multiply_batch", start_time, false);
            return Result<EncryptedIntBatch>("Batch multiplication failed: " + result_ciphertext.error());
        }

        double result_budget = std::min(a.noise_budget().current_budget,
                                       b.noise_budget().current_budget) - 5.0;
        
        EncryptedIntBatch result(result_ciphertext.value(), context_, a.size(), result_budget);
        
        record_operation("multiply_batch", start_time, true, 5.0);
        return Result<EncryptedIntBatch>(std::move(result));
        
    } catch (const std::exception& e) {
        record_operation("multiply_batch", start_time, false);
        return Result<EncryptedIntBatch>(std::string("Batch operation failed: ") + e.what());
    }
}

Result<EncryptedIntBatch> BFVOperations::negate_batch(const EncryptedIntBatch& a) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!a.is_valid()) {
        record_operation("negate_batch", start_time, false);
        return Result<EncryptedIntBatch>("Invalid batch operand");
    }

    try {
        // create a batch of -1 values
        std::vector<int64_t> neg_ones(a.size(), -1);
        auto neg_batch_result = context_->encrypt(neg_ones);
        if (!neg_batch_result.has_value()) {
            record_operation("negate_batch", start_time, false);
            return Result<EncryptedIntBatch>("Failed to create negation batch: " + neg_batch_result.error());
        }

        EncryptedIntBatch neg_batch(neg_batch_result.value(), context_, a.size(), 50.0);
        auto result = multiply_batch(a, neg_batch);
        
        record_operation("negate_batch", start_time, result.has_value(), 5.0);
        return result;
        
    } catch (const std::exception& e) {
        record_operation("negate_batch", start_time, false);
        return Result<EncryptedIntBatch>(std::string("Batch negation failed: ") + e.what());
    }
}

// Advanced operations
Result<EncryptedInt> BFVOperations::sum(const std::vector<EncryptedInt>& values) {
    if (values.empty()) {
        return Result<EncryptedInt>("Cannot sum empty vector");
    }

    if (values.size() == 1) {
        return Result<EncryptedInt>(values[0]);
    }

    // tree-based reduction for better noise management
    std::vector<EncryptedInt> current_level = values;
    
    while (current_level.size() > 1) {
        std::vector<EncryptedInt> next_level;
        
        for (size_t i = 0; i < current_level.size(); i += 2) {
            if (i + 1 < current_level.size()) {
                auto sum_result = add(current_level[i], current_level[i + 1]);
                if (!sum_result.has_value()) {
                    return sum_result;
                }
                next_level.push_back(sum_result.value());
            } else {
                next_level.push_back(current_level[i]);
            }
        }
        
        current_level = std::move(next_level);
    }
    
    return Result<EncryptedInt>(current_level[0]);
}

Result<EncryptedInt> BFVOperations::dot_product(const std::vector<EncryptedInt>& a,
                                                const std::vector<EncryptedInt>& b) {
    if (a.size() != b.size()) {
        return Result<EncryptedInt>("Vector sizes must match for dot product");
    }

    if (a.empty()) {
        return Result<EncryptedInt>("Cannot compute dot product of empty vectors");
    }

    // compute element-wise products
    std::vector<EncryptedInt> products;
    products.reserve(a.size());
    
    for (size_t i = 0; i < a.size(); ++i) {
        auto product_result = multiply(a[i], b[i]);
        if (!product_result.has_value()) {
            return product_result;
        }
        products.push_back(product_result.value());
    }
    
    // sum all products
    return sum(products);
}

Result<EncryptedInt> BFVOperations::evaluate_polynomial(const std::vector<int64_t>& coefficients,
                                                        const EncryptedInt& x) {
    if (coefficients.empty()) {
        return Result<EncryptedInt>("Empty polynomial coefficients");
    }

    // use Horner's method for polynomial evaluation
    // p(x) = a_n * x^n + ... + a_1 * x + a_0
    // p(x) = a_0 + x * (a_1 + x * (a_2 + ... + x * a_n))
    
    try {
        auto result = EncryptedInt(coefficients.back(), context_);
        
        for (int i = static_cast<int>(coefficients.size()) - 2; i >= 0; --i) {
            // result = result * x + coefficients[i]
            auto mult_result = multiply(result, x);
            if (!mult_result.has_value()) {
                return mult_result;
            }
            
            auto add_result = add_constant(mult_result.value(), coefficients[i]);
            if (!add_result.has_value()) {
                return add_result;
            }
            
            result = add_result.value();
        }
        
        return Result<EncryptedInt>(result);
        
    } catch (const std::exception& e) {
        return Result<EncryptedInt>(std::string("Polynomial evaluation failed: ") + e.what());
    }
}

// Operation chaining
BFVOperations::OperationChain::OperationChain(std::shared_ptr<BFVOperations> ops, 
                                              EncryptedInt initial_value)
    : operations_(ops), current_value_(initial_value), estimated_cost_(0.0) {
}

BFVOperations::OperationChain& BFVOperations::OperationChain::add(const EncryptedInt& value) {
    chain_.push_back([this, value](const EncryptedInt& current) {
        return operations_->add(current, value);
    });
    estimated_cost_ += 1.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::add(int64_t constant) {
    chain_.push_back([this, constant](const EncryptedInt& current) {
        return operations_->add_constant(current, constant);
    });
    estimated_cost_ += 1.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::subtract(const EncryptedInt& value) {
    chain_.push_back([this, value](const EncryptedInt& current) {
        return operations_->subtract(current, value);
    });
    estimated_cost_ += 1.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::subtract(int64_t constant) {
    chain_.push_back([this, constant](const EncryptedInt& current) {
        auto neg_constant = EncryptedInt(-constant, operations_->context_);
        return operations_->add(current, neg_constant);
    });
    estimated_cost_ += 1.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::multiply(const EncryptedInt& value) {
    chain_.push_back([this, value](const EncryptedInt& current) {
        return operations_->multiply(current, value);
    });
    estimated_cost_ += 5.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::multiply(int64_t constant) {
    chain_.push_back([this, constant](const EncryptedInt& current) {
        return operations_->multiply_constant(current, constant);
    });
    estimated_cost_ += 5.0;
    return *this;
}

BFVOperations::OperationChain& BFVOperations::OperationChain::negate() {
    chain_.push_back([this](const EncryptedInt& current) {
        return operations_->negate(current);
    });
    estimated_cost_ += 2.0;
    return *this;
}

Result<EncryptedInt> BFVOperations::OperationChain::execute() {
    optimize_chain();
    
    EncryptedInt result = current_value_;
    
    for (const auto& operation : chain_) {
        auto op_result = operation(result);
        if (!op_result.has_value()) {
            return op_result;
        }
        result = op_result.value();
        
        // check if refresh is needed
        if (result.needs_refresh()) {
            auto refresh_result = result.refresh();
            if (!refresh_result.has_value()) {
                return Result<EncryptedInt>("Failed to refresh during chain execution: " + 
                                          refresh_result.error());
            }
        }
    }
    
    return Result<EncryptedInt>(result);
}

double BFVOperations::OperationChain::estimated_noise_cost() const {
    return estimated_cost_;
}

void BFVOperations::OperationChain::optimize_chain() {
    // simple optimization: combine consecutive constant additions/multiplications
    // more sophisticated optimizations could be added here
}

BFVOperations::OperationChain BFVOperations::chain(EncryptedInt initial_value) {
    return OperationChain(shared_from_this(), initial_value);
}

// Validation and overflow detection
Result<bool> BFVOperations::is_in_safe_range(const EncryptedInt& value) {
    auto decrypt_result = value.decrypt();
    if (!decrypt_result.has_value()) {
        return Result<bool>("Cannot decrypt value for range check: " + decrypt_result.error());
    }

    int64_t plaintext_value = decrypt_result.value();
    int64_t max_safe = encrypted_int_utils::max_safe_value(context_);
    int64_t min_safe = encrypted_int_utils::min_safe_value(context_);
    
    bool in_range = (plaintext_value >= min_safe && plaintext_value <= max_safe);
    return Result<bool>(in_range);
}

bool BFVOperations::will_overflow(const EncryptedInt& a, const EncryptedInt& b,
                                  const std::string& operation) {
    // simplified overflow detection - in practice, this would need more sophisticated analysis
    auto decrypt_a = a.decrypt();
    auto decrypt_b = b.decrypt();
    
    if (!decrypt_a.has_value() || !decrypt_b.has_value()) {
        return true; // assume overflow if we can't decrypt
    }

    int64_t val_a = decrypt_a.value();
    int64_t val_b = decrypt_b.value();
    int64_t max_safe = encrypted_int_utils::max_safe_value(context_);
    int64_t min_safe = encrypted_int_utils::min_safe_value(context_);

    if (operation == "add") {
        // check for addition overflow
        if (val_a > 0 && val_b > 0 && val_a > max_safe - val_b) return true;
        if (val_a < 0 && val_b < 0 && val_a < min_safe - val_b) return true;
    } else if (operation == "multiply") {
        // check for multiplication overflow
        if (val_a != 0 && std::abs(val_b) > max_safe / std::abs(val_a)) return true;
    }

    return false;
}

void BFVOperations::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = OperationStats{};
}

// Private helper methods
Result<EncryptedInt> BFVOperations::perform_binary_operation(
    const EncryptedInt& a, const EncryptedInt& b,
    std::function<Result<BFVContext::Ciphertext>(const BFVContext::Ciphertext&,
                                                 const BFVContext::Ciphertext&)> operation,
    const std::string& operation_name, double noise_cost) {

    try {
        auto result_ciphertext = operation(a.ciphertext(), b.ciphertext());
        if (!result_ciphertext.has_value()) {
            return Result<EncryptedInt>(operation_name + " operation failed: " + result_ciphertext.error());
        }

        // calculate noise budget for result
        double result_budget = std::min(a.noise_budget().current_budget,
                                       b.noise_budget().current_budget) - noise_cost;
        result_budget = std::max(0.0, result_budget);

        // preserve the original initial budget for refresh capability
        double initial_budget = std::max(a.noise_budget().initial_budget, 
                                        b.noise_budget().initial_budget);
        
        EncryptedInt result(result_ciphertext.value(), context_, initial_budget);
        
        // set the current budget to the calculated reduced value
        result.set_current_budget(result_budget);
        
        return Result<EncryptedInt>(std::move(result));
        
    } catch (const std::exception& e) {
        return Result<EncryptedInt>(operation_name + " operation failed: " + e.what());
    }
}

Result<EncryptedInt> BFVOperations::perform_unary_operation(
    const EncryptedInt& a,
    std::function<Result<BFVContext::Ciphertext>(const BFVContext::Ciphertext&)> operation,
    const std::string& operation_name, double noise_cost) {

    try {
        auto result_ciphertext = operation(a.ciphertext());
        if (!result_ciphertext.has_value()) {
            return Result<EncryptedInt>(operation_name + " operation failed: " + result_ciphertext.error());
        }

        double result_budget = a.noise_budget().current_budget - noise_cost;
        result_budget = std::max(0.0, result_budget);

        // preserve the original initial budget for refresh capability
        EncryptedInt result(result_ciphertext.value(), context_, a.noise_budget().initial_budget);
        
        // set the current budget to the calculated reduced value
        result.set_current_budget(result_budget);
        
        return Result<EncryptedInt>(std::move(result));
        
    } catch (const std::exception& e) {
        return Result<EncryptedInt>(operation_name + " operation failed: " + e.what());
    }
}

double BFVOperations::calculate_noise_cost(const std::string& operation,
                                          const std::vector<double>& operand_budgets) {
    (void)operand_budgets; // unused in this implementation
    double base_costs[] = {
        1.0,  // addition
        1.0,  // subtraction  
        5.0,  // multiplication
        2.0   // negation
    };
    (void)base_costs; // array defined but not used in current implementation
    
    // simplified cost calculation
    if (operation == "add" || operation == "subtract") return 1.0;
    if (operation == "multiply") return 5.0;
    if (operation == "negate") return 2.0;
    
    return 1.0; // default cost
}

bool BFVOperations::should_auto_refresh(const EncryptedInt& value) {
    return value.needs_refresh();
}

Result<EncryptedInt> BFVOperations::auto_refresh_if_needed(EncryptedInt value) {
    if (should_auto_refresh(value)) {
        auto refresh_result = value.refresh();
        if (!refresh_result.has_value()) {
            return Result<EncryptedInt>("Auto-refresh failed: " + refresh_result.error());
        }
        stats_.refreshes_performed++;
    }
    return Result<EncryptedInt>(std::move(value));
}

bool BFVOperations::validate_operands(const EncryptedInt& a, const EncryptedInt& b) {
    if (!a.is_valid() || !b.is_valid()) {
        stats_.validation_failures++;
        return false;
    }
    
    if (a.context() != b.context()) {
        stats_.validation_failures++;
        return false;
    }
    
    return true;
}

bool BFVOperations::validate_batch_operands(const EncryptedIntBatch& a, const EncryptedIntBatch& b) {
    if (!a.is_valid() || !b.is_valid()) {
        stats_.validation_failures++;
        return false;
    }
    
    if (a.context() != b.context() || a.size() != b.size()) {
        stats_.validation_failures++;
        return false;
    }
    
    return true;
}

void BFVOperations::record_operation(const std::string& operation,
                                    std::chrono::steady_clock::time_point start_time,
                                    bool success, double noise_consumed) {
    (void)operation; // unused in current implementation
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto duration = std::chrono::steady_clock::now() - start_time;
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    
    stats_.total_operation_time += duration_ms;
    
    if (success) {
        // update average noise consumption
        double total_operations = stats_.additions_performed + stats_.subtractions_performed +
                                 stats_.multiplications_performed + stats_.negations_performed;
        if (total_operations > 0) {
            stats_.average_noise_consumption = 
                (stats_.average_noise_consumption * (total_operations - 1) + noise_consumed) / total_operations;
        } else {
            stats_.average_noise_consumption = noise_consumed;
        }
    }
}

// Utility functions implementation
namespace encrypted_int_utils {

Result<EncryptedInt> encrypt(int64_t value, std::shared_ptr<BFVContext> context) {
    try {
        return Result<EncryptedInt>(EncryptedInt(value, context));
    } catch (const std::exception& e) {
        return Result<EncryptedInt>(std::string("Encryption failed: ") + e.what());
    }
}

Result<EncryptedIntBatch> encrypt_batch(const std::vector<int64_t>& values,
                                        std::shared_ptr<BFVContext> context) {
    try {
        return Result<EncryptedIntBatch>(EncryptedIntBatch(values, context));
    } catch (const std::exception& e) {
        return Result<EncryptedIntBatch>(std::string("Batch encryption failed: ") + e.what());
    }
}

Result<int> compare(const EncryptedInt& a, const EncryptedInt& b) {
    auto decrypt_a = a.decrypt();
    auto decrypt_b = b.decrypt();
    
    if (!decrypt_a.has_value()) {
        return Result<int>("Failed to decrypt first operand: " + decrypt_a.error());
    }
    
    if (!decrypt_b.has_value()) {
        return Result<int>("Failed to decrypt second operand: " + decrypt_b.error());
    }
    
    int64_t val_a = decrypt_a.value();
    int64_t val_b = decrypt_b.value();
    
    if (val_a < val_b) return Result<int>(-1);
    if (val_a > val_b) return Result<int>(1);  
    return Result<int>(0);
}

int64_t max_safe_value(std::shared_ptr<BFVContext> context) {
    // simplified - use half of plaintext modulus as safe range
    return static_cast<int64_t>(context->parameters().plaintext_modulus / 4);
}

int64_t min_safe_value(std::shared_ptr<BFVContext> context) {
    return -max_safe_value(context);
}

double estimate_noise_after_operations(double initial_budget,
                                       const std::vector<std::string>& operations) {
    double remaining = initial_budget;
    
    for (const auto& op : operations) {
        if (op == "add" || op == "subtract") {
            remaining -= 1.0;
        } else if (op == "multiply") {
            remaining -= 5.0;
        } else if (op == "negate") {
            remaining -= 2.0;
        }
    }
    
    return std::max(0.0, remaining);
}

} // namespace encrypted_int_utils

} // namespace cryptmalloc