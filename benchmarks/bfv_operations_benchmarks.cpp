/**
 * @file bfv_operations_benchmarks.cpp
 * @brief performance benchmarks comparing encrypted vs plaintext operation costs
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <chrono>
#include <random>
#include <vector>

#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

namespace {

class OperationsBenchmarkHelper {
public:
    OperationsBenchmarkHelper() {
        auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
        context_ = std::make_shared<BFVContext>(params);
        auto init_result = context_->initialize();
        if (!init_result.has_value()) {
            throw std::runtime_error("Failed to initialize context for benchmarks");
        }
        operations_ = std::make_shared<BFVOperations>(context_);
    }

    std::shared_ptr<BFVContext> context() { return context_; }
    std::shared_ptr<BFVOperations> operations() { return operations_; }

    EncryptedInt encrypt(int64_t value) {
        return EncryptedInt(value, context_);
    }

    EncryptedIntBatch encrypt_batch(const std::vector<int64_t>& values) {
        return EncryptedIntBatch(values, context_);
    }

    std::vector<int64_t> generate_random_ints(size_t count, int64_t min_val = -1000, int64_t max_val = 1000) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<int64_t> dis(min_val, max_val);
        
        std::vector<int64_t> result(count);
        for (auto& val : result) {
            val = dis(gen);
        }
        return result;
    }

    std::vector<EncryptedInt> encrypt_vector(const std::vector<int64_t>& values) {
        std::vector<EncryptedInt> result;
        result.reserve(values.size());
        for (int64_t val : values) {
            result.push_back(encrypt(val));
        }
        return result;
    }

private:
    std::shared_ptr<BFVContext> context_;
    std::shared_ptr<BFVOperations> operations_;
};

} // anonymous namespace

TEST_CASE("Encrypted vs Plaintext Arithmetic Benchmarks", "[benchmark][operations][comparison]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Addition comparison") {
        // plaintext addition
        BENCHMARK("Plaintext addition") {
            int64_t a = 123, b = 456;
            return a + b;
        };
        
        // encrypted addition (single operation)
        auto enc_a = helper.encrypt(123);
        auto enc_b = helper.encrypt(456);
        
        BENCHMARK("Encrypted addition") {
            return helper.operations()->add(enc_a, enc_b);
        };
        
        // encrypted addition with decryption
        BENCHMARK("Encrypted addition + decrypt") {
            auto result = helper.operations()->add(enc_a, enc_b);
            if (result.has_value()) {
                return result.value().decrypt();
            }
            return Result<int64_t>("Failed");
        };
    }
    
    SECTION("Multiplication comparison") {
        // plaintext multiplication
        BENCHMARK("Plaintext multiplication") {
            int64_t a = 123, b = 456;
            return a * b;
        };
        
        // encrypted multiplication
        auto enc_a = helper.encrypt(123);
        auto enc_b = helper.encrypt(456);
        
        BENCHMARK("Encrypted multiplication") {
            return helper.operations()->multiply(enc_a, enc_b);
        };
        
        // encrypted multiplication with decryption
        BENCHMARK("Encrypted multiplication + decrypt") {
            auto result = helper.operations()->multiply(enc_a, enc_b);
            if (result.has_value()) {
                return result.value().decrypt();
            }
            return Result<int64_t>("Failed");
        };
    }
    
    SECTION("Complex expression comparison") {
        // plaintext: (a + b) * (c - d)
        BENCHMARK("Plaintext complex expression") {
            int64_t a = 10, b = 20, c = 50, d = 30;
            return (a + b) * (c - d);
        };
        
        // encrypted equivalent
        auto enc_a = helper.encrypt(10);
        auto enc_b = helper.encrypt(20);
        auto enc_c = helper.encrypt(50);
        auto enc_d = helper.encrypt(30);
        
        BENCHMARK("Encrypted complex expression") {
            auto sum_result = helper.operations()->add(enc_a, enc_b);
            auto diff_result = helper.operations()->subtract(enc_c, enc_d);
            
            if (sum_result.has_value() && diff_result.has_value()) {
                return helper.operations()->multiply(sum_result.value(), diff_result.value());
            }
            return Result<EncryptedInt>("Failed");
        };
    }
}

TEST_CASE("Batch Operation Performance", "[benchmark][operations][batch]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Batch vs individual operations") {
        std::vector<int64_t> vec_a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        std::vector<int64_t> vec_b = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        
        // individual encrypted operations
        auto enc_vec_a = helper.encrypt_vector(vec_a);
        auto enc_vec_b = helper.encrypt_vector(vec_b);
        
        BENCHMARK("Individual encrypted additions") {
            std::vector<EncryptedInt> results;
            results.reserve(vec_a.size());
            
            for (size_t i = 0; i < vec_a.size(); ++i) {
                auto result = helper.operations()->add(enc_vec_a[i], enc_vec_b[i]);
                if (result.has_value()) {
                    results.push_back(result.value());
                }
            }
            return results.size();
        };
        
        // batch operations
        auto batch_a = helper.encrypt_batch(vec_a);
        auto batch_b = helper.encrypt_batch(vec_b);
        
        BENCHMARK("Batch encrypted addition") {
            return helper.operations()->add_batch(batch_a, batch_b);
        };
        
        // plaintext batch operations for comparison
        BENCHMARK("Plaintext vector addition") {
            std::vector<int64_t> result(vec_a.size());
            for (size_t i = 0; i < vec_a.size(); ++i) {
                result[i] = vec_a[i] + vec_b[i];
            }
            return result.size();
        };
    }
    
    SECTION("Batch size scaling") {
        std::vector<size_t> batch_sizes = {10, 50, 100, 500};
        
        for (size_t size : batch_sizes) {
            std::string test_name = "Batch addition (" + std::to_string(size) + " elements)";
            
            auto vec_a = helper.generate_random_ints(size);
            auto vec_b = helper.generate_random_ints(size);
            auto batch_a = helper.encrypt_batch(vec_a);
            auto batch_b = helper.encrypt_batch(vec_b);
            
            BENCHMARK(test_name.c_str()) {
                return helper.operations()->add_batch(batch_a, batch_b);
            };
        }
    }
}

TEST_CASE("Advanced Operation Benchmarks", "[benchmark][operations][advanced]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Sum operations") {
        std::vector<size_t> vector_sizes = {5, 10, 20, 50};
        
        for (size_t size : vector_sizes) {
            std::string plaintext_name = "Plaintext sum (" + std::to_string(size) + " values)";
            std::string encrypted_name = "Encrypted sum (" + std::to_string(size) + " values)";
            
            auto values = helper.generate_random_ints(size, 1, 100);
            auto encrypted_values = helper.encrypt_vector(values);
            
            BENCHMARK(plaintext_name.c_str()) {
                int64_t sum = 0;
                for (int64_t val : values) {
                    sum += val;
                }
                return sum;
            };
            
            BENCHMARK(encrypted_name.c_str()) {
                return helper.operations()->sum(encrypted_values);
            };
        }
    }
    
    SECTION("Dot product operations") {
        std::vector<size_t> vector_sizes = {3, 5, 10, 20};
        
        for (size_t size : vector_sizes) {
            std::string plaintext_name = "Plaintext dot product (" + std::to_string(size) + " elements)";
            std::string encrypted_name = "Encrypted dot product (" + std::to_string(size) + " elements)";
            
            auto vec_a = helper.generate_random_ints(size, 1, 10);
            auto vec_b = helper.generate_random_ints(size, 1, 10);
            auto enc_a = helper.encrypt_vector(vec_a);
            auto enc_b = helper.encrypt_vector(vec_b);
            
            BENCHMARK(plaintext_name.c_str()) {
                int64_t dot_product = 0;
                for (size_t i = 0; i < vec_a.size(); ++i) {
                    dot_product += vec_a[i] * vec_b[i];
                }
                return dot_product;
            };
            
            BENCHMARK(encrypted_name.c_str()) {
                return helper.operations()->dot_product(enc_a, enc_b);
            };
        }
    }
    
    SECTION("Polynomial evaluation") {
        std::vector<size_t> polynomial_degrees = {2, 3, 4, 5};
        
        for (size_t degree : polynomial_degrees) {
            std::string plaintext_name = "Plaintext polynomial degree " + std::to_string(degree);
            std::string encrypted_name = "Encrypted polynomial degree " + std::to_string(degree);
            
            auto coefficients = helper.generate_random_ints(degree + 1, 1, 5);
            int64_t x_val = 3;
            auto enc_x = helper.encrypt(x_val);
            
            BENCHMARK(plaintext_name.c_str()) {
                // Horner's method for plaintext
                int64_t result = coefficients.back();
                for (int i = static_cast<int>(coefficients.size()) - 2; i >= 0; --i) {
                    result = result * x_val + coefficients[i];
                }
                return result;
            };
            
            BENCHMARK(encrypted_name.c_str()) {
                return helper.operations()->evaluate_polynomial(coefficients, enc_x);
            };
        }
    }
}

TEST_CASE("Operation Chaining Performance", "[benchmark][operations][chaining]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Chain length comparison") {
        std::vector<size_t> chain_lengths = {3, 5, 10, 15};
        
        for (size_t length : chain_lengths) {
            std::string test_name = "Operation chain length " + std::to_string(length);
            
            auto initial = helper.encrypt(10);
            
            BENCHMARK(test_name.c_str()) {
                auto chain = helper.operations()->chain(initial);
                
                // build chain of alternating add/multiply operations
                for (size_t i = 0; i < length; ++i) {
                    if (i % 2 == 0) {
                        chain.add(2);
                    } else {
                        chain.multiply(2);
                    }
                }
                
                return chain.execute();
            };
        }
    }
    
    SECTION("Chain vs individual operations") {
        auto initial = helper.encrypt(5);
        
        // individual operations
        BENCHMARK("Individual operations") {
            auto current = initial;
            
            auto add_result = helper.operations()->add_constant(current, 3);
            if (!add_result.has_value()) return add_result;
            current = add_result.value();
            
            auto mult_result = helper.operations()->multiply_constant(current, 2);
            if (!mult_result.has_value()) return Result<EncryptedInt>(mult_result.error());
            current = mult_result.value();
            
            auto sub_result = helper.operations()->add_constant(current, -1);
            if (!sub_result.has_value()) return Result<EncryptedInt>(sub_result.error());
            
            return Result<EncryptedInt>(sub_result.value());
        };
        
        // chained operations
        BENCHMARK("Chained operations") {
            return helper.operations()->chain(initial)
                .add(3)
                .multiply(2)
                .subtract(1)
                .execute();
        };
    }
}

TEST_CASE("Noise Budget Impact on Performance", "[benchmark][operations][noise]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Fresh vs degraded ciphertext") {
        auto fresh = helper.encrypt(42);
        
        // create degraded ciphertext by performing many operations
        auto degraded = fresh;
        for (int i = 0; i < 10; ++i) {
            auto result = helper.operations()->add_constant(degraded, 1);
            if (result.has_value()) {
                degraded = result.value();
            }
        }
        
        auto operand = helper.encrypt(7);
        
        BENCHMARK("Operation on fresh ciphertext") {
            return helper.operations()->multiply(fresh, operand);
        };
        
        BENCHMARK("Operation on degraded ciphertext") {
            return helper.operations()->multiply(degraded, operand);
        };
    }
    
    SECTION("Refresh operation cost") {
        auto encrypted = helper.encrypt(123);
        
        // degrade the ciphertext
        for (int i = 0; i < 15; ++i) {
            auto result = helper.operations()->multiply_constant(encrypted, 2);
            if (result.has_value()) {
                encrypted = result.value();
            }
        }
        
        BENCHMARK("Refresh degraded ciphertext") {
            auto copy = encrypted;
            return copy.refresh();
        };
        
        BENCHMARK("Fresh encryption") {
            return EncryptedInt(123, helper.context());
        };
    }
}

TEST_CASE("Memory and Throughput Benchmarks", "[benchmark][operations][throughput]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("High-throughput operations") {
        constexpr size_t num_operations = 1000;
        
        auto a = helper.encrypt(10);
        auto b = helper.encrypt(5);
        
        BENCHMARK("1000 encrypted additions") {
            size_t successful = 0;
            for (size_t i = 0; i < num_operations; ++i) {
                auto result = helper.operations()->add(a, b);
                if (result.has_value()) {
                    successful++;
                }
            }
            return successful;
        };
        
        // compare with plaintext
        BENCHMARK("1000 plaintext additions") {
            size_t count = 0;
            for (size_t i = 0; i < num_operations; ++i) {
                volatile int64_t result = 10 + 5; // volatile to prevent optimization
                count++;
            }
            return count;
        };
    }
    
    SECTION("Batch throughput scaling") {
        std::vector<size_t> batch_sizes = {10, 50, 100, 200, 500};
        
        for (size_t size : batch_sizes) {
            std::string test_name = "Batch throughput (" + std::to_string(size) + " elements)";
            
            auto vec_a = helper.generate_random_ints(size, 1, 100);
            auto vec_b = helper.generate_random_ints(size, 1, 100);
            auto batch_a = helper.encrypt_batch(vec_a);
            auto batch_b = helper.encrypt_batch(vec_b);
            
            BENCHMARK(test_name.c_str()) {
                auto add_result = helper.operations()->add_batch(batch_a, batch_b);
                if (add_result.has_value()) {
                    auto mult_result = helper.operations()->multiply_batch(add_result.value(), batch_a);
                    return mult_result.has_value() ? size : 0;
                }
                return 0;
            };
        }
    }
}

TEST_CASE("Error Handling Performance", "[benchmark][operations][errors]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Validation overhead") {
        auto valid_a = helper.encrypt(10);
        auto valid_b = helper.encrypt(5);
        
        BENCHMARK("Valid operand addition") {
            return helper.operations()->add(valid_a, valid_b);
        };
        
        // create invalid ciphertext for comparison
        // (this is implementation dependent and might not be easily achievable)
        BENCHMARK("Operand validation check") {
            // simulate validation cost
            bool valid = valid_a.is_valid() && valid_b.is_valid() && 
                        valid_a.context() == valid_b.context();
            return valid;
        };
    }
    
    SECTION("Overflow detection cost") {
        auto a = helper.encrypt(1000);
        auto b = helper.encrypt(2000);
        
        BENCHMARK("Overflow detection for multiplication") {
            return helper.operations()->will_overflow(a, b, "multiply");
        };
        
        BENCHMARK("Safe range validation") {
            return helper.operations()->is_in_safe_range(a);
        };
    }
}

TEST_CASE("Utility Function Performance", "[benchmark][operations][utils]") {
    OperationsBenchmarkHelper helper;
    
    SECTION("Encryption utilities") {
        BENCHMARK("Utility encrypt single value") {
            return encrypted_int_utils::encrypt(42, helper.context());
        };
        
        BENCHMARK("Direct EncryptedInt construction") {
            return EncryptedInt(42, helper.context());
        };
        
        std::vector<int64_t> values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        
        BENCHMARK("Utility encrypt batch") {
            return encrypted_int_utils::encrypt_batch(values, helper.context());
        };
        
        BENCHMARK("Direct EncryptedIntBatch construction") {
            return EncryptedIntBatch(values, helper.context());
        };
    }
    
    SECTION("Comparison utilities") {
        auto a = helper.encrypt(100);
        auto b = helper.encrypt(50);
        
        BENCHMARK("Encrypted comparison") {
            return encrypted_int_utils::compare(a, b);
        };
        
        BENCHMARK("Plaintext comparison") {
            int64_t val_a = 100, val_b = 50;
            if (val_a < val_b) return -1;
            if (val_a > val_b) return 1;
            return 0;
        };
    }
    
    SECTION("Noise estimation") {
        std::vector<std::string> operations = {"add", "multiply", "subtract", "add", "multiply"};
        
        BENCHMARK("Noise estimation calculation") {
            return encrypted_int_utils::estimate_noise_after_operations(50.0, operations);
        };
    }
}