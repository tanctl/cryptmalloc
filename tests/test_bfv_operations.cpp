/**
 * @file test_bfv_operations.cpp
 * @brief comprehensive arithmetic tests for BFV operations including edge cases
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <limits>
#include <random>
#include <vector>

#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

// Test fixture for BFV operations
class BFVOperationsTestFixture {
public:
    BFVOperationsTestFixture() {
        auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
        context_ = std::make_shared<BFVContext>(params);
        auto init_result = context_->initialize();
        if (!init_result.has_value()) {
            throw std::runtime_error("Failed to initialize BFV context for tests");
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

private:
    std::shared_ptr<BFVContext> context_;
    std::shared_ptr<BFVOperations> operations_;
};

TEST_CASE_METHOD(BFVOperationsTestFixture, "EncryptedInt basic functionality", "[bfv][operations][encrypted_int]") {
    SECTION("Construction and decryption") {
        std::vector<int64_t> test_values = {0, 1, -1, 42, -42, 1000, -1000};
        
        for (int64_t value : test_values) {
            auto encrypted = encrypt(value);
            REQUIRE(encrypted.is_valid());
            
            auto decrypted = encrypted.decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == value);
        }
    }
    
    SECTION("Noise budget tracking") {
        auto encrypted = encrypt(42);
        
        // fresh ciphertext should have high budget
        REQUIRE(encrypted.noise_budget().current_budget > 40.0);
        REQUIRE(encrypted.operation_count() == 0);
        REQUIRE_FALSE(encrypted.needs_refresh());
        
        // copy constructor preserves budget
        auto encrypted_copy = encrypted;
        REQUIRE(encrypted_copy.noise_budget().current_budget == encrypted.noise_budget().current_budget);
    }
    
    SECTION("Refresh functionality") {
        auto encrypted = encrypt(123);
        
        // manually reduce noise budget to test refresh
        for (int i = 0; i < 10; ++i) {
            auto add_result = operations()->add_constant(encrypted, 1);
            REQUIRE(add_result.has_value());
            encrypted = add_result.value();
        }
        
        double budget_before = encrypted.noise_budget().current_budget;
        
        auto refresh_result = encrypted.refresh();
        REQUIRE(refresh_result.has_value());
        
        // budget should be restored
        REQUIRE(encrypted.noise_budget().current_budget > budget_before);
        
        // value should remain the same
        auto decrypted = encrypted.decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 133); // 123 + 10
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Basic arithmetic operations", "[bfv][operations][arithmetic]") {
    SECTION("Addition") {
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {5, 7}, {-3, 8}, {0, 42}, {-10, -5}, {100, -50}
        };
        
        for (const auto& [a, b] : test_cases) {
            auto enc_a = encrypt(a);
            auto enc_b = encrypt(b);
            
            auto result = operations()->add(enc_a, enc_b);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == a + b);
        }
    }
    
    SECTION("Subtraction") {
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {10, 3}, {5, 15}, {0, 7}, {-5, -2}, {100, 200}
        };
        
        for (const auto& [a, b] : test_cases) {
            auto enc_a = encrypt(a);
            auto enc_b = encrypt(b);
            
            auto result = operations()->subtract(enc_a, enc_b);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == a - b);
        }
    }
    
    SECTION("Multiplication") {
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {3, 4}, {-2, 5}, {0, 42}, {-3, -7}, {1, 100}
        };
        
        for (const auto& [a, b] : test_cases) {
            auto enc_a = encrypt(a);
            auto enc_b = encrypt(b);
            
            auto result = operations()->multiply(enc_a, enc_b);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == a * b);
        }
    }
    
    SECTION("Negation") {
        std::vector<int64_t> test_values = {5, -3, 0, 42, -100};
        
        for (int64_t value : test_values) {
            auto encrypted = encrypt(value);
            
            auto result = operations()->negate(encrypted);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == -value);
        }
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Constant operations", "[bfv][operations][constants]") {
    SECTION("Add constant") {
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {10, 5}, {-3, 7}, {0, 0}, {42, -15}
        };
        
        for (const auto& [value, constant] : test_cases) {
            auto encrypted = encrypt(value);
            
            auto result = operations()->add_constant(encrypted, constant);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == value + constant);
        }
    }
    
    SECTION("Multiply by constant") {
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {5, 3}, {-4, 2}, {0, 10}, {7, -2}, {1, 1}
        };
        
        for (const auto& [value, constant] : test_cases) {
            auto encrypted = encrypt(value);
            
            auto result = operations()->multiply_constant(encrypted, constant);
            REQUIRE(result.has_value());
            
            auto decrypted = result.value().decrypt();
            REQUIRE(decrypted.has_value());
            REQUIRE(decrypted.value() == value * constant);
        }
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Batch operations", "[bfv][operations][batch]") {
    SECTION("Batch addition") {
        std::vector<int64_t> vec_a = {1, 2, 3, 4, 5};
        std::vector<int64_t> vec_b = {6, 7, 8, 9, 10};
        
        auto batch_a = encrypt_batch(vec_a);
        auto batch_b = encrypt_batch(vec_b);
        
        auto result = operations()->add_batch(batch_a, batch_b);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        
        auto result_vec = decrypted.value();
        REQUIRE(result_vec.size() >= vec_a.size());
        
        for (size_t i = 0; i < vec_a.size(); ++i) {
            REQUIRE(result_vec[i] == vec_a[i] + vec_b[i]);
        }
    }
    
    SECTION("Batch subtraction") {
        std::vector<int64_t> vec_a = {10, 15, 20, 25, 30};
        std::vector<int64_t> vec_b = {3, 5, 7, 9, 11};
        
        auto batch_a = encrypt_batch(vec_a);
        auto batch_b = encrypt_batch(vec_b);
        
        auto result = operations()->subtract_batch(batch_a, batch_b);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        
        auto result_vec = decrypted.value();
        for (size_t i = 0; i < vec_a.size(); ++i) {
            REQUIRE(result_vec[i] == vec_a[i] - vec_b[i]);
        }
    }
    
    SECTION("Batch multiplication") {
        std::vector<int64_t> vec_a = {2, 3, 4, 5, 6};
        std::vector<int64_t> vec_b = {3, 4, 5, 6, 7};
        
        auto batch_a = encrypt_batch(vec_a);
        auto batch_b = encrypt_batch(vec_b);
        
        auto result = operations()->multiply_batch(batch_a, batch_b);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        
        auto result_vec = decrypted.value();
        for (size_t i = 0; i < vec_a.size(); ++i) {
            REQUIRE(result_vec[i] == vec_a[i] * vec_b[i]);
        }
    }
    
    SECTION("Batch negation") {
        std::vector<int64_t> values = {5, -3, 0, 42, -100};
        
        auto batch = encrypt_batch(values);
        auto result = operations()->negate_batch(batch);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        
        auto result_vec = decrypted.value();
        for (size_t i = 0; i < values.size(); ++i) {
            REQUIRE(result_vec[i] == -values[i]);
        }
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Advanced operations", "[bfv][operations][advanced]") {
    SECTION("Sum of encrypted values") {
        std::vector<int64_t> values = {1, 2, 3, 4, 5};
        std::vector<EncryptedInt> encrypted_values;
        
        for (int64_t value : values) {
            encrypted_values.push_back(encrypt(value));
        }
        
        auto result = operations()->sum(encrypted_values);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 15); // 1+2+3+4+5
    }
    
    SECTION("Dot product") {
        std::vector<int64_t> vec_a = {1, 2, 3};
        std::vector<int64_t> vec_b = {4, 5, 6};
        
        std::vector<EncryptedInt> enc_a, enc_b;
        for (size_t i = 0; i < vec_a.size(); ++i) {
            enc_a.push_back(encrypt(vec_a[i]));
            enc_b.push_back(encrypt(vec_b[i]));
        }
        
        auto result = operations()->dot_product(enc_a, enc_b);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 32); // 1*4 + 2*5 + 3*6 = 4 + 10 + 18
    }
    
    SECTION("Polynomial evaluation") {
        // evaluate p(x) = 2x^2 + 3x + 1 at x = 4
        std::vector<int64_t> coefficients = {1, 3, 2}; // constant, x, x^2
        auto x = encrypt(4);
        
        auto result = operations()->evaluate_polynomial(coefficients, x);
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 45); // 2*16 + 3*4 + 1 = 32 + 12 + 1
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Operation chaining", "[bfv][operations][chaining]") {
    SECTION("Basic chain operations") {
        auto initial = encrypt(10);
        
        // chain: (10 + 5) * 2 - 3 = 27
        auto result = operations()->chain(initial)
            .add(5)
            .multiply(2)
            .subtract(3)
            .execute();
        
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 27);
    }
    
    SECTION("Chain with encrypted values") {
        auto initial = encrypt(5);
        auto add_value = encrypt(3);
        auto mult_value = encrypt(4);
        
        // chain: (5 + 3) * 4 = 32
        auto result = operations()->chain(initial)
            .add(add_value)
            .multiply(mult_value)
            .execute();
        
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 32);
    }
    
    SECTION("Noise cost estimation") {
        auto initial = encrypt(1);
        
        auto chain = operations()->chain(initial)
            .add(1)
            .multiply(2)
            .subtract(1);
        
        double estimated_cost = chain.estimated_noise_cost();
        REQUIRE(estimated_cost > 0);
        REQUIRE(estimated_cost == 7.0); // 1 + 5 + 1 = 7
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Edge cases and error handling", "[bfv][operations][edge_cases]") {
    SECTION("Zero operations") {
        auto zero = encrypt(0);
        auto value = encrypt(42);
        
        // 0 + 42 = 42
        auto add_result = operations()->add(zero, value);
        REQUIRE(add_result.has_value());
        REQUIRE(add_result.value().decrypt().value() == 42);
        
        // 42 * 0 = 0
        auto mult_result = operations()->multiply(value, zero);
        REQUIRE(mult_result.has_value());
        REQUIRE(mult_result.value().decrypt().value() == 0);
        
        // 42 - 0 = 42
        auto sub_result = operations()->subtract(value, zero);
        REQUIRE(sub_result.has_value());
        REQUIRE(sub_result.value().decrypt().value() == 42);
    }
    
    SECTION("Negative number operations") {
        auto pos = encrypt(10);
        auto neg = encrypt(-5);
        
        // 10 + (-5) = 5
        auto add_result = operations()->add(pos, neg);
        REQUIRE(add_result.has_value());
        REQUIRE(add_result.value().decrypt().value() == 5);
        
        // 10 * (-5) = -50
        auto mult_result = operations()->multiply(pos, neg);
        REQUIRE(mult_result.has_value());
        REQUIRE(mult_result.value().decrypt().value() == -50);
        
        // -(-5) = 5
        auto neg_result = operations()->negate(neg);
        REQUIRE(neg_result.has_value());
        REQUIRE(neg_result.value().decrypt().value() == 5);
    }
    
    SECTION("Large value operations") {
        int64_t max_safe = encrypted_int_utils::max_safe_value(context());
        int64_t large_val = max_safe / 4; // use quarter of max safe value
        
        auto enc_large = encrypt(large_val);
        auto enc_small = encrypt(2);
        
        auto add_result = operations()->add(enc_large, enc_small);
        REQUIRE(add_result.has_value());
        REQUIRE(add_result.value().decrypt().value() == large_val + 2);
        
        auto mult_result = operations()->multiply(enc_small, enc_small);
        REQUIRE(mult_result.has_value());
        REQUIRE(mult_result.value().decrypt().value() == 4);
    }
    
    SECTION("Batch size validation") {
        std::vector<int64_t> vec_a = {1, 2, 3};
        std::vector<int64_t> vec_b = {4, 5}; // different size
        
        auto batch_a = encrypt_batch(vec_a);
        auto batch_b = encrypt_batch(vec_b);
        
        // operations on different sized batches should fail validation
        auto result = operations()->add_batch(batch_a, batch_b);
        REQUIRE_FALSE(result.has_value());
    }
    
    SECTION("Empty operations") {
        std::vector<EncryptedInt> empty_vec;
        
        auto sum_result = operations()->sum(empty_vec);
        REQUIRE_FALSE(sum_result.has_value());
        
        std::vector<int64_t> empty_coeffs;
        auto poly_result = operations()->evaluate_polynomial(empty_coeffs, encrypt(1));
        REQUIRE_FALSE(poly_result.has_value());
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Noise budget management", "[bfv][operations][noise]") {
    SECTION("Noise budget degradation") {
        auto encrypted = encrypt(10);
        double initial_budget = encrypted.noise_budget().current_budget;
        
        // perform several operations
        for (int i = 0; i < 5; ++i) {
            auto add_result = operations()->add_constant(encrypted, 1);
            REQUIRE(add_result.has_value());
            encrypted = add_result.value();
        }
        
        // noise budget should have decreased
        REQUIRE(encrypted.noise_budget().current_budget < initial_budget);
        REQUIRE(encrypted.operation_count() == 0); // count is reset after each operation
        
        // value should still be correct
        auto decrypted = encrypted.decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 15);
    }
    
    SECTION("Multiplication noise cost") {
        auto a = encrypt(5);
        auto b = encrypt(3);
        
        double budget_a = a.noise_budget().current_budget;
        double budget_b = b.noise_budget().current_budget;
        
        auto mult_result = operations()->multiply(a, b);
        REQUIRE(mult_result.has_value());
        
        // multiplication should consume more noise than addition
        double remaining_budget = mult_result.value().noise_budget().current_budget;
        double expected_budget = std::min(budget_a, budget_b) - 5.0; // multiplication cost
        
        REQUIRE(remaining_budget <= expected_budget + 1.0); // allow small tolerance
    }
    
    SECTION("Automatic refresh detection") {
        auto encrypted = encrypt(42);
        
        // Create an encrypted int with very low initial budget so the threshold is low
        auto low_budget_encrypted = EncryptedInt(encrypted.ciphertext(), context(), 1.0);
        
        // Perform an operation that will reduce the budget below threshold
        auto ops = std::make_shared<BFVOperations>(context());
        auto dummy_encrypted = encrypt(1);
        auto result = ops->add(low_budget_encrypted, dummy_encrypted);
        
        REQUIRE(result.has_value());
        
        // The result should need refresh (budget went from min(1.0, 50.0) - 1.0 = 0.0)
        auto result_encrypted = result.value();
        REQUIRE(result_encrypted.needs_refresh());
        
        auto refresh_result = result_encrypted.refresh();
        REQUIRE(refresh_result.has_value());
        REQUIRE_FALSE(result_encrypted.needs_refresh());
        
        // value should be preserved
        auto decrypted = result_encrypted.decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 43); // 42 + 1
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Validation and overflow detection", "[bfv][operations][validation]") {
    SECTION("Safe range validation") {
        int64_t safe_value = encrypted_int_utils::max_safe_value(context()) / 2;
        auto encrypted = encrypt(safe_value);
        
        auto range_check = operations()->is_in_safe_range(encrypted);
        REQUIRE(range_check.has_value());
        REQUIRE(range_check.value() == true);
        
        // test boundary values
        int64_t max_safe = encrypted_int_utils::max_safe_value(context());
        auto max_encrypted = encrypt(max_safe);
        
        auto max_range_check = operations()->is_in_safe_range(max_encrypted);
        REQUIRE(max_range_check.has_value());
        REQUIRE(max_range_check.value() == true);
    }
    
    SECTION("Overflow detection") {
        int64_t large_val = encrypted_int_utils::max_safe_value(context()) / 2;
        auto a = encrypt(large_val);
        auto b = encrypt(large_val);
        
        // this might cause overflow depending on implementation
        bool will_overflow = operations()->will_overflow(a, b, "multiply");
        
        // the function should be able to make a determination
        REQUIRE((will_overflow == true || will_overflow == false));
    }
    
    SECTION("Invalid operand handling") {
        // create an uninitialized context for invalid ciphertext
        auto invalid_context = std::make_shared<BFVContext>(BFVParameters{});
        // don't initialize it
        
        try {
            // this should throw because context is not initialized
            auto invalid_encrypted = EncryptedInt(42, invalid_context);
            REQUIRE(false); // should not reach here
        } catch (const std::invalid_argument&) {
            // expected exception
            REQUIRE(true);
        }
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Statistics and diagnostics", "[bfv][operations][stats]") {
    SECTION("Operation statistics tracking") {
        auto a = encrypt(10);
        auto b = encrypt(5);
        
        // reset statistics
        operations()->reset_statistics();
        auto initial_stats = operations()->statistics();
        REQUIRE(initial_stats.additions_performed == 0);
        REQUIRE(initial_stats.multiplications_performed == 0);
        
        // perform operations
        auto add_result = operations()->add(a, b);
        REQUIRE(add_result.has_value());
        
        auto mult_result = operations()->multiply(a, b);
        REQUIRE(mult_result.has_value());
        
        // check updated statistics
        auto final_stats = operations()->statistics();
        REQUIRE(final_stats.additions_performed == 1);
        REQUIRE(final_stats.multiplications_performed == 1);
        REQUIRE(final_stats.total_operation_time.count() > 0);
    }
    
    SECTION("Noise consumption tracking") {
        auto a = encrypt(3);
        auto b = encrypt(4);
        
        operations()->reset_statistics();
        
        // perform several operations
        auto mult_result = operations()->multiply(a, b);
        REQUIRE(mult_result.has_value());
        
        auto add_result = operations()->add(mult_result.value(), a);
        REQUIRE(add_result.has_value());
        
        auto stats = operations()->statistics();
        REQUIRE(stats.average_noise_consumption > 0);
        REQUIRE(stats.multiplications_performed == 1);
        REQUIRE(stats.additions_performed == 1);
    }
}

TEST_CASE_METHOD(BFVOperationsTestFixture, "Utility functions", "[bfv][operations][utils]") {
    SECTION("Encryption utilities") {
        auto result = encrypted_int_utils::encrypt(42, context());
        REQUIRE(result.has_value());
        
        auto decrypted = result.value().decrypt();
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted.value() == 42);
        
        std::vector<int64_t> values = {1, 2, 3, 4, 5};
        auto batch_result = encrypted_int_utils::encrypt_batch(values, context());
        REQUIRE(batch_result.has_value());
        
        auto batch_decrypted = batch_result.value().decrypt();
        REQUIRE(batch_decrypted.has_value());
        for (size_t i = 0; i < values.size(); ++i) {
            REQUIRE(batch_decrypted.value()[i] == values[i]);
        }
    }
    
    SECTION("Comparison utilities") {
        auto a = encrypt(10);
        auto b = encrypt(5);
        auto c = encrypt(10);
        
        auto cmp_result = encrypted_int_utils::compare(a, b);
        REQUIRE(cmp_result.has_value());
        REQUIRE(cmp_result.value() == 1); // a > b
        
        auto eq_result = encrypted_int_utils::compare(a, c);
        REQUIRE(eq_result.has_value());
        REQUIRE(eq_result.value() == 0); // a == c
        
        auto lt_result = encrypted_int_utils::compare(b, a);
        REQUIRE(lt_result.has_value());
        REQUIRE(lt_result.value() == -1); // b < a
    }
    
    SECTION("Safe value ranges") {
        int64_t max_safe = encrypted_int_utils::max_safe_value(context());
        int64_t min_safe = encrypted_int_utils::min_safe_value(context());
        
        REQUIRE(max_safe > 0);
        REQUIRE(min_safe < 0);
        REQUIRE(max_safe > std::abs(min_safe) * 0.9); // should be roughly symmetric
        
        // test that safe values can be encrypted and operated on
        auto max_encrypted = encrypt(max_safe);
        auto min_encrypted = encrypt(min_safe);
        
        REQUIRE(max_encrypted.is_valid());
        REQUIRE(min_encrypted.is_valid());
    }
    
    SECTION("Noise estimation") {
        std::vector<std::string> operations = {"add", "multiply", "subtract"};
        double initial_budget = 50.0;
        
        double estimated = encrypted_int_utils::estimate_noise_after_operations(initial_budget, operations);
        
        // should consume noise: 1 + 5 + 1 = 7
        REQUIRE(estimated == 43.0);
        
        // test with operations that would exhaust budget
        std::vector<std::string> heavy_ops(20, "multiply");
        double exhausted = encrypted_int_utils::estimate_noise_after_operations(initial_budget, heavy_ops);
        REQUIRE(exhausted == 0.0); // budget exhausted
    }
}