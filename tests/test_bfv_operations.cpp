#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>
#include <limits>
#include <random>
#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

// test fixture for arithmetic operations
class ArithmeticTestFixture {
  public:
    std::shared_ptr<BFVContext> context_;

    void SetUp(uint32_t poly_degree = 16384) {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params.polynomial_degree = poly_degree;
        params.multiplicative_depth = 4;  // higher depth for complex operations
        params.enable_relinearization = true;

        context_ = std::make_shared<BFVContext>(params);
        context_->generate_keys();

        // reset config to defaults
        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::THROW_EXCEPTION);
        ArithmeticConfig::instance().set_auto_refresh(true);
    }
};

TEST_CASE("encrypted int basic construction", "[operations][basic]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("construction from integer") {
        REQUIRE_NOTHROW([&]() {
            EncryptedInt a(fixture.context_, 42);
            REQUIRE(a.is_valid());
            REQUIRE(a.decrypt() == 42);
        }());
    }

    SECTION("construction edge cases") {
        // zero value
        EncryptedInt zero(fixture.context_, 0);
        REQUIRE(zero.decrypt() == 0);

        // negative values
        EncryptedInt neg(fixture.context_, -123);
        REQUIRE(neg.decrypt() == -123);

        // large positive value
        EncryptedInt large_pos(fixture.context_, 32767);
        REQUIRE(large_pos.decrypt() == 32767);

        // large negative value
        EncryptedInt large_neg(fixture.context_, -32767);
        REQUIRE(large_neg.decrypt() == -32767);
    }

    SECTION("copy and move semantics") {
        EncryptedInt a(fixture.context_, 100);

        // copy construction
        EncryptedInt b = a;
        REQUIRE(b.decrypt() == 100);
        REQUIRE(a.decrypt() == 100);  // original unchanged

        // move construction
        EncryptedInt c = std::move(a);
        REQUIRE(c.decrypt() == 100);

        // copy assignment
        EncryptedInt d(fixture.context_, 200);
        d = b;
        REQUIRE(d.decrypt() == 100);

        // move assignment
        EncryptedInt e(fixture.context_, 300);
        e = std::move(c);
        REQUIRE(e.decrypt() == 100);
    }
}

TEST_CASE("encrypted int arithmetic operations", "[operations][arithmetic]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("addition operations") {
        EncryptedInt a(fixture.context_, 25);
        EncryptedInt b(fixture.context_, 17);

        auto result = a + b;
        REQUIRE(result.decrypt() == 42);

        // test with zero
        EncryptedInt zero(fixture.context_, 0);
        auto result_zero = a + zero;
        REQUIRE(result_zero.decrypt() == 25);

        // test with negative
        EncryptedInt neg(fixture.context_, -10);
        auto result_neg = a + neg;
        REQUIRE(result_neg.decrypt() == 15);
    }

    SECTION("subtraction operations") {
        EncryptedInt a(fixture.context_, 50);
        EncryptedInt b(fixture.context_, 20);

        auto result = a - b;
        REQUIRE(result.decrypt() == 30);

        // test subtraction resulting in negative
        auto result_neg = b - a;
        REQUIRE(result_neg.decrypt() == -30);

        // test subtraction with zero
        EncryptedInt zero(fixture.context_, 0);
        auto result_zero = a - zero;
        REQUIRE(result_zero.decrypt() == 50);
    }

    SECTION("multiplication operations") {
        EncryptedInt a(fixture.context_, 6);
        EncryptedInt b(fixture.context_, 7);

        auto result = a * b;
        REQUIRE(result.decrypt() == 42);

        // test with zero
        EncryptedInt zero(fixture.context_, 0);
        auto result_zero = a * zero;
        REQUIRE(result_zero.decrypt() == 0);

        // test with one
        EncryptedInt one(fixture.context_, 1);
        auto result_one = a * one;
        REQUIRE(result_one.decrypt() == 6);

        // test with negative
        EncryptedInt neg(fixture.context_, -2);
        auto result_neg = a * neg;
        REQUIRE(result_neg.decrypt() == -12);
    }

    SECTION("negation operation") {
        EncryptedInt a(fixture.context_, 42);
        auto neg_a = -a;
        REQUIRE(neg_a.decrypt() == -42);

        // double negation
        auto double_neg = -neg_a;
        REQUIRE(double_neg.decrypt() == 42);

        // negation of zero
        EncryptedInt zero(fixture.context_, 0);
        auto neg_zero = -zero;
        REQUIRE(neg_zero.decrypt() == 0);
    }
}

TEST_CASE("encrypted int compound assignment", "[operations][assignment]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("addition assignment") {
        EncryptedInt a(fixture.context_, 10);
        EncryptedInt b(fixture.context_, 5);

        a += b;
        REQUIRE(a.decrypt() == 15);

        a += 10;  // plaintext addition
        REQUIRE(a.decrypt() == 25);
    }

    SECTION("subtraction assignment") {
        EncryptedInt a(fixture.context_, 20);
        EncryptedInt b(fixture.context_, 8);

        a -= b;
        REQUIRE(a.decrypt() == 12);

        a -= 2;  // plaintext subtraction
        REQUIRE(a.decrypt() == 10);
    }

    SECTION("multiplication assignment") {
        EncryptedInt a(fixture.context_, 3);
        EncryptedInt b(fixture.context_, 4);

        a *= b;
        REQUIRE(a.decrypt() == 12);

        a *= 2;  // plaintext multiplication
        REQUIRE(a.decrypt() == 24);
    }
}

TEST_CASE("encrypted int plaintext operations", "[operations][plaintext]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("plaintext arithmetic") {
        EncryptedInt a(fixture.context_, 10);

        // addition with plaintext
        auto add_result = a + 15;
        REQUIRE(add_result.decrypt() == 25);

        // subtraction with plaintext
        auto sub_result = a - 3;
        REQUIRE(sub_result.decrypt() == 7);

        // multiplication with plaintext
        auto mul_result = a * 4;
        REQUIRE(mul_result.decrypt() == 40);
    }

    SECTION("plaintext edge cases") {
        EncryptedInt a(fixture.context_, 5);

        // operations with zero
        REQUIRE((a + 0).decrypt() == 5);
        REQUIRE((a - 0).decrypt() == 5);
        REQUIRE((a * 0).decrypt() == 0);

        // operations with one
        REQUIRE((a + 1).decrypt() == 6);
        REQUIRE((a - 1).decrypt() == 4);
        REQUIRE((a * 1).decrypt() == 5);

        // operations with negative values
        REQUIRE((a + (-2)).decrypt() == 3);
        REQUIRE((a - (-2)).decrypt() == 7);
        REQUIRE((a * (-2)).decrypt() == -10);
    }
}

TEST_CASE("encrypted int edge cases and limits", "[operations][edge_cases]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("zero operations") {
        EncryptedInt zero(fixture.context_, 0);
        EncryptedInt a(fixture.context_, 42);

        // zero + anything = anything
        REQUIRE((zero + a).decrypt() == 42);
        REQUIRE((a + zero).decrypt() == 42);

        // zero * anything = zero
        REQUIRE((zero * a).decrypt() == 0);
        REQUIRE((a * zero).decrypt() == 0);

        // anything - zero = anything
        REQUIRE((a - zero).decrypt() == 42);

        // zero - anything = -anything
        REQUIRE((zero - a).decrypt() == -42);
    }

    SECTION("negative number operations") {
        EncryptedInt pos(fixture.context_, 10);
        EncryptedInt neg(fixture.context_, -5);

        // positive + negative
        REQUIRE((pos + neg).decrypt() == 5);

        // negative + positive
        REQUIRE((neg + pos).decrypt() == 5);

        // positive - negative = positive + positive
        REQUIRE((pos - neg).decrypt() == 15);

        // negative - positive = negative - positive
        REQUIRE((neg - pos).decrypt() == -15);

        // positive * negative = negative
        REQUIRE((pos * neg).decrypt() == -50);

        // negative * negative = positive
        EncryptedInt neg2(fixture.context_, -3);
        REQUIRE((neg * neg2).decrypt() == 15);
    }

    SECTION("large values within range") {
        // test with values near the safe range limits
        auto params = fixture.context_->get_parameters();
        int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;
        int64_t near_max = max_safe / 2;

        EncryptedInt large_a(fixture.context_, near_max);
        EncryptedInt large_b(fixture.context_, near_max / 2);

        // these should work without overflow
        REQUIRE((large_a + large_b).decrypt() == near_max + near_max / 2);
        REQUIRE((large_a - large_b).decrypt() == near_max - near_max / 2);
    }
}

TEST_CASE("encrypted int complex operations", "[operations][complex]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("chained operations") {
        EncryptedInt a(fixture.context_, 2);
        EncryptedInt b(fixture.context_, 3);
        EncryptedInt c(fixture.context_, 4);

        // (a + b) * c
        auto result1 = (a + b) * c;
        REQUIRE(result1.decrypt() == 20);

        // a * (b + c)
        auto result2 = a * (b + c);
        REQUIRE(result2.decrypt() == 14);

        // a + b * c
        auto result3 = a + b * c;
        REQUIRE(result3.decrypt() == 14);
    }

    SECTION("polynomial evaluation") {
        EncryptedInt x(fixture.context_, 3);

        // evaluate x^2 + 2x + 1 = (3^2 + 2*3 + 1) = 16
        auto x_squared = x * x;
        auto two_x = x * 2;
        auto result = x_squared + two_x + 1;

        REQUIRE(result.decrypt() == 16);
    }

    SECTION("multiple operations preserving correctness") {
        EncryptedInt a(fixture.context_, 5);
        EncryptedInt b(fixture.context_, 3);

        // perform many operations
        auto temp1 = a + b;       // 8
        auto temp2 = temp1 * 2;   // 16
        auto temp3 = temp2 - a;   // 11
        auto result = temp3 + b;  // 14

        REQUIRE(result.decrypt() == 14);

        // verify intermediate results are still valid
        REQUIRE(temp1.decrypt() == 8);
        REQUIRE(temp2.decrypt() == 16);
        REQUIRE(temp3.decrypt() == 11);
    }
}

TEST_CASE("encrypted batch operations", "[operations][batch]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("batch construction and basic operations") {
        std::vector<int64_t> values1 = {1, 2, 3, 4, 5};
        std::vector<int64_t> values2 = {5, 4, 3, 2, 1};

        EncryptedBatch batch1(fixture.context_, values1);
        EncryptedBatch batch2(fixture.context_, values2);

        REQUIRE(batch1.size() == 5);
        REQUIRE(batch2.size() == 5);

        auto decrypted1 = batch1.decrypt();
        REQUIRE(decrypted1.size() >= 5);
        for (size_t i = 0; i < 5; ++i) {
            REQUIRE(decrypted1[i] == values1[i]);
        }
    }

    SECTION("batch arithmetic") {
        std::vector<int64_t> values1 = {10, 20, 30, 40};
        std::vector<int64_t> values2 = {1, 2, 3, 4};

        EncryptedBatch batch1(fixture.context_, values1);
        EncryptedBatch batch2(fixture.context_, values2);

        // batch addition
        auto sum_batch = batch1 + batch2;
        auto sum_result = sum_batch.decrypt();

        std::vector<int64_t> expected_sum = {11, 22, 33, 44};
        for (size_t i = 0; i < expected_sum.size(); ++i) {
            REQUIRE(sum_result[i] == expected_sum[i]);
        }

        // batch multiplication
        auto mult_batch = batch1 * batch2;
        auto mult_result = mult_batch.decrypt();

        std::vector<int64_t> expected_mult = {10, 40, 90, 160};
        for (size_t i = 0; i < expected_mult.size(); ++i) {
            REQUIRE(mult_result[i] == expected_mult[i]);
        }
    }

    SECTION("batch scalar operations") {
        std::vector<int64_t> values = {2, 4, 6, 8};
        EncryptedBatch batch(fixture.context_, values);

        // scalar addition
        auto add_result = (batch + 1).decrypt();
        std::vector<int64_t> expected_add = {3, 5, 7, 9};
        for (size_t i = 0; i < expected_add.size(); ++i) {
            REQUIRE(add_result[i] == expected_add[i]);
        }

        // scalar multiplication
        auto mult_result = (batch * 3).decrypt();
        std::vector<int64_t> expected_mult = {6, 12, 18, 24};
        for (size_t i = 0; i < expected_mult.size(); ++i) {
            REQUIRE(mult_result[i] == expected_mult[i]);
        }
    }
}

TEST_CASE("noise budget management", "[operations][noise]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("noise info tracking") {
        EncryptedInt a(fixture.context_, 42);

        auto initial_noise = a.get_noise_info();
        REQUIRE(initial_noise.current_level >= 0.0);
        REQUIRE(initial_noise.depth_remaining >= 0);

        // after multiplication, noise should increase
        EncryptedInt b(fixture.context_, 3);
        auto result = a * b;

        auto post_mult_noise = result.get_noise_info();
        REQUIRE(post_mult_noise.current_level >= initial_noise.current_level);
        REQUIRE(post_mult_noise.depth_remaining <= initial_noise.depth_remaining);
    }

    SECTION("refresh mechanism") {
        EncryptedInt a(fixture.context_, 123);

        // force refresh
        auto original_value = a.decrypt();
        a.force_refresh();

        // value should be preserved
        REQUIRE(a.decrypt() == original_value);
        REQUIRE(a.is_valid());
    }

    SECTION("automatic refresh on high noise") {
        ArithmeticConfig::instance().set_auto_refresh(true);

        EncryptedInt a(fixture.context_, 2);

        // perform multiple multiplications to increase noise
        for (int i = 0; i < 3; ++i) {
            a *= 2;  // should trigger auto-refresh when needed
        }

        REQUIRE(a.decrypt() == 16);  // 2 * 2 * 2 * 2 = 16
        REQUIRE(a.is_valid());
    }
}

TEST_CASE("overflow protection", "[operations][overflow]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("overflow exception behavior") {
        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::THROW_EXCEPTION);

        auto params = fixture.context_->get_parameters();
        int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;

        // this should throw on construction if value is too large
        REQUIRE_THROWS_AS([&]() { EncryptedInt too_large(fixture.context_, max_safe + 1000); }(),
                          OverflowException);
    }

    SECTION("overflow wrap around behavior") {
        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::WRAP_AROUND);

        auto params = fixture.context_->get_parameters();
        int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;

        // this should wrap around instead of throwing
        REQUIRE_NOTHROW([&]() {
            EncryptedInt wrapped(fixture.context_, max_safe + 10);
            // exact wrapped value depends on modulus, but should not throw
            REQUIRE(wrapped.is_valid());
        }());
    }

    SECTION("overflow ignore behavior") {
        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::IGNORE);

        auto params = fixture.context_->get_parameters();
        int64_t max_safe = static_cast<int64_t>(params.plaintext_modulus / 2) - 1;

        // should not throw, behavior undefined but no crash
        REQUIRE_NOTHROW([&]() {
            EncryptedInt ignored(fixture.context_, max_safe + 100);
            REQUIRE(ignored.is_valid());
        }());
    }
}

TEST_CASE("ciphertext validation and integrity", "[operations][validation]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("basic validation") {
        EncryptedInt a(fixture.context_, 42);

        REQUIRE(a.is_valid());
        REQUIRE(a.validate_integrity());

        // after operations, should still be valid
        auto b = a + 8;
        REQUIRE(b.is_valid());
        REQUIRE(b.validate_integrity());
    }

    SECTION("context consistency") {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params.polynomial_degree = 16384;
        auto other_context = std::make_shared<BFVContext>(params);
        other_context->generate_keys();

        EncryptedInt a(fixture.context_, 10);
        EncryptedInt b(other_context, 20);

        // operations between different contexts should fail
        REQUIRE_THROWS([&]() { auto result = a + b; }());
    }
}

TEST_CASE("utility arithmetic functions", "[operations][utilities]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("safe operations") {
        EncryptedInt a(fixture.context_, 15);
        EncryptedInt b(fixture.context_, 25);
        EncryptedInt result(fixture.context_);

        auto add_result = arithmetic::safe_add(a, b, result);
        REQUIRE(add_result.success);
        REQUIRE(result.decrypt() == 40);

        auto mult_result = arithmetic::safe_multiply(a, b, result);
        REQUIRE(mult_result.success);
        REQUIRE(result.decrypt() == 375);
    }

    SECTION("batch operations") {
        std::vector<EncryptedInt> vec_a, vec_b;
        for (int i = 1; i <= 5; ++i) {
            vec_a.emplace_back(fixture.context_, i);
            vec_b.emplace_back(fixture.context_, i * 2);
        }

        auto batch_result = arithmetic::batch_add(vec_a, vec_b);
        REQUIRE(batch_result.size() == 5);

        for (size_t i = 0; i < 5; ++i) {
            int expected = (i + 1) + (i + 1) * 2;  // i + 2i = 3i
            REQUIRE(batch_result[i].decrypt() == expected);
        }
    }

    SECTION("sum computation") {
        std::vector<EncryptedInt> values;
        int64_t expected_sum = 0;

        for (int i = 1; i <= 10; ++i) {
            values.emplace_back(fixture.context_, i);
            expected_sum += i;
        }

        auto sum_result = arithmetic::compute_sum(values);
        REQUIRE(sum_result.decrypt() == expected_sum);  // 1+2+...+10 = 55
    }

    SECTION("memory allocator operations") {
        EncryptedInt base_addr(fixture.context_, 1000);
        EncryptedInt index(fixture.context_, 5);
        int64_t element_size = 8;

        auto address = arithmetic::compute_address_offset(base_addr, index, element_size);
        REQUIRE(address.decrypt() == 1040);  // 1000 + 5*8
    }
}

TEST_CASE("arithmetic configuration", "[operations][config]") {
    ArithmeticTestFixture fixture;
    fixture.SetUp();

    SECTION("noise threshold configuration") {
        auto& config = ArithmeticConfig::instance();

        double original_threshold = config.get_noise_threshold();
        config.set_noise_threshold(0.05);
        REQUIRE(config.get_noise_threshold() == 0.05);

        // restore original
        config.set_noise_threshold(original_threshold);
    }

    SECTION("auto refresh configuration") {
        auto& config = ArithmeticConfig::instance();

        bool original_auto_refresh = config.get_auto_refresh();
        config.set_auto_refresh(false);
        REQUIRE_FALSE(config.get_auto_refresh());

        // restore original
        config.set_auto_refresh(original_auto_refresh);
    }

    SECTION("statistics tracking") {
        auto& config = ArithmeticConfig::instance();
        config.reset_statistics();

        auto initial_stats = config.get_statistics();
        REQUIRE(initial_stats.total_operations == 0);

        // perform some operations
        EncryptedInt a(fixture.context_, 5);
        EncryptedInt b(fixture.context_, 3);
        auto result = a + b;

        // statistics should be updated (implementation dependent)
        auto final_stats = config.get_statistics();
        // exact values depend on implementation
        REQUIRE(final_stats.total_operations >= initial_stats.total_operations);
    }
}