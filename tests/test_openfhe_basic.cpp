#include <catch2/catch_test_macros.hpp>
#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

TEST_CASE("openfhe context creation", "[openfhe]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 1;

    REQUIRE_NOTHROW([&]() {
        cryptmalloc::OpenFHEContext context(params);
        REQUIRE(context.is_valid());
    }());
}

TEST_CASE("basic encryption and decryption", "[openfhe]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 1;

    cryptmalloc::OpenFHEContext context(params);
    REQUIRE(context.is_valid());

    SECTION("encrypt and decrypt single value") {
        int64_t original_value = 42;

        auto ciphertext = context.encrypt(original_value);
        auto decrypted_value = context.decrypt(ciphertext);

        REQUIRE(decrypted_value == original_value);
    }

    SECTION("encrypt and decrypt multiple values") {
        std::vector<int64_t> test_values = {0, 1, 42, 123, 999, 12345};

        for (auto value : test_values) {
            auto ciphertext = context.encrypt(value);
            auto decrypted_value = context.decrypt(ciphertext);
            REQUIRE(decrypted_value == value);
        }
    }
}

TEST_CASE("homomorphic operations", "[openfhe]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 2;  // need depth for mult

    cryptmalloc::OpenFHEContext context(params);
    REQUIRE(context.is_valid());

    SECTION("homomorphic addition") {
        int64_t a = 15;
        int64_t b = 27;

        auto ct_a = context.encrypt(a);
        auto ct_b = context.encrypt(b);
        auto ct_sum = context.add(ct_a, ct_b);

        auto result = context.decrypt(ct_sum);
        REQUIRE(result == a + b);
    }

    SECTION("homomorphic multiplication") {
        int64_t a = 7;
        int64_t b = 6;

        auto ct_a = context.encrypt(a);
        auto ct_b = context.encrypt(b);
        auto ct_product = context.multiply(ct_a, ct_b);

        auto result = context.decrypt(ct_product);
        REQUIRE(result == a * b);
    }

    SECTION("complex operations") {
        int64_t a = 5;
        int64_t b = 3;
        int64_t c = 2;

        auto ct_a = context.encrypt(a);
        auto ct_b = context.encrypt(b);
        auto ct_c = context.encrypt(c);

        // (a + b) * c
        auto ct_sum = context.add(ct_a, ct_b);
        auto ct_result = context.multiply(ct_sum, ct_c);

        auto result = context.decrypt(ct_result);
        REQUIRE(result == (a + b) * c);
    }
}