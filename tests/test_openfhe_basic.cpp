/**
 * @file test_openfhe_basic.cpp
 * @brief basic tests for OpenFHE integration
 */

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

TEST_CASE("OpenFHE context initialization", "[openfhe][context]") {
    cryptmalloc::OpenFHEContext context;

    SECTION("Default configuration") {
        auto result = context.initialize();
        REQUIRE(result.has_value());
        REQUIRE(context.is_initialized());
    }

    SECTION("Custom configuration") {
        cryptmalloc::EncryptionConfig config;
        config.security_level = 128;
        config.ring_dimension = 8192;
        config.plaintext_modulus = 65537;

        cryptmalloc::OpenFHEContext custom_context(config);
        auto result = custom_context.initialize();
        REQUIRE(result.has_value());
        REQUIRE(custom_context.is_initialized());
    }
}

TEST_CASE("Basic encryption and decryption", "[openfhe][crypto]") {
    cryptmalloc::OpenFHEContext context;
    auto init_result = context.initialize();
    REQUIRE(init_result.has_value());

    SECTION("Integer encryption") {
        int test_value = 42;

        auto encrypt_result = context.encrypt(&test_value, sizeof(test_value));
        REQUIRE(encrypt_result.has_value());

        int decrypted_value = 0;
        auto decrypt_result =
            context.decrypt(encrypt_result.value(), &decrypted_value, sizeof(decrypted_value));
        REQUIRE(decrypt_result.has_value());
        REQUIRE(decrypt_result.value() == sizeof(test_value));
        REQUIRE(decrypted_value == test_value);
    }

    SECTION("String encryption") {
        std::string test_string = "Hello, OpenFHE!";

        auto encrypt_result = context.encrypt(test_string.data(), test_string.size());
        REQUIRE(encrypt_result.has_value());

        std::vector<char> decrypted_buffer(test_string.size());
        auto decrypt_result = context.decrypt(encrypt_result.value(), decrypted_buffer.data(),
                                              decrypted_buffer.size());
        REQUIRE(decrypt_result.has_value());

        std::string decrypted_string(decrypted_buffer.data(), decrypt_result.value());
        REQUIRE(decrypted_string == test_string);
    }

    SECTION("Empty data") {
        std::string empty_string;

        auto encrypt_result = context.encrypt(empty_string.data(), empty_string.size());
        // Empty data encryption is expected to fail with OpenFHE
        REQUIRE_FALSE(encrypt_result.has_value());
    }
}

TEST_CASE("Context state management", "[openfhe][context]") {
    cryptmalloc::OpenFHEContext context;

    SECTION("Uninitialized context") {
        REQUIRE_FALSE(context.is_initialized());

        int test_value = 42;
        auto encrypt_result = context.encrypt(&test_value, sizeof(test_value));
        REQUIRE_FALSE(encrypt_result.has_value());
        REQUIRE(encrypt_result.error() == "Context not initialized");
    }

    SECTION("Context keys after initialization") {
        auto init_result = context.initialize();
        REQUIRE(init_result.has_value());

        // verify keys are available
        REQUIRE_NOTHROW(context.get_public_key());
        REQUIRE_NOTHROW(context.get_private_key());
        REQUIRE_NOTHROW(context.get_context());
    }
}

/*
BENCHMARK_ADVANCED("Integer encryption performance")(Catch::Benchmark::Chronometer meter) {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    int test_value = 12345;

    meter.measure([&] { return context.encrypt(&test_value, sizeof(test_value)); });
}
*/

/*
BENCHMARK_ADVANCED("Integer decryption performance")(Catch::Benchmark::Chronometer meter) {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    int test_value = 12345;
    auto ciphertext = context.encrypt(&test_value, sizeof(test_value)).value();

    meter.measure([&] {
        int result = 0;
        return context.decrypt(ciphertext, &result, sizeof(result));
    });
}
*/

/*
BENCHMARK_ADVANCED("String encryption performance")(Catch::Benchmark::Chronometer meter) {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    std::string test_string = "Performance test string for encryption benchmarking";

    meter.measure([&] { return context.encrypt(test_string.data(), test_string.size()); });
}
*/