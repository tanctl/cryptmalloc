/**
 * @file benchmark_crypto_ops.cpp
 * @brief comprehensive benchmarks for cryptographic operations
 */

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <random>
#include <string>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

namespace {

std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);

    for(auto& byte : data) {
        byte = dis(gen);
    }

    return data;
}

}  // anonymous namespace

TEST_CASE("Encryption benchmarks", "[benchmark][encryption]") {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    BENCHMARK("Encrypt 64 bytes") {
        auto data = generate_random_data(64);
        return context.encrypt(data.data(), data.size());
    };

    BENCHMARK("Encrypt 256 bytes") {
        auto data = generate_random_data(256);
        return context.encrypt(data.data(), data.size());
    };

    BENCHMARK("Encrypt 1KB") {
        auto data = generate_random_data(1024);
        return context.encrypt(data.data(), data.size());
    };

    BENCHMARK("Encrypt 4KB") {
        auto data = generate_random_data(4096);
        return context.encrypt(data.data(), data.size());
    };
}

TEST_CASE("Decryption benchmarks", "[benchmark][decryption]") {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    SECTION("64 bytes") {
        auto data = generate_random_data(64);
        auto ciphertext = context.encrypt(data.data(), data.size()).value();
        std::vector<uint8_t> output(64);

        BENCHMARK("Decrypt 64 bytes") {
            return context.decrypt(ciphertext, output.data(), output.size());
        };
    }

    SECTION("256 bytes") {
        auto data = generate_random_data(256);
        auto ciphertext = context.encrypt(data.data(), data.size()).value();
        std::vector<uint8_t> output(256);

        BENCHMARK("Decrypt 256 bytes") {
            return context.decrypt(ciphertext, output.data(), output.size());
        };
    }

    SECTION("1KB") {
        auto data = generate_random_data(1024);
        auto ciphertext = context.encrypt(data.data(), data.size()).value();
        std::vector<uint8_t> output(1024);

        BENCHMARK("Decrypt 1KB") {
            return context.decrypt(ciphertext, output.data(), output.size());
        };
    }
}

TEST_CASE("Round-trip benchmarks", "[benchmark][roundtrip]") {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    BENCHMARK("Round-trip 64 bytes") {
        auto data = generate_random_data(64);
        auto ciphertext = context.encrypt(data.data(), data.size()).value();
        std::vector<uint8_t> output(64);
        return context.decrypt(ciphertext, output.data(), output.size());
    };

    BENCHMARK("Round-trip 256 bytes") {
        auto data = generate_random_data(256);
        auto ciphertext = context.encrypt(data.data(), data.size()).value();
        std::vector<uint8_t> output(256);
        return context.decrypt(ciphertext, output.data(), output.size());
    };
}

TEST_CASE("Context initialization benchmark", "[benchmark][initialization]") {
    BENCHMARK("Context initialization") {
        cryptmalloc::OpenFHEContext context;
        return context.initialize();
    };
}