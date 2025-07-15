/**
 * @file crypto_benchmarks.cpp
 * @brief performance benchmarks for cryptographic operations
 */

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

namespace {

class BenchmarkData {
   public:
    static std::vector<uint8_t> random_bytes(size_t size) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint8_t> dis(0, 255);

        std::vector<uint8_t> data(size);
        for(auto& byte : data) {
            byte = dis(gen);
        }
        return data;
    }
};

}  // anonymous namespace

TEST_CASE("Crypto operation scaling benchmarks", "[benchmark][scaling]") {
    cryptmalloc::OpenFHEContext context;
    auto init_result = context.initialize();
    REQUIRE(init_result.has_value());

    SECTION("Encryption scaling") {
        std::vector<size_t> sizes = {16, 64, 256, 1024, 4096};

        for(auto size : sizes) {
            std::string test_name = "Encrypt " + std::to_string(size) + " bytes";

            BENCHMARK(test_name.c_str()) {
                auto data = BenchmarkData::random_bytes(size);
                return context.encrypt(data.data(), data.size());
            };
        }
    }

    SECTION("Decryption scaling") {
        std::vector<size_t> sizes = {16, 64, 256, 1024, 4096};
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphertexts;

        // pre-encrypt data for benchmarking
        for(auto size : sizes) {
            auto data = BenchmarkData::random_bytes(size);
            auto result = context.encrypt(data.data(), data.size());
            REQUIRE(result.has_value());
            ciphertexts.push_back(result.value());
        }

        for(size_t i = 0; i < sizes.size(); ++i) {
            std::string test_name = "Decrypt " + std::to_string(sizes[i]) + " bytes";
            std::vector<uint8_t> output(sizes[i]);

            BENCHMARK(test_name.c_str()) {
                return context.decrypt(ciphertexts[i], output.data(), output.size());
            };
        }
    }
}

TEST_CASE("Context performance benchmarks", "[benchmark][context]") {
    SECTION("Context initialization") {
        BENCHMARK("Default context init") {
            cryptmalloc::OpenFHEContext context;
            return context.initialize();
        };

        BENCHMARK("Custom context init") {
            cryptmalloc::EncryptionConfig config;
            config.ring_dimension = 8192;
            config.plaintext_modulus = 65537;

            cryptmalloc::OpenFHEContext context(config);
            return context.initialize();
        };
    }
}

TEST_CASE("Throughput benchmarks", "[benchmark][throughput]") {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    SECTION("Encryption throughput") {
        constexpr size_t block_size = 1024;
        constexpr size_t num_blocks = 100;

        BENCHMARK("Encrypt 100x1KB blocks") {
            size_t total_encrypted = 0;
            for(size_t i = 0; i < num_blocks; ++i) {
                auto data = BenchmarkData::random_bytes(block_size);
                auto result = context.encrypt(data.data(), data.size());
                if(result.has_value()) {
                    total_encrypted += block_size;
                }
            }
            return total_encrypted;
        };
    }

    SECTION("Round-trip throughput") {
        constexpr size_t block_size = 256;
        constexpr size_t num_blocks = 50;

        BENCHMARK("Round-trip 50x256B blocks") {
            size_t total_processed = 0;
            for(size_t i = 0; i < num_blocks; ++i) {
                auto data = BenchmarkData::random_bytes(block_size);
                auto encrypt_result = context.encrypt(data.data(), data.size());

                if(encrypt_result.has_value()) {
                    std::vector<uint8_t> output(block_size);
                    auto decrypt_result =
                        context.decrypt(encrypt_result.value(), output.data(), output.size());
                    if(decrypt_result.has_value()) {
                        total_processed += block_size;
                    }
                }
            }
            return total_processed;
        };
    }
}

TEST_CASE("Memory usage benchmarks", "[benchmark][memory]") {
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    SECTION("Ciphertext size overhead") {
        std::vector<size_t> plaintext_sizes = {16, 64, 256, 1024};

        for(auto size : plaintext_sizes) {
            auto data = BenchmarkData::random_bytes(size);
            auto ciphertext = context.encrypt(data.data(), data.size()).value();

            INFO("Plaintext size: " << size << " bytes");
            // actual ciphertext size measurement would require OpenFHE internals
            SUCCEED("Ciphertext created successfully");
        }
    }
}