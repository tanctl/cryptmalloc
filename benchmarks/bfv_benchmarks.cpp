/**
 * @file bfv_benchmarks.cpp
 * @brief performance benchmarks for BFV context operations
 */

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <vector>

#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

namespace {

class BenchmarkHelper {
   public:
    static std::vector<int64_t> generate_random_integers(size_t count, int64_t max_value = 10000) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<int64_t> dis(-max_value, max_value);

        std::vector<int64_t> result(count);
        for(auto& val : result) {
            val = dis(gen);
        }
        return result;
    }

    static BFVContext create_initialized_context(SecurityLevel level, uint32_t depth = 3) {
        auto params = BFVParameters::recommended(level, 100000, depth);
        BFVContext context(params);
        auto init_result = context.initialize();
        if(!init_result.has_value()) {
            throw std::runtime_error("Failed to initialize context for benchmark");
        }
        return context;
    }
};

}  // anonymous namespace

TEST_CASE("BFV Context Initialization Benchmarks", "[benchmark][bfv][initialization]") {
    SECTION("Context initialization by security level") {
        BENCHMARK("128-bit security context init") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 100000, 3);
            BFVContext context(params);
            return context.initialize();
        };

        BENCHMARK("192-bit security context init") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_192_classic, 100000, 2);
            BFVContext context(params);
            return context.initialize();
        };

        BENCHMARK("256-bit security context init") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_256_classic, 100000, 2);
            BFVContext context(params);
            return context.initialize();
        };
    }

    SECTION("Key generation by multiplicative depth") {
        BENCHMARK("Depth 1 key generation") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 10000, 1);
            BFVContext context(params);
            return context.initialize();
        };

        BENCHMARK("Depth 3 key generation") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 10000, 3);
            BFVContext context(params);
            return context.initialize();
        };

        BENCHMARK("Depth 5 key generation") {
            auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 10000, 5);
            BFVContext context(params);
            return context.initialize();
        };
    }
}

TEST_CASE("BFV Encryption Performance Benchmarks", "[benchmark][bfv][encryption]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);
    auto params = context.parameters();

    SECTION("Single integer encryption") {
        int64_t test_value = 12345;

        BENCHMARK("Encrypt single integer") {
            return context.encrypt(test_value);
        };
    }

    SECTION("Vector encryption by size") {
        BENCHMARK("Encrypt 10 integers") {
            auto values = BenchmarkHelper::generate_random_integers(10);
            return context.encrypt(values);
        };

        BENCHMARK("Encrypt 100 integers") {
            auto values = BenchmarkHelper::generate_random_integers(100);
            return context.encrypt(values);
        };

        BENCHMARK("Encrypt 1000 integers") {
            auto values = BenchmarkHelper::generate_random_integers(1000);
            return context.encrypt(values);
        };

        BENCHMARK("Encrypt full batch") {
            auto values = BenchmarkHelper::generate_random_integers(params.batch_size / 2);
            return context.encrypt(values);
        };
    }

    SECTION("Large integer values") {
        int64_t large_value = static_cast<int64_t>(params.plaintext_modulus / 4);

        BENCHMARK("Encrypt large integer") {
            return context.encrypt(large_value);
        };
    }
}

TEST_CASE("BFV Decryption Performance Benchmarks", "[benchmark][bfv][decryption]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);

    SECTION("Single integer decryption") {
        auto encrypted = context.encrypt(12345).value();

        BENCHMARK("Decrypt single integer") {
            return context.decrypt_int(encrypted);
        };
    }

    SECTION("Vector decryption by size") {
        auto vec_10 = context.encrypt(BenchmarkHelper::generate_random_integers(10)).value();
        auto vec_100 = context.encrypt(BenchmarkHelper::generate_random_integers(100)).value();
        auto vec_1000 = context.encrypt(BenchmarkHelper::generate_random_integers(1000)).value();

        BENCHMARK("Decrypt 10 integers") {
            return context.decrypt_vector(vec_10, 10);
        };

        BENCHMARK("Decrypt 100 integers") {
            return context.decrypt_vector(vec_100, 100);
        };

        BENCHMARK("Decrypt 1000 integers") {
            return context.decrypt_vector(vec_1000, 1000);
        };
    }
}

TEST_CASE("BFV Homomorphic Operations Benchmarks", "[benchmark][bfv][homomorphic]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);

    SECTION("Addition benchmarks") {
        auto enc_a = context.encrypt(123).value();
        auto enc_b = context.encrypt(456).value();

        BENCHMARK("Homomorphic addition") {
            return context.add(enc_a, enc_b);
        };

        // vector addition
        auto vec_a = context.encrypt(BenchmarkHelper::generate_random_integers(100)).value();
        auto vec_b = context.encrypt(BenchmarkHelper::generate_random_integers(100)).value();

        BENCHMARK("Vector addition (100 elements)") {
            return context.add(vec_a, vec_b);
        };
    }

    SECTION("Subtraction benchmarks") {
        auto enc_a = context.encrypt(1000).value();
        auto enc_b = context.encrypt(300).value();

        BENCHMARK("Homomorphic subtraction") {
            return context.subtract(enc_a, enc_b);
        };
    }

    SECTION("Multiplication benchmarks") {
        auto enc_a = context.encrypt(15).value();
        auto enc_b = context.encrypt(27).value();

        BENCHMARK("Homomorphic multiplication") {
            return context.multiply(enc_a, enc_b);
        };

        // vector multiplication
        auto vec_a = context.encrypt(BenchmarkHelper::generate_random_integers(50, 100)).value();
        auto vec_b = context.encrypt(BenchmarkHelper::generate_random_integers(50, 100)).value();

        BENCHMARK("Vector multiplication (50 elements)") {
            return context.multiply(vec_a, vec_b);
        };
    }

    SECTION("Chain operations") {
        auto enc_a = context.encrypt(5).value();
        auto enc_b = context.encrypt(3).value();
        auto enc_c = context.encrypt(7).value();

        BENCHMARK("Chain: (a + b) * c") {
            auto sum = context.add(enc_a, enc_b);
            if(sum.has_value()) {
                return context.multiply(sum.value(), enc_c);
            }
            return sum;
        };

        BENCHMARK("Chain: a * b + c") {
            auto product = context.multiply(enc_a, enc_b);
            if(product.has_value()) {
                return context.add(product.value(), enc_c);
            }
            return product;
        };
    }
}

TEST_CASE("BFV Round-trip Performance Benchmarks", "[benchmark][bfv][roundtrip]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);

    SECTION("Single integer round-trip") {
        BENCHMARK("Single int encrypt->decrypt") {
            int64_t value = 12345;
            auto encrypted = context.encrypt(value);
            if(encrypted.has_value()) {
                return context.decrypt_int(encrypted.value());
            }
            return Result<int64_t>("Encryption failed");
        };
    }

    SECTION("Vector round-trip by size") {
        BENCHMARK("10 ints round-trip") {
            auto values = BenchmarkHelper::generate_random_integers(10);
            auto encrypted = context.encrypt(values);
            if(encrypted.has_value()) {
                return context.decrypt_vector(encrypted.value(), values.size());
            }
            return Result<std::vector<int64_t>>("Encryption failed");
        };

        BENCHMARK("100 ints round-trip") {
            auto values = BenchmarkHelper::generate_random_integers(100);
            auto encrypted = context.encrypt(values);
            if(encrypted.has_value()) {
                return context.decrypt_vector(encrypted.value(), values.size());
            }
            return Result<std::vector<int64_t>>("Encryption failed");
        };
    }

    SECTION("Operations with round-trip") {
        BENCHMARK("Add and decrypt") {
            auto enc_a = context.encrypt(100);
            auto enc_b = context.encrypt(200);
            if(enc_a.has_value() && enc_b.has_value()) {
                auto sum = context.add(enc_a.value(), enc_b.value());
                if(sum.has_value()) {
                    return context.decrypt_int(sum.value());
                }
            }
            return Result<int64_t>("Operation failed");
        };

        BENCHMARK("Multiply and decrypt") {
            auto enc_a = context.encrypt(15);
            auto enc_b = context.encrypt(25);
            if(enc_a.has_value() && enc_b.has_value()) {
                auto product = context.multiply(enc_a.value(), enc_b.value());
                if(product.has_value()) {
                    return context.decrypt_int(product.value());
                }
            }
            return Result<int64_t>("Operation failed");
        };
    }
}

TEST_CASE("BFV Security Level Performance Comparison", "[benchmark][bfv][security]") {
    SECTION("Encryption performance by security level") {
        auto context_128 =
            BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);
        auto context_192 =
            BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_192_classic);

        int64_t test_value = 12345;

        BENCHMARK("128-bit security encryption") {
            return context_128.encrypt(test_value);
        };

        BENCHMARK("192-bit security encryption") {
            return context_192.encrypt(test_value);
        };

        // 256-bit security is very slow, so we skip it for regular benchmarks
    }

    SECTION("Multiplication performance by security level") {
        auto context_128 =
            BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);
        auto context_192 =
            BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_192_classic);

        auto enc_a_128 = context_128.encrypt(15).value();
        auto enc_b_128 = context_128.encrypt(25).value();

        auto enc_a_192 = context_192.encrypt(15).value();
        auto enc_b_192 = context_192.encrypt(25).value();

        BENCHMARK("128-bit security multiplication") {
            return context_128.multiply(enc_a_128, enc_b_128);
        };

        BENCHMARK("192-bit security multiplication") {
            return context_192.multiply(enc_a_192, enc_b_192);
        };
    }
}

TEST_CASE("BFV Memory and Throughput Benchmarks", "[benchmark][bfv][throughput]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);

    SECTION("Throughput benchmarks") {
        BENCHMARK("Encrypt 1000 single integers") {
            size_t count = 0;
            for(int i = 0; i < 1000; ++i) {
                auto result = context.encrypt(i);
                if(result.has_value()) {
                    count++;
                }
            }
            return count;
        };

        BENCHMARK("Batch encrypt 10x100 integers") {
            size_t count = 0;
            for(int i = 0; i < 10; ++i) {
                auto values = BenchmarkHelper::generate_random_integers(100);
                auto result = context.encrypt(values);
                if(result.has_value()) {
                    count += values.size();
                }
            }
            return count;
        };
    }

    SECTION("Context statistics overhead") {
        BENCHMARK("Get context statistics") {
            return context.get_statistics();
        };

        auto encrypted = context.encrypt(42).value();
        BENCHMARK("Noise estimation") {
            return context.estimate_noise(encrypted);
        };
    }
}

TEST_CASE("BFV Key Serialization Benchmarks", "[benchmark][bfv][serialization]") {
    auto context = BenchmarkHelper::create_initialized_context(SecurityLevel::HEStd_128_classic);
    const auto& keys = context.keys();
    std::string password = "benchmark_password_123";

    SECTION("Key serialization") {
        BENCHMARK("Serialize key bundle") {
            return keys.serialize(password);
        };
    }

    SECTION("Key deserialization") {
        auto serialized = keys.serialize(password).value();

        BENCHMARK("Deserialize key bundle") {
            SecureKeyBundle new_keys;
            return new_keys.deserialize(serialized, password, context.crypto_context());
        };
    }

    SECTION("Round-trip serialization") {
        BENCHMARK("Serialize->Deserialize keys") {
            auto serialized = keys.serialize(password);
            if(serialized.has_value()) {
                SecureKeyBundle new_keys;
                return new_keys.deserialize(serialized.value(), password, context.crypto_context());
            }
            return Result<void>("Serialization failed");
        };
    }
}

TEST_CASE("BFV Context Manager Benchmarks", "[benchmark][bfv][manager]") {
    SECTION("Context cache performance") {
        auto params = BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 10000, 2);

        BENCHMARK("Get cached context") {
            return BFVContextManager::get_context(params);
        };

        BENCHMARK("Create new context (cache miss)") {
            BFVContextManager::clear_cache();
            return BFVContextManager::get_context(params);
        };
    }

    SECTION("Multiple contexts") {
        BENCHMARK("Create 5 different contexts") {
            std::vector<std::shared_ptr<BFVContext>> contexts;
            for(int i = 1; i <= 5; ++i) {
                auto params =
                    BFVParameters::recommended(SecurityLevel::HEStd_128_classic, 1000 * i, 2);
                contexts.push_back(BFVContextManager::get_context(params));
            }
            return contexts.size();
        };
    }
}