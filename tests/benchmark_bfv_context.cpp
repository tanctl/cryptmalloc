#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

TEST_CASE("bfv context creation benchmarks", "[benchmark][bfv]") {
    SECTION("128-bit security context creation") {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params.polynomial_degree = 16384;

        BENCHMARK("create 128-bit context") {
            BFVContext context(params);
            return context.is_initialized();
        };
    }

    SECTION("different polynomial degrees") {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);

        params.polynomial_degree = 16384;
        BENCHMARK("context creation - 16384 degree") {
            BFVContext context(params);
            return context.is_initialized();
        };

        params.polynomial_degree = 8192;
        BENCHMARK("context creation - 8192 degree") {
            BFVContext context(params);
            return context.is_initialized();
        };
    }
}

TEST_CASE("bfv key generation benchmarks", "[benchmark][bfv]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;

    SECTION("basic key generation") {
        BFVContext context(params);

        BENCHMARK("key generation") {
            context.generate_keys();
            context.clear_keys();  // reset for next iteration
            return true;
        };
    }

    SECTION("relinearization key generation") {
        BFVContext context(params);
        context.generate_keys();

        BENCHMARK("relinearization keys") {
            context.generate_relinearization_keys();
            return true;
        };
    }

    SECTION("rotation key generation") {
        auto rotation_params = params;
        rotation_params.enable_rotation = true;
        BFVContext context(rotation_params);
        context.generate_keys();

        std::vector<int32_t> indices = {1, -1, 2, -2, 4, -4};

        BENCHMARK("rotation keys") {
            context.generate_rotation_keys(indices);
            return true;
        };
    }
}

TEST_CASE("bfv encryption benchmarks", "[benchmark][bfv]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    BFVContext context(params);
    context.generate_keys();

    SECTION("single value encryption") {
        int64_t value = 42;

        BENCHMARK("encrypt single value") {
            return context.encrypt(value);
        };

        auto ciphertext = context.encrypt(value);
        BENCHMARK("decrypt single value") {
            return context.decrypt_single(ciphertext);
        };
    }

    SECTION("batch encryption") {
        std::vector<int64_t> values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        BENCHMARK("encrypt batch values") {
            return context.encrypt(values);
        };

        auto ciphertext = context.encrypt(values);
        BENCHMARK("decrypt batch values") {
            return context.decrypt_batch(ciphertext);
        };
    }

    SECTION("encryption with different value sizes") {
        BENCHMARK("encrypt small value (42)") {
            return context.encrypt(42);
        };

        BENCHMARK("encrypt medium value (12345)") {
            return context.encrypt(12345);
        };

        BENCHMARK("encrypt large value (999999)") {
            return context.encrypt(999999);
        };
    }
}

TEST_CASE("bfv homomorphic operation benchmarks", "[benchmark][bfv]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    params.multiplicative_depth = 3;
    BFVContext context(params);
    context.generate_keys();

    auto ct1 = context.encrypt(123);
    auto ct2 = context.encrypt(456);

    SECTION("homomorphic operations") {
        BENCHMARK("homomorphic addition") {
            return context.add(ct1, ct2);
        };

        BENCHMARK("homomorphic multiplication") {
            return context.multiply(ct1, ct2);
        };
    }

    SECTION("complex operations") {
        BENCHMARK("addition chain (5 operations)") {
            auto result = ct1;
            for (int i = 0; i < 5; ++i) {
                result = context.add(result, ct2);
            }
            return result;
        };

        BENCHMARK("multiplication chain (2 operations)") {
            auto result = context.multiply(ct1, ct2);
            result = context.multiply(result, ct1);
            return result;
        };
    }
}

TEST_CASE("bfv serialization benchmarks", "[benchmark][bfv]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    BFVContext context(params);
    context.generate_keys();

    std::string context_file = "bench_context.bin";
    std::string keys_file = "bench_keys.bin";

    SECTION("context serialization") {
        BENCHMARK("serialize context") {
            return context.serialize_context(context_file + "_temp");
        };

        context.serialize_context(context_file);
        BENCHMARK("deserialize context") {
            BFVContext loaded_context(params);
            return loaded_context.deserialize_context(context_file);
        };
    }

    SECTION("key serialization") {
        BENCHMARK("serialize keys") {
            return context.serialize_keys(keys_file + "_temp");
        };

        context.serialize_keys(keys_file);
        BENCHMARK("deserialize keys") {
            BFVContext new_context(params);
            return new_context.deserialize_keys(keys_file);
        };
    }
}

TEST_CASE("bfv parameter set performance comparison", "[benchmark][bfv]") {
    SECTION("different parameter sets") {
        auto fast_params =
            get_recommended_parameters(SecurityLevel::SECURITY_128, ParameterSet::FAST_OPERATIONS);
        auto memory_params =
            get_recommended_parameters(SecurityLevel::SECURITY_128, ParameterSet::MEMORY_EFFICIENT);
        auto balanced_params =
            get_recommended_parameters(SecurityLevel::SECURITY_128, ParameterSet::BALANCED);

        BENCHMARK("fast operations - context + keys") {
            BFVContext context(fast_params);
            context.generate_keys();
            return context.is_key_generated();
        };

        BENCHMARK("memory efficient - context + keys") {
            BFVContext context(memory_params);
            context.generate_keys();
            return context.is_key_generated();
        };

        BENCHMARK("balanced - context + keys") {
            BFVContext context(balanced_params);
            context.generate_keys();
            return context.is_key_generated();
        };
    }

    SECTION("encryption performance by parameter set") {
        auto fast_params =
            get_recommended_parameters(SecurityLevel::SECURITY_128, ParameterSet::FAST_OPERATIONS);
        auto memory_params =
            get_recommended_parameters(SecurityLevel::SECURITY_128, ParameterSet::MEMORY_EFFICIENT);

        BFVContext fast_context(fast_params);
        fast_context.generate_keys();

        BFVContext memory_context(memory_params);
        memory_context.generate_keys();

        int64_t test_value = 12345;

        BENCHMARK("fast operations - encrypt/decrypt") {
            auto ct = fast_context.encrypt(test_value);
            return fast_context.decrypt_single(ct);
        };

        BENCHMARK("memory efficient - encrypt/decrypt") {
            auto ct = memory_context.encrypt(test_value);
            return memory_context.decrypt_single(ct);
        };
    }
}

TEST_CASE("bfv security level performance comparison", "[benchmark][bfv]") {
    SECTION("key generation by security level") {
        auto params_128 = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params_128.polynomial_degree = 16384;

        auto params_192 = BFVParameters::for_security_level(SecurityLevel::SECURITY_192);
        params_192.polynomial_degree = 8192;  // smaller than default for testing

        BENCHMARK("128-bit security key generation") {
            BFVContext context(params_128);
            context.generate_keys();
            return context.is_key_generated();
        };

        BENCHMARK("192-bit security key generation") {
            BFVContext context(params_192);
            context.generate_keys();
            return context.is_key_generated();
        };
    }

    SECTION("encryption by security level") {
        auto params_128 = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params_128.polynomial_degree = 16384;
        BFVContext context_128(params_128);
        context_128.generate_keys();

        auto params_192 = BFVParameters::for_security_level(SecurityLevel::SECURITY_192);
        params_192.polynomial_degree = 8192;
        BFVContext context_192(params_192);
        context_192.generate_keys();

        int64_t value = 42;

        BENCHMARK("128-bit security encryption") {
            return context_128.encrypt(value);
        };

        BENCHMARK("192-bit security encryption") {
            return context_192.encrypt(value);
        };
    }
}

TEST_CASE("ciphertext pool benchmarks", "[benchmark][bfv]") {
    auto& pool = CiphertextPool::instance();
    pool.clear();

    SECTION("pool operations") {
        BENCHMARK("acquire from empty pool") {
            return pool.acquire();
        };

        // populate pool
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> cts;
        for (int i = 0; i < 10; ++i) {
            cts.push_back(pool.acquire());
        }
        for (auto& ct : cts) {
            pool.release(std::move(ct));
        }

        BENCHMARK("acquire from populated pool") {
            auto ct = pool.acquire();
            pool.release(std::move(ct));
            return true;
        };

        BENCHMARK("release to pool") {
            auto ct = pool.acquire();
            pool.release(std::move(ct));
            return true;
        };
    }
}

TEST_CASE("memory allocation benchmarks", "[benchmark][bfv]") {
    SECTION("secure memory operations") {
        BENCHMARK("secure allocation 1KB") {
            void* ptr = SecureMemory::allocate_secure(1024);
            SecureMemory::deallocate_secure(ptr, 1024);
            return true;
        };

        BENCHMARK("secure allocation 64KB") {
            void* ptr = SecureMemory::allocate_secure(65536);
            SecureMemory::deallocate_secure(ptr, 65536);
            return true;
        };

        BENCHMARK("secure zero 1KB") {
            void* ptr = SecureMemory::allocate_secure(1024);
            SecureMemory::secure_zero(ptr, 1024);
            SecureMemory::deallocate_secure(ptr, 1024);
            return true;
        };
    }
}