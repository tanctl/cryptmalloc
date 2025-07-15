#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

TEST_CASE("encryption performance", "[benchmark]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 2;

    cryptmalloc::OpenFHEContext context(params);
    REQUIRE(context.is_valid());

    BENCHMARK("encrypt single integer") {
        return context.encrypt(42);
    };

    BENCHMARK("decrypt single integer") {
        auto ct = context.encrypt(42);
        return context.decrypt(ct);
    };
}

TEST_CASE("homomorphic operations performance", "[benchmark]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 2;

    cryptmalloc::OpenFHEContext context(params);
    REQUIRE(context.is_valid());

    auto ct1 = context.encrypt(15);
    auto ct2 = context.encrypt(27);

    BENCHMARK("homomorphic addition") {
        return context.add(ct1, ct2);
    };

    BENCHMARK("homomorphic multiplication") {
        return context.multiply(ct1, ct2);
    };
}

TEST_CASE("context creation performance", "[benchmark]") {
    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 1;

    BENCHMARK("create openfhe context") {
        cryptmalloc::OpenFHEContext context(params);
        return context.is_valid();
    };
}