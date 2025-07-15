#include <catch2/catch_test_macros.hpp>
#include "cryptmalloc/core.hpp"

TEST_CASE("version information", "[core]") {
    REQUIRE(cryptmalloc::Version::major == 1);
    REQUIRE(cryptmalloc::Version::minor == 0);
    REQUIRE(cryptmalloc::Version::patch == 0);
    REQUIRE(cryptmalloc::Version::string() == "1.0.0");
}

TEST_CASE("cryptmalloc initialization", "[core]") {
    cryptmalloc::CryptMalloc::shutdown();
    REQUIRE_FALSE(cryptmalloc::CryptMalloc::is_initialized());

    REQUIRE(cryptmalloc::CryptMalloc::initialize());
    REQUIRE(cryptmalloc::CryptMalloc::is_initialized());

    REQUIRE(cryptmalloc::CryptMalloc::initialize());
    REQUIRE(cryptmalloc::CryptMalloc::is_initialized());

    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;

    cryptmalloc::CryptMalloc::shutdown();
    REQUIRE(cryptmalloc::CryptMalloc::initialize(params));

    auto retrieved_params = cryptmalloc::CryptMalloc::get_params();
    REQUIRE(retrieved_params.ring_dimension == params.ring_dimension);
    REQUIRE(retrieved_params.plaintext_modulus == params.plaintext_modulus);

    cryptmalloc::CryptMalloc::shutdown();
    REQUIRE_FALSE(cryptmalloc::CryptMalloc::is_initialized());
}