#include <chrono>
#include <iostream>
#include <vector>
#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

void basic_operations_demo() {
    std::cout << "\n=== basic encryption operations demo ===" << std::endl;

    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;  // updated for OpenFHE 1.3.1 security requirements
    params.plaintext_modulus = 65537;
    params.depth = 2;

    cryptmalloc::OpenFHEContext context(params);
    if (!context.is_valid()) {
        std::cerr << "failed to create encryption context" << std::endl;
        return;
    }

    std::vector<int64_t> test_values = {42, 123, 999, 12345};

    std::cout << "encrypting and decrypting values:" << std::endl;
    for (auto value : test_values) {
        auto encrypted = context.encrypt(value);
        auto decrypted = context.decrypt(encrypted);

        std::cout << "  " << value << " -> encrypted -> " << decrypted;
        std::cout << (value == decrypted ? " ✓" : " ✗") << std::endl;
    }
}

void homomorphic_operations_demo() {
    std::cout << "\n=== homomorphic operations demo ===" << std::endl;

    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 2;

    cryptmalloc::OpenFHEContext context(params);

    int64_t a = 15, b = 27;
    std::cout << "homomorphic addition: " << a << " + " << b << std::endl;

    auto ct_a = context.encrypt(a);
    auto ct_b = context.encrypt(b);
    auto ct_sum = context.add(ct_a, ct_b);
    auto result_add = context.decrypt(ct_sum);

    std::cout << "  encrypted result: " << result_add;
    std::cout << " (expected: " << (a + b) << ")";
    std::cout << (result_add == a + b ? " ✓" : " ✗") << std::endl;

    int64_t c = 7, d = 6;
    std::cout << "homomorphic multiplication: " << c << " * " << d << std::endl;

    auto ct_c = context.encrypt(c);
    auto ct_d = context.encrypt(d);
    auto ct_mult = context.multiply(ct_c, ct_d);
    auto result_mult = context.decrypt(ct_mult);

    std::cout << "  encrypted result: " << result_mult;
    std::cout << " (expected: " << (c * d) << ")";
    std::cout << (result_mult == c * d ? " ✓" : " ✗") << std::endl;

    // compute (a + b) * c
    int64_t e = 5, f = 3, g = 2;
    std::cout << "complex operation: (" << e << " + " << f << ") * " << g << std::endl;

    auto ct_e = context.encrypt(e);
    auto ct_f = context.encrypt(f);
    auto ct_g = context.encrypt(g);

    auto ct_sum_ef = context.add(ct_e, ct_f);
    auto ct_final = context.multiply(ct_sum_ef, ct_g);
    auto result_complex = context.decrypt(ct_final);

    std::cout << "  encrypted result: " << result_complex;
    std::cout << " (expected: " << ((e + f) * g) << ")";
    std::cout << (result_complex == (e + f) * g ? " ✓" : " ✗") << std::endl;
}

void performance_demo() {
    std::cout << "\n=== performance demo ===" << std::endl;

    cryptmalloc::EncryptionParams params;
    params.ring_dimension = 16384;
    params.plaintext_modulus = 65537;
    params.depth = 1;

    auto start = std::chrono::high_resolution_clock::now();
    cryptmalloc::OpenFHEContext context(params);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "context creation time: " << duration.count() << " ms" << std::endl;

    const int num_operations = 10;
    int64_t test_value = 42;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_operations; ++i) {
        auto ct = context.encrypt(test_value + i);
        volatile auto result = context.decrypt(ct);  // prevent opt
        (void)result;
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << num_operations << " encrypt/decrypt cycles: " << duration.count() << " ms"
              << " (" << (double)duration.count() / num_operations << " ms per cycle)" << std::endl;
}

int main() {
    std::cout << "cryptmalloc basic encryption demo" << std::endl;
    std::cout << "version: " << cryptmalloc::Version::string() << std::endl;

    if (!cryptmalloc::CryptMalloc::initialize()) {
        std::cerr << "failed to initialize cryptmalloc" << std::endl;
        return 1;
    }

    try {
        basic_operations_demo();
        homomorphic_operations_demo();
        performance_demo();

        std::cout << "\n=== demo completed successfully! ===" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "error during demo: " << e.what() << std::endl;
        cryptmalloc::CryptMalloc::shutdown();
        return 1;
    }

    cryptmalloc::CryptMalloc::shutdown();
    return 0;
}