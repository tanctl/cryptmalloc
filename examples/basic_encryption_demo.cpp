/**
 * @file basic_encryption_demo.cpp
 * @brief comprehensive demo of cryptmalloc basic encryption capabilities
 */

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

void print_header(const std::string& title) {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(50, '=') << std::endl;
}

void print_success(const std::string& message) {
    std::cout << "✅ " << message << std::endl;
}

void print_error(const std::string& message) {
    std::cout << "❌ " << message << std::endl;
}

void demo_basic_encryption() {
    print_header("Basic Encryption Demo");

    cryptmalloc::OpenFHEContext context;

    std::cout << "Initializing OpenFHE context..." << std::endl;
    auto init_result = context.initialize();
    if(!init_result.has_value()) {
        print_error("Failed to initialize context: " + init_result.error());
        return;
    }
    print_success("Context initialized successfully");

    // test with different data types
    struct TestCase {
        std::string name;
        std::vector<uint8_t> data;
    };

    std::vector<TestCase> test_cases{{"Integer", {42, 0, 0, 0}},  // little-endian int
                                     {"String", {'H', 'e', 'l', 'l', 'o', '!'}},
                                     {"Binary", {0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF}},
                                     {"Empty", {}}};

    for(const auto& test_case : test_cases) {
        std::cout << "\nTesting " << test_case.name << " data..." << std::endl;

        // encrypt
        auto encrypt_result = context.encrypt(test_case.data.data(), test_case.data.size());
        if(!encrypt_result.has_value()) {
            print_error("Encryption failed: " + encrypt_result.error());
            continue;
        }
        print_success("Data encrypted successfully");

        // decrypt
        std::vector<uint8_t> decrypted_data(test_case.data.size());
        auto decrypt_result =
            context.decrypt(encrypt_result.value(), decrypted_data.data(), decrypted_data.size());

        if(!decrypt_result.has_value()) {
            print_error("Decryption failed: " + decrypt_result.error());
            continue;
        }

        if(decrypt_result.value() != test_case.data.size()) {
            print_error("Decrypted size mismatch");
            continue;
        }

        // verify correctness
        bool match =
            std::equal(test_case.data.begin(), test_case.data.end(), decrypted_data.begin());

        if(match) {
            print_success("Data decrypted correctly");
        } else {
            print_error("Decrypted data does not match original");
        }
    }
}

void demo_performance_test() {
    print_header("Performance Test");

    cryptmalloc::OpenFHEContext context;
    context.initialize();

    std::vector<size_t> data_sizes = {16, 64, 256, 1024};

    for(auto size : data_sizes) {
        std::cout << "\nTesting " << size << " bytes..." << std::endl;

        // generate test data
        std::vector<uint8_t> test_data(size);
        for(size_t i = 0; i < size; ++i) {
            test_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // measure encryption time
        auto start = std::chrono::high_resolution_clock::now();
        auto encrypt_result = context.encrypt(test_data.data(), test_data.size());
        auto encrypt_end = std::chrono::high_resolution_clock::now();

        if(!encrypt_result.has_value()) {
            print_error("Encryption failed");
            continue;
        }

        // measure decryption time
        std::vector<uint8_t> output(size);
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        auto decrypt_result = context.decrypt(encrypt_result.value(), output.data(), output.size());
        auto decrypt_end = std::chrono::high_resolution_clock::now();

        if(!decrypt_result.has_value()) {
            print_error("Decryption failed");
            continue;
        }

        // calculate timings
        auto encrypt_duration =
            std::chrono::duration_cast<std::chrono::microseconds>(encrypt_end - start).count();
        auto decrypt_duration =
            std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end - decrypt_start)
                .count();

        std::cout << "  Encryption: " << std::setw(6) << encrypt_duration << " μs" << std::endl;
        std::cout << "  Decryption: " << std::setw(6) << decrypt_duration << " μs" << std::endl;
        std::cout << "  Total:      " << std::setw(6) << (encrypt_duration + decrypt_duration)
                  << " μs" << std::endl;
    }
}

void demo_error_handling() {
    print_header("Error Handling Demo");

    // test uninitialized context
    std::cout << "Testing uninitialized context..." << std::endl;
    cryptmalloc::OpenFHEContext uninitialized_context;

    int test_value = 42;
    auto result = uninitialized_context.encrypt(&test_value, sizeof(test_value));

    if(!result.has_value()) {
        print_success("Properly caught uninitialized context error: " + result.error());
    } else {
        print_error("Failed to catch uninitialized context error");
    }

    // test initialized context with edge cases
    std::cout << "\nTesting edge cases..." << std::endl;
    cryptmalloc::OpenFHEContext context;
    context.initialize();

    // test null pointer (this would be undefined behavior, so we skip it)
    std::cout << "Skipping null pointer test (undefined behavior)" << std::endl;

    print_success("Error handling tests completed");
}

int main() {
    std::cout << "CryptMalloc Basic Encryption Demo" << std::endl;
    std::cout << "Version: " << cryptmalloc::Version::string << std::endl;

    try {
        demo_basic_encryption();
        demo_performance_test();
        demo_error_handling();

        print_header("Demo Complete");
        print_success("All demos completed successfully!");

    } catch(const std::exception& e) {
        print_error(std::string("Exception caught: ") + e.what());
        return 1;
    }

    return 0;
}