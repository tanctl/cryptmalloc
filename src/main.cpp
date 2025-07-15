/**
 * @file main.cpp
 * @brief demo application showing cryptmalloc usage
 */

#include <iostream>
#include <string>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

int main() {
    std::cout << "CryptMalloc Demo v" << cryptmalloc::Version::string << std::endl;

    // create encryption context
    cryptmalloc::OpenFHEContext context;

    std::cout << "Initializing OpenFHE context..." << std::endl;
    auto init_result = context.initialize();
    if(!init_result) {
        std::cerr << "Failed to initialize context: " << init_result.error() << std::endl;
        return 1;
    }

    // test data
    std::string test_data = "lorem ipsum dolor sit amet";
    std::cout << "Original data: " << test_data << std::endl;

    // encrypt data
    std::cout << "Encrypting data..." << std::endl;
    auto encrypt_result = context.encrypt(test_data.data(), test_data.size());
    if(!encrypt_result) {
        std::cerr << "Encryption failed: " << encrypt_result.error() << std::endl;
        return 1;
    }

    auto ciphertext = encrypt_result.value();
    std::cout << "Data encrypted successfully!" << std::endl;

    // decrypt data
    std::cout << "Decrypting data..." << std::endl;
    std::vector<char> decrypted_buffer(test_data.size() + 1, 0);
    auto decrypt_result =
        context.decrypt(ciphertext, decrypted_buffer.data(), decrypted_buffer.size() - 1);

    if(!decrypt_result) {
        std::cerr << "Decryption failed: " << decrypt_result.error() << std::endl;
        return 1;
    }

    std::string decrypted_data(decrypted_buffer.data(), decrypt_result.value());
    std::cout << "Decrypted data: " << decrypted_data << std::endl;

    // verify correctness
    if(test_data == decrypted_data) {
        std::cout << "✅ Encryption/decryption test passed!" << std::endl;
    } else {
        std::cout << "❌ Encryption/decryption test failed!" << std::endl;
        return 1;
    }

    return 0;
}