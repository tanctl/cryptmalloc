#include <iostream>
#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

int main() {
    std::cout << "cryptmalloc demo v" << cryptmalloc::Version::string() << std::endl;

    if (!cryptmalloc::CryptMalloc::initialize()) {
        std::cerr << "failed to initialize cryptmalloc" << std::endl;
        return 1;
    }

    try {
        auto params = cryptmalloc::CryptMalloc::get_params();
        cryptmalloc::OpenFHEContext context(params);

        int64_t value1 = 42;
        int64_t value2 = 17;

        std::cout << "encrypting values: " << value1 << " and " << value2 << std::endl;

        auto ct1 = context.encrypt(value1);
        auto ct2 = context.encrypt(value2);

        auto ct_sum = context.add(ct1, ct2);
        int64_t sum_result = context.decrypt(ct_sum);

        std::cout << "encrypted addition: " << value1 << " + " << value2 << " = " << sum_result
                  << std::endl;

        auto ct_mult = context.multiply(ct1, ct2);
        int64_t mult_result = context.decrypt(ct_mult);

        std::cout << "encrypted multiplication: " << value1 << " * " << value2 << " = "
                  << mult_result << std::endl;

        if (sum_result == value1 + value2 && mult_result == value1 * value2) {
            std::cout << "all tests passed!" << std::endl;
        } else {
            std::cerr << "test failed!" << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    cryptmalloc::CryptMalloc::shutdown();

    return 0;
}