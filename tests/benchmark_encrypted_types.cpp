#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <chrono>
#include <random>
#include <vector>
#include "cryptmalloc/encrypted_types.hpp"
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

static std::shared_ptr<BFVContext> create_benchmark_context() {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    auto context = std::make_shared<BFVContext>(params);
    context->generate_keys();
    return context;
}

static std::vector<size_t> generate_random_sizes(size_t count, size_t max_size = 10000) {
    std::vector<size_t> sizes;
    sizes.reserve(count);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(1, max_size);
    
    for (size_t i = 0; i < count; ++i) {
        sizes.push_back(dist(gen));
    }
    
    return sizes;
}

static std::vector<uintptr_t> generate_random_addresses(size_t count) {
    std::vector<uintptr_t> addresses;
    addresses.reserve(count);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uintptr_t> dist(0x1000, 0x7FFFFFFF);
    
    for (size_t i = 0; i < count; ++i) {
        addresses.push_back(dist(gen) & ~0x7);
    }
    
    return addresses;
}

TEST_CASE("encrypted size performance benchmarks", "[benchmark][encrypted_types][size]") {
    auto context = create_benchmark_context();
    const size_t test_count = 100;
    auto test_sizes = generate_random_sizes(test_count);

    BENCHMARK("plaintext size addition") {
        size_t result = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            result += test_sizes[i] + test_sizes[i + 1];
        }
        return result;
    };

    BENCHMARK("encrypted size addition") {
        std::vector<EncryptedSize> encrypted_sizes;
        encrypted_sizes.reserve(test_count);
        
        for (auto size : test_sizes) {
            encrypted_sizes.emplace_back(context, size);
        }
        
        size_t result = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto sum = encrypted_sizes[i] + encrypted_sizes[i + 1];
            result += sum.decrypt();
        }
        return result;
    };

    BENCHMARK("plaintext size comparison") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            if (test_sizes[i] > test_sizes[i + 1]) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("encrypted size comparison") {
        std::vector<EncryptedSize> encrypted_sizes;
        encrypted_sizes.reserve(test_count);
        
        for (auto size : test_sizes) {
            encrypted_sizes.emplace_back(context, size);
        }
        
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto comparison = encrypted_sizes[i] > encrypted_sizes[i + 1];
            if (comparison.decrypt()) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("plaintext size alignment") {
        size_t total_aligned = 0;
        for (auto size : test_sizes) {
            size_t aligned = ((size + 15) / 16) * 16;
            total_aligned += aligned;
        }
        return total_aligned;
    };

    BENCHMARK("encrypted size alignment") {
        size_t total_aligned = 0;
        for (auto size : test_sizes) {
            EncryptedSize encrypted_size(context, size);
            auto aligned = encrypted_size.align_to(16);
            total_aligned += aligned.decrypt();
        }
        return total_aligned;
    };
}

TEST_CASE("encrypted address performance benchmarks", "[benchmark][encrypted_types][address]") {
    auto context = create_benchmark_context();
    const size_t test_count = 100;
    auto test_addresses = generate_random_addresses(test_count);
    auto test_offsets = generate_random_sizes(test_count, 1000);

    BENCHMARK("plaintext pointer arithmetic") {
        uintptr_t result = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            result += test_addresses[i] + test_offsets[i];
        }
        return result;
    };

    BENCHMARK("encrypted pointer arithmetic") {
        std::vector<EncryptedAddress> encrypted_addresses;
        std::vector<EncryptedSize> encrypted_offsets;
        
        encrypted_addresses.reserve(test_count);
        encrypted_offsets.reserve(test_count);
        
        for (size_t i = 0; i < test_count; ++i) {
            encrypted_addresses.emplace_back(context, test_addresses[i]);
            encrypted_offsets.emplace_back(context, test_offsets[i]);
        }
        
        uintptr_t result = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto new_addr = encrypted_addresses[i] + encrypted_offsets[i];
            result += new_addr.decrypt();
        }
        return result;
    };

    BENCHMARK("plaintext address comparison") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            if (test_addresses[i] > test_addresses[i + 1]) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("encrypted address comparison") {
        std::vector<EncryptedAddress> encrypted_addresses;
        encrypted_addresses.reserve(test_count);
        
        for (auto addr : test_addresses) {
            encrypted_addresses.emplace_back(context, addr);
        }
        
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto comparison = encrypted_addresses[i] > encrypted_addresses[i + 1];
            if (comparison.decrypt()) {
                true_count++;
            }
        }
        return true_count;
    };
}

TEST_CASE("encrypted pointer performance benchmarks", "[benchmark][encrypted_types][pointer]") {
    auto context = create_benchmark_context();
    const size_t test_count = 50;
    auto test_addresses = generate_random_addresses(test_count);

    BENCHMARK("plaintext pointer increment") {
        size_t result = 0;
        for (auto addr : test_addresses) {
            int* ptr = reinterpret_cast<int*>(addr);
            for (int i = 0; i < 10; ++i) {
                ptr++;
            }
            result += reinterpret_cast<uintptr_t>(ptr);
        }
        return result;
    };

    BENCHMARK("encrypted pointer increment") {
        size_t result = 0;
        for (auto addr : test_addresses) {
            EncryptedPointer<int> ptr(context, reinterpret_cast<int*>(addr));
            for (int i = 0; i < 10; ++i) {
                ++ptr;
            }
            result += reinterpret_cast<uintptr_t>(ptr.decrypt());
        }
        return result;
    };

    BENCHMARK("plaintext pointer difference") {
        ptrdiff_t total_diff = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            int* ptr1 = reinterpret_cast<int*>(test_addresses[i]);
            int* ptr2 = reinterpret_cast<int*>(test_addresses[i + 1]);
            total_diff += ptr2 - ptr1;
        }
        return total_diff;
    };

    BENCHMARK("encrypted pointer difference") {
        ptrdiff_t total_diff = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            EncryptedPointer<int> ptr1(context, reinterpret_cast<int*>(test_addresses[i]));
            EncryptedPointer<int> ptr2(context, reinterpret_cast<int*>(test_addresses[i + 1]));
            auto diff = ptr2 - ptr1;
            total_diff += static_cast<ptrdiff_t>(diff.decrypt());
        }
        return total_diff;
    };
}

TEST_CASE("type conversion performance benchmarks", "[benchmark][encrypted_types][conversions]") {
    auto context = create_benchmark_context();
    const size_t test_count = 100;
    auto test_values = generate_random_sizes(test_count);

    BENCHMARK("plaintext size to address conversion") {
        uintptr_t result = 0;
        for (auto value : test_values) {
            result += static_cast<uintptr_t>(value);
        }
        return result;
    };

    BENCHMARK("encrypted size to address conversion") {
        uintptr_t result = 0;
        for (auto value : test_values) {
            EncryptedSize size(context, value);
            auto address = type_conversions::safe_cast_to_address(size);
            result += address.decrypt();
        }
        return result;
    };

    BENCHMARK("plaintext int to specialized types") {
        size_t result = 0;
        for (auto value : test_values) {
            size_t as_size = static_cast<size_t>(value);
            uintptr_t as_addr = static_cast<uintptr_t>(value);
            result += as_size + as_addr;
        }
        return result;
    };

    BENCHMARK("encrypted int to specialized types") {
        size_t result = 0;
        for (auto value : test_values) {
            EncryptedInt int_val(context, static_cast<int64_t>(value));
            auto size = type_conversions::from_encrypted_int_to_size(int_val);
            auto address = type_conversions::from_encrypted_int_to_address(int_val);
            result += size.decrypt() + address.decrypt();
        }
        return result;
    };
}

TEST_CASE("memory alignment performance benchmarks", "[benchmark][encrypted_types][alignment]") {
    auto context = create_benchmark_context();
    const size_t test_count = 100;
    auto test_sizes = generate_random_sizes(test_count);
    auto test_addresses = generate_random_addresses(test_count);

    BENCHMARK("plaintext size alignment to 16 bytes") {
        size_t total_aligned = 0;
        for (auto size : test_sizes) {
            size_t aligned = ((size + 15) / 16) * 16;
            total_aligned += aligned;
        }
        return total_aligned;
    };

    BENCHMARK("encrypted size alignment to 16 bytes") {
        size_t total_aligned = 0;
        for (auto size : test_sizes) {
            EncryptedSize encrypted_size(context, size);
            auto aligned = memory_alignment::align_up<16>(encrypted_size);
            total_aligned += aligned.decrypt();
        }
        return total_aligned;
    };

    BENCHMARK("plaintext address alignment to 64 bytes") {
        uintptr_t total_aligned = 0;
        for (auto addr : test_addresses) {
            uintptr_t aligned = ((addr + 63) / 64) * 64;
            total_aligned += aligned;
        }
        return total_aligned;
    };

    BENCHMARK("encrypted address alignment to 64 bytes") {
        uintptr_t total_aligned = 0;
        for (auto addr : test_addresses) {
            EncryptedAddress encrypted_addr(context, addr);
            auto aligned = memory_alignment::align_up<64>(encrypted_addr);
            total_aligned += aligned.decrypt();
        }
        return total_aligned;
    };

    BENCHMARK("plaintext alignment checking") {
        size_t aligned_count = 0;
        for (auto addr : test_addresses) {
            if (addr % 16 == 0) {
                aligned_count++;
            }
        }
        return aligned_count;
    };

    BENCHMARK("encrypted alignment checking") {
        size_t aligned_count = 0;
        for (auto addr : test_addresses) {
            EncryptedAddress encrypted_addr(context, addr);
            if (memory_alignment::is_aligned<16>(encrypted_addr).decrypt()) {
                aligned_count++;
            }
        }
        return aligned_count;
    };
}

TEST_CASE("serialization performance benchmarks", "[benchmark][encrypted_types][serialization]") {
    auto context = create_benchmark_context();
    const size_t test_count = 50;
    auto test_sizes = generate_random_sizes(test_count);

    std::vector<EncryptedSize> encrypted_sizes;
    encrypted_sizes.reserve(test_count);
    for (auto size : test_sizes) {
        encrypted_sizes.emplace_back(context, size);
    }

    BENCHMARK("encrypted size serialization") {
        size_t total_bytes = 0;
        for (const auto& size : encrypted_sizes) {
            auto serialized = serialization::TypeSerializer::serialize(size);
            total_bytes += serialized.size();
        }
        return total_bytes;
    };

    std::vector<std::vector<uint8_t>> serialized_data;
    serialized_data.reserve(test_count);
    for (const auto& size : encrypted_sizes) {
        serialized_data.push_back(serialization::TypeSerializer::serialize(size));
    }

    BENCHMARK("encrypted size deserialization") {
        size_t total_values = 0;
        for (const auto& data : serialized_data) {
            auto deserialized = serialization::TypeSerializer::deserialize_size(data, context);
            total_values += deserialized.decrypt();
        }
        return total_values;
    };
}

TEST_CASE("enhanced bool performance benchmarks", "[benchmark][encrypted_types][bool]") {
    auto context = create_benchmark_context();
    const size_t test_count = 100;

    std::vector<bool> plaintext_bools;
    std::vector<EnhancedEncryptedBool> encrypted_bools;
    
    plaintext_bools.reserve(test_count);
    encrypted_bools.reserve(test_count);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::bernoulli_distribution dist(0.5);
    
    for (size_t i = 0; i < test_count; ++i) {
        bool value = dist(gen);
        plaintext_bools.push_back(value);
        encrypted_bools.emplace_back(context, value);
    }

    BENCHMARK("plaintext boolean AND operations") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            if (plaintext_bools[i] && plaintext_bools[i + 1]) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("encrypted boolean AND operations") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto result = encrypted_bools[i] && encrypted_bools[i + 1];
            if (result.decrypt() == TriState::TRUE) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("plaintext boolean OR operations") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            if (plaintext_bools[i] || plaintext_bools[i + 1]) {
                true_count++;
            }
        }
        return true_count;
    };

    BENCHMARK("encrypted boolean OR operations") {
        size_t true_count = 0;
        for (size_t i = 0; i < test_count - 1; ++i) {
            auto result = encrypted_bools[i] || encrypted_bools[i + 1];
            if (result.decrypt() == TriState::TRUE) {
                true_count++;
            }
        }
        return true_count;
    };
}

TEST_CASE("memory overhead analysis", "[benchmark][encrypted_types][memory]") {
    auto context = create_benchmark_context();

    SECTION("size overhead comparison") {
        size_t plaintext_size = sizeof(size_t);
        EncryptedSize encrypted_size(context, 1024);
        
        INFO("Plaintext size_t: " << plaintext_size << " bytes");
        INFO("EncryptedSize object: " << sizeof(EncryptedSize) << " bytes");
        INFO("Estimated ciphertext size: " << encrypted_size.to_encrypted_int().get_ciphertext_size() << " bytes");
        
        double overhead_ratio = static_cast<double>(sizeof(EncryptedSize)) / plaintext_size;
        INFO("Memory overhead ratio: " << overhead_ratio << "x");
        
        REQUIRE(overhead_ratio > 1.0);
    }

    SECTION("address overhead comparison") {
        size_t plaintext_address = sizeof(uintptr_t);
        EncryptedAddress encrypted_address(context, 0x1000);
        
        INFO("Plaintext uintptr_t: " << plaintext_address << " bytes");
        INFO("EncryptedAddress object: " << sizeof(EncryptedAddress) << " bytes");
        
        double overhead_ratio = static_cast<double>(sizeof(EncryptedAddress)) / plaintext_address;
        INFO("Memory overhead ratio: " << overhead_ratio << "x");
        
        REQUIRE(overhead_ratio > 1.0);
    }

    SECTION("pointer overhead comparison") {
        size_t plaintext_pointer = sizeof(void*);
        EncryptedPointer<int> encrypted_pointer(context, reinterpret_cast<int*>(0x2000));
        
        INFO("Plaintext pointer: " << plaintext_pointer << " bytes");
        INFO("EncryptedPointer object: " << sizeof(EncryptedPointer<int>) << " bytes");
        
        double overhead_ratio = static_cast<double>(sizeof(EncryptedPointer<int>)) / plaintext_pointer;
        INFO("Memory overhead ratio: " << overhead_ratio << "x");
        
        REQUIRE(overhead_ratio > 1.0);
    }
}