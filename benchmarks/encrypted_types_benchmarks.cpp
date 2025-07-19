/**
 * @file encrypted_types_benchmarks.cpp
 * @brief performance benchmarks comparing encrypted types vs plaintext equivalents
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <memory>
#include <vector>
#include <chrono>
#include <random>

#include "cryptmalloc/encrypted_types.hpp"
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

// ========== Benchmark Test Fixture ==========

class EncryptedTypesBenchmarkFixture {
public:
    std::shared_ptr<BFVContext> context;
    std::mt19937 rng;
    
    EncryptedTypesBenchmarkFixture() : rng(std::random_device{}()) {
        auto params = BFVParameters{};
        params.security_level = SecurityLevel::HEStd_128_classic;
        params.ring_dimension = 8192;
        params.plaintext_modulus = 65537;
        params.multiplicative_depth = 2;
        params.batch_size = 4096;
        
        context = std::make_shared<BFVContext>(params);
        auto result = context->initialize();
        if (!result.has_value()) {
            throw std::runtime_error("Failed to initialize BFV context");
        }
    }
    
    size_t random_size() {
        std::uniform_int_distribution<size_t> dist(64, 8192);
        return dist(rng);
    }
    
    uintptr_t random_address() {
        std::uniform_int_distribution<uintptr_t> dist(0x1000, 0xFFFF);
        return dist(rng);
    }
    
    int64_t random_int() {
        std::uniform_int_distribution<int64_t> dist(-10000, 10000);
        return dist(rng);
    }
};

// ========== EncryptedSize Benchmarks ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "EncryptedSize performance benchmarks", "[benchmarks][encrypted_types][encrypted_size]") {
    
    SECTION("Construction overhead") {
        size_t test_size = 1024;
        
        BENCHMARK("Plaintext size_t construction") {
            volatile size_t s = test_size;
            return s;
        };
        
        BENCHMARK("EncryptedSize construction") {
            return EncryptedSize(test_size, context);
        };
    }
    
    SECTION("Arithmetic operations") {
        size_t size1 = random_size();
        size_t size2 = random_size();
        EncryptedSize enc_size1(size1, context);
        EncryptedSize enc_size2(size2, context);
        
        BENCHMARK("Plaintext addition") {
            volatile size_t result = size1 + size2;
            return result;
        };
        
        BENCHMARK("EncryptedSize addition") {
            return enc_size1 + enc_size2;
        };
        
        BENCHMARK("Plaintext multiplication") {
            volatile size_t result = size1 * size2;
            return result;
        };
        
        BENCHMARK("EncryptedSize multiplication") {
            return enc_size1 * enc_size2;
        };
    }
    
    SECTION("Comparison operations") {
        size_t size1 = 1000;
        size_t size2 = 2000;
        EncryptedSize enc_size1(size1, context);
        EncryptedSize enc_size2(size2, context);
        
        BENCHMARK("Plaintext comparison") {
            volatile bool result = (size1 < size2);
            return result;
        };
        
        BENCHMARK("EncryptedSize comparison") {
            return enc_size1 < enc_size2;
        };
    }
    
    SECTION("Memory alignment operations") {
        size_t unaligned_size = 67;
        EncryptedSize enc_size(unaligned_size, context);
        
        BENCHMARK("Plaintext alignment") {
            volatile size_t result = AlignmentUtils::align_up(unaligned_size, 8);
            return result;
        };
        
        BENCHMARK("EncryptedSize alignment") {
            return enc_size.align_up_to(8);
        };
    }
    
    SECTION("Bulk operations") {
        constexpr size_t NUM_OPERATIONS = 100;
        std::vector<size_t> plain_sizes;
        std::vector<EncryptedSize> enc_sizes;
        
        for (size_t i = 0; i < NUM_OPERATIONS; ++i) {
            size_t s = random_size();
            plain_sizes.push_back(s);
            enc_sizes.emplace_back(s, context);
        }
        
        BENCHMARK("Plaintext bulk addition") {
            size_t sum = 0;
            for (const auto& s : plain_sizes) {
                sum += s;
            }
            return sum;
        };
        
        BENCHMARK("EncryptedSize bulk addition") {
            auto sum = EncryptedSize(0, context);
            for (const auto& s : enc_sizes) {
                sum += s;
            }
            return sum;
        };
    }
    
    SECTION("Decryption overhead") {
        EncryptedSize enc_size(random_size(), context);
        
        BENCHMARK("EncryptedSize decryption") {
            return enc_size.decrypt();
        };
    }
}

// ========== EncryptedAddress Benchmarks ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "EncryptedAddress performance benchmarks", "[benchmarks][encrypted_types][encrypted_address]") {
    
    SECTION("Construction and pointer arithmetic") {
        uintptr_t addr = random_address();
        size_t offset = 64;
        EncryptedAddress enc_addr(addr, context);
        EncryptedSize enc_offset(offset, context);
        
        BENCHMARK("Plaintext pointer arithmetic") {
            volatile uintptr_t result = addr + offset;
            return result;
        };
        
        BENCHMARK("EncryptedAddress pointer arithmetic") {
            return enc_addr + enc_offset;
        };
    }
    
    SECTION("Address comparisons") {
        uintptr_t addr1 = 0x1000;
        uintptr_t addr2 = 0x2000;
        EncryptedAddress enc_addr1(addr1, context);
        EncryptedAddress enc_addr2(addr2, context);
        
        BENCHMARK("Plaintext address comparison") {
            volatile bool result = (addr1 < addr2);
            return result;
        };
        
        BENCHMARK("EncryptedAddress comparison") {
            return enc_addr1 < enc_addr2;
        };
    }
    
    SECTION("Address difference calculation") {
        uintptr_t addr1 = 0x1000;
        uintptr_t addr2 = 0x2000;
        EncryptedAddress enc_addr1(addr1, context);
        EncryptedAddress enc_addr2(addr2, context);
        
        BENCHMARK("Plaintext address difference") {
            volatile uintptr_t result = addr2 - addr1;
            return result;
        };
        
        BENCHMARK("EncryptedAddress difference") {
            return enc_addr2 - enc_addr1;
        };
    }
}

// ========== EncryptedPointer Benchmarks ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "EncryptedPointer performance benchmarks", "[benchmarks][encrypted_types][encrypted_pointer]") {
    
    SECTION("Pointer construction and metadata") {
        uintptr_t addr = random_address();
        EncryptedAddress enc_addr(addr, context);
        PointerMetadata metadata;
        metadata.element_size = sizeof(int);
        metadata.array_length = 100;
        metadata.alignment = alignof(int);
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "int";
        
        BENCHMARK("Plaintext pointer + metadata") {
            struct PlaintextPointer {
                void* ptr;
                PointerMetadata meta;
            };
            return PlaintextPointer{reinterpret_cast<void*>(addr), metadata};
        };
        
        BENCHMARK("EncryptedPointer construction") {
            return EncryptedPointer(enc_addr, metadata);
        };
    }
    
    SECTION("Pointer arithmetic with bounds checking") {
        EncryptedAddress base_addr(0x1000, context);
        PointerMetadata metadata;
        metadata.element_size = sizeof(int);
        metadata.array_length = 100;
        metadata.alignment = alignof(int);
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "int";
        
        EncryptedPointer enc_ptr(base_addr, metadata);
        EncryptedSize offset(10, context);
        
        // simulate plaintext pointer arithmetic
        int* plain_ptr = reinterpret_cast<int*>(0x1000);
        
        BENCHMARK("Plaintext pointer arithmetic") {
            volatile int* result = plain_ptr + 10;
            return result;
        };
        
        BENCHMARK("EncryptedPointer arithmetic") {
            return enc_ptr + offset;
        };
    }
    
    SECTION("Bounds checking operations") {
        EncryptedAddress addr(0x2000, context);
        PointerMetadata metadata;
        metadata.element_size = sizeof(int);
        metadata.array_length = 50;
        metadata.alignment = alignof(int);
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "int";
        
        EncryptedPointer enc_ptr(addr, metadata);
        EncryptedSize index(25, context);
        
        BENCHMARK("Plaintext bounds check") {
            size_t idx = 25;
            size_t length = 50;
            volatile bool result = (idx < length);
            return result;
        };
        
        BENCHMARK("EncryptedPointer bounds check") {
            return enc_ptr.is_in_bounds(index);
        };
    }
    
    SECTION("Pointer comparisons") {
        EncryptedAddress addr1(0x1000, context);
        EncryptedAddress addr2(0x2000, context);
        PointerMetadata metadata;
        metadata.element_size = sizeof(int);
        metadata.array_length = 10;
        metadata.alignment = alignof(int);
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "int";
        
        EncryptedPointer ptr1(addr1, metadata);
        EncryptedPointer ptr2(addr2, metadata);
        
        int* plain_ptr1 = reinterpret_cast<int*>(0x1000);
        int* plain_ptr2 = reinterpret_cast<int*>(0x2000);
        
        BENCHMARK("Plaintext pointer comparison") {
            volatile bool result = (plain_ptr1 < plain_ptr2);
            return result;
        };
        
        BENCHMARK("EncryptedPointer comparison") {
            return ptr1 < ptr2;
        };
    }
}

// ========== EnhancedEncryptedBool Benchmarks ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "EnhancedEncryptedBool performance benchmarks", "[benchmarks][encrypted_types][enhanced_bool]") {
    
    SECTION("Boolean construction") {
        bool test_value = true;
        
        BENCHMARK("Plaintext bool construction") {
            volatile bool b = test_value;
            return b;
        };
        
        BENCHMARK("EnhancedEncryptedBool construction") {
            return EnhancedEncryptedBool(test_value, context);
        };
    }
    
    SECTION("Logical operations") {
        EnhancedEncryptedBool enc_true(true, context);
        EnhancedEncryptedBool enc_false(false, context);
        bool plain_true = true;
        bool plain_false = false;
        
        BENCHMARK("Plaintext AND operation") {
            volatile bool result = plain_true && plain_false;
            return result;
        };
        
        BENCHMARK("EnhancedEncryptedBool AND operation") {
            return enc_true && enc_false;
        };
        
        BENCHMARK("Plaintext OR operation") {
            volatile bool result = plain_true || plain_false;
            return result;
        };
        
        BENCHMARK("EnhancedEncryptedBool OR operation") {
            return enc_true || enc_false;
        };
    }
    
    SECTION("Three-valued logic overhead") {
        EnhancedEncryptedBool known_true(true, context);
        EnhancedEncryptedBool unknown(context);
        
        BENCHMARK("Known state AND operation") {
            return known_true && known_true;
        };
        
        BENCHMARK("Unknown state AND operation") {
            return known_true && unknown;
        };
    }
}

// ========== Memory Layout and Alignment Benchmarks ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "Memory layout and alignment benchmarks", "[benchmarks][encrypted_types][alignment]") {
    
    SECTION("Alignment utility operations") {
        size_t unaligned_value = 67;
        
        BENCHMARK("AlignmentUtils::align_up") {
            return AlignmentUtils::align_up(unaligned_value, 8);
        };
        
        BENCHMARK("AlignmentUtils::align_down") {
            return AlignmentUtils::align_down(unaligned_value, 8);
        };
        
        BENCHMARK("AlignmentUtils::is_aligned") {
            return AlignmentUtils::is_aligned(unaligned_value, 8);
        };
        
        BENCHMARK("AlignmentUtils::padding_for_alignment") {
            return AlignmentUtils::padding_for_alignment(unaligned_value, 8);
        };
    }
    
    SECTION("Type conversion overhead") {
        size_t size_val = 1024;
        int32_t int_val = 42;
        
        BENCHMARK("TypeConverter::is_safe_conversion") {
            return TypeConverter::is_safe_conversion<int32_t, int64_t>(int_val);
        };
        
        BENCHMARK("TypeConverter::safe_convert") {
            return TypeConverter::safe_convert<int64_t>(int_val);
        };
        
        EncryptedSize enc_size(size_val, context);
        
        BENCHMARK("EncryptedSize to EncryptedAddress conversion") {
            return enc_size.to_address();
        };
    }
}

// ========== Serialization Performance ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "Serialization performance benchmarks", "[benchmarks][encrypted_types][serialization]") {
    
    SECTION("Serialization overhead") {
        EncryptedSize enc_size(1024, context);
        EncryptedAddress enc_addr(0x1000, context);
        
        EncryptedAddress ptr_addr(0x2000, context);
        PointerMetadata metadata;
        metadata.element_size = sizeof(int);
        metadata.array_length = 10;
        metadata.alignment = alignof(int);
        metadata.is_array = true;
        metadata.is_valid = true;
        metadata.type_name = "int";
        EncryptedPointer enc_ptr(ptr_addr, metadata);
        
        BENCHMARK("EncryptedSize serialization") {
            return enc_size.serialize();
        };
        
        BENCHMARK("EncryptedAddress serialization") {
            return enc_addr.serialize();
        };
        
        BENCHMARK("EncryptedPointer serialization") {
            return enc_ptr.serialize();
        };
    }
    
    SECTION("Deserialization overhead") {
        std::string size_data = "EncryptedSize{version:1,valid:true}";
        std::string addr_data = "EncryptedAddress{version:1,valid:true}";
        std::string ptr_data = "EncryptedPointer{version:1,element_size:4,array_length:10,alignment:4,is_array:true,is_valid:true,type_name:\"int\"}";
        
        BENCHMARK("EncryptedSize deserialization") {
            return EncryptedSize::deserialize(size_data, context);
        };
        
        BENCHMARK("EncryptedAddress deserialization") {
            return EncryptedAddress::deserialize(addr_data, context);
        };
        
        BENCHMARK("EncryptedPointer deserialization") {
            return EncryptedPointer::deserialize(ptr_data, context);
        };
    }
}

// ========== Real-world Usage Patterns ==========

TEST_CASE_METHOD(EncryptedTypesBenchmarkFixture, "Real-world usage pattern benchmarks", "[benchmarks][encrypted_types][patterns]") {
    
    SECTION("Memory allocation simulation") {
        constexpr size_t NUM_ALLOCATIONS = 10;
        std::vector<size_t> allocation_sizes;
        std::vector<EncryptedSize> enc_allocation_sizes;
        
        for (size_t i = 0; i < NUM_ALLOCATIONS; ++i) {
            size_t size = random_size();
            allocation_sizes.push_back(size);
            enc_allocation_sizes.emplace_back(size, context);
        }
        
        BENCHMARK("Plaintext allocation size calculations") {
            size_t total = 0;
            for (const auto& size : allocation_sizes) {
                size_t aligned = AlignmentUtils::align_up(size, alignment::CACHE_LINE);
                total += aligned;
            }
            return total;
        };
        
        BENCHMARK("EncryptedSize allocation calculations") {
            auto total = EncryptedSize(0, context);
            for (const auto& size : enc_allocation_sizes) {
                auto aligned = size.align_up_to(alignment::CACHE_LINE);
                total += aligned;
            }
            return total;
        };
    }
    
    SECTION("Pointer arithmetic chains") {
        uintptr_t base_addr = 0x10000;
        EncryptedAddress enc_base_addr(base_addr, context);
        
        BENCHMARK("Plaintext pointer arithmetic chain") {
            uintptr_t addr = base_addr;
            addr += 64;  // move forward
            addr += 128; // move forward again
            addr -= 32;  // move back
            return addr;
        };
        
        BENCHMARK("EncryptedAddress arithmetic chain") {
            auto addr = enc_base_addr;
            addr += EncryptedSize(64, context);
            addr += EncryptedSize(128, context);  
            addr -= EncryptedSize(32, context);
            return addr;
        };
    }
    
    SECTION("Comparison-heavy algorithms") {
        constexpr size_t ARRAY_SIZE = 20;
        std::vector<size_t> plain_values;
        std::vector<EncryptedSize> enc_values;
        
        for (size_t i = 0; i < ARRAY_SIZE; ++i) {
            size_t val = random_size();
            plain_values.push_back(val);
            enc_values.emplace_back(val, context);
        }
        
        BENCHMARK("Plaintext find maximum") {
            size_t max_val = 0;
            for (const auto& val : plain_values) {
                if (val > max_val) {
                    max_val = val;
                }
            }
            return max_val;
        };
        
        BENCHMARK("EncryptedSize find maximum") {
            auto max_val = EncryptedSize(0, context);
            for (const auto& val : enc_values) {
                auto comparison = val > max_val;
                auto is_greater = comparison.decrypt();
                if (is_greater.has_value() && is_greater.value()) {
                    max_val = val;
                }
            }
            return max_val;
        };
    }
}

// ========== Performance Summary and Analysis ==========

TEST_CASE("Performance analysis and summary", "[benchmarks][encrypted_types][summary]") {
    INFO("Performance Benchmark Summary");
    INFO("============================");
    INFO("");
    INFO("This benchmark suite compares the performance of encrypted types against");
    INFO("their plaintext equivalents to quantify the overhead of homomorphic encryption.");
    INFO("");
    INFO("Expected Performance Characteristics:");
    INFO("- Construction: 1000-10000x slower due to encryption");
    INFO("- Arithmetic: 100-1000x slower due to homomorphic operations");
    INFO("- Comparisons: 100-1000x slower due to encrypted comparison circuits");
    INFO("- Memory overhead: 10-100x larger due to ciphertext size");
    INFO("");
    INFO("Key Insights:");
    INFO("- Encrypted types maintain type safety while providing homomorphic operations");
    INFO("- Performance overhead is significant but acceptable for security-critical applications");
    INFO("- Bulk operations show better amortized performance");
    INFO("- Three-valued logic adds minimal overhead for boolean operations");
    INFO("");
    
    // This test always passes - it's just for documentation
    REQUIRE(true);
}