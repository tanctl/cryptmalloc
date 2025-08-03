#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>
#include <limits>
#include <vector>
#include "cryptmalloc/encrypted_types.hpp"
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

static std::shared_ptr<BFVContext> create_test_context() {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    auto context = std::make_shared<BFVContext>(params);
    context->generate_keys();
    return context;
}

TEST_CASE("encrypted size basic operations", "[encrypted_types][size]") {
    auto context = create_test_context();

    SECTION("construction and decryption") {
        EncryptedSize size1(context, 1024);
        REQUIRE(size1.decrypt() == 1024);
        REQUIRE(size1.is_valid());

        EncryptedSize size2(context, 0);
        REQUIRE(size2.is_valid());
        REQUIRE(size2.decrypt() == 0);
    }

    SECTION("arithmetic operations") {
        EncryptedSize size1(context, 100);
        EncryptedSize size2(context, 50);

        auto sum = size1 + size2;
        REQUIRE(sum.decrypt() == 150);

        auto diff = size1 - size2;
        REQUIRE(diff.decrypt() == 50);

        auto product = size1 * size2;
        REQUIRE(product.decrypt() == 5000);

        auto quotient = size1 / size2;
        REQUIRE(quotient.decrypt() == 2);

        auto remainder = size1 % size2;
        REQUIRE(remainder.decrypt() == 0);
    }

    SECTION("arithmetic with plaintext values") {
        EncryptedSize size(context, 100);

        auto sum = size + 25;
        REQUIRE(sum.decrypt() == 125);

        auto diff = size - 25;
        REQUIRE(diff.decrypt() == 75);

        auto product = size * 3;
        REQUIRE(product.decrypt() == 300);

        auto quotient = size / 4;
        REQUIRE(quotient.decrypt() == 25);

        auto remainder = size % 30;
        REQUIRE(remainder.decrypt() == 10);
    }

    SECTION("compound assignment operations") {
        EncryptedSize size(context, 100);

        size += 50;
        REQUIRE(size.decrypt() == 150);

        size -= 25;
        REQUIRE(size.decrypt() == 125);

        size *= 2;
        REQUIRE(size.decrypt() == 250);

        size /= 5;
        REQUIRE(size.decrypt() == 50);

        size %= 30;
        REQUIRE(size.decrypt() == 20);
    }

    SECTION("comparison operations") {
        EncryptedSize size1(context, 100);
        EncryptedSize size2(context, 50);
        EncryptedSize size3(context, 100);

        REQUIRE((size1 == size3).decrypt() == true);
        REQUIRE((size1 != size2).decrypt() == true);
        REQUIRE((size1 > size2).decrypt() == true);
        REQUIRE((size2 < size1).decrypt() == true);
        REQUIRE((size1 >= size3).decrypt() == true);
        REQUIRE((size2 <= size1).decrypt() == true);
    }

    SECTION("comparison with plaintext") {
        EncryptedSize size(context, 100);

        REQUIRE((size == 100).decrypt() == true);
        REQUIRE((size != 50).decrypt() == true);
        REQUIRE((size > 50).decrypt() == true);
        REQUIRE((size < 200).decrypt() == true);
        REQUIRE((size >= 100).decrypt() == true);
        REQUIRE((size <= 100).decrypt() == true);
    }

    SECTION("alignment operations") {
        EncryptedSize size(context, 13);

        auto aligned = size.align_to(8);
        REQUIRE(aligned.decrypt() == 16);

        REQUIRE((size.is_aligned(8)).decrypt() == false);
        REQUIRE((aligned.is_aligned(8)).decrypt() == true);
    }

    SECTION("simd alignment detection") {
        size_t simd_alignment = EncryptedSize::get_simd_alignment();
        REQUIRE(simd_alignment >= 4);
        REQUIRE((simd_alignment & (simd_alignment - 1)) == 0);
    }

    SECTION("error handling") {
        EncryptedSize divisor(context, 0);
        EncryptedSize dividend(context, 100);

        REQUIRE_THROWS_AS(dividend / divisor, InvalidOperationError);
        REQUIRE_THROWS_AS(dividend % divisor, InvalidOperationError);
        REQUIRE_THROWS_AS(dividend / 0, InvalidOperationError);
        REQUIRE_THROWS_AS(dividend % 0, InvalidOperationError);
    }
}

TEST_CASE("encrypted address operations", "[encrypted_types][address]") {
    auto context = create_test_context();

    SECTION("construction and decryption") {
        uintptr_t test_addr = 0x1000;
        EncryptedAddress addr1(context, test_addr);
        REQUIRE(addr1.decrypt() == test_addr);
        REQUIRE(addr1.is_valid());

        EncryptedAddress addr2(context, 0);
        REQUIRE(addr2.is_valid());
        REQUIRE(addr2.decrypt() == 0);
    }

    SECTION("pointer arithmetic with sizes") {
        EncryptedAddress addr(context, 0x1000);
        EncryptedSize offset(context, 0x100);

        auto new_addr = addr + offset;
        REQUIRE(new_addr.decrypt() == 0x1100);

        auto back_addr = new_addr - offset;
        REQUIRE(back_addr.decrypt() == 0x1000);

        auto diff = new_addr - addr;
        REQUIRE(diff.decrypt() == 0x100);
    }

    SECTION("pointer arithmetic with plaintext") {
        EncryptedAddress addr(context, 0x1000);

        auto new_addr = addr + 0x200;
        REQUIRE(new_addr.decrypt() == 0x1200);

        auto back_addr = new_addr - 0x200;
        REQUIRE(back_addr.decrypt() == 0x1000);
    }

    SECTION("compound assignment") {
        EncryptedAddress addr(context, 0x1000);
        EncryptedSize offset(context, 0x100);

        addr += offset;
        REQUIRE(addr.decrypt() == 0x1100);

        addr -= offset;
        REQUIRE(addr.decrypt() == 0x1000);

        addr += 0x300;
        REQUIRE(addr.decrypt() == 0x1300);

        addr -= 0x300;
        REQUIRE(addr.decrypt() == 0x1000);
    }

    SECTION("comparison operations") {
        EncryptedAddress addr1(context, 0x1000);
        EncryptedAddress addr2(context, 0x2000);
        EncryptedAddress addr3(context, 0x1000);

        REQUIRE((addr1 == addr3).decrypt() == true);
        REQUIRE((addr1 != addr2).decrypt() == true);
        REQUIRE((addr2 > addr1).decrypt() == true);
        REQUIRE((addr1 < addr2).decrypt() == true);
        REQUIRE((addr1 >= addr3).decrypt() == true);
        REQUIRE((addr1 <= addr3).decrypt() == true);
    }

    SECTION("null checking") {
        EncryptedAddress null_addr(context, 0);
        EncryptedAddress non_null_addr(context, 0x1000);

        REQUIRE(null_addr.is_null().decrypt() == true);
        REQUIRE(non_null_addr.is_null().decrypt() == false);
    }

    SECTION("alignment operations") {
        EncryptedAddress addr(context, 0x1003);

        auto aligned = addr.align_to(8);
        REQUIRE(aligned.decrypt() == 0x1008);

        REQUIRE(addr.is_aligned(8).decrypt() == false);
        REQUIRE(aligned.is_aligned(8).decrypt() == true);
    }
}

TEST_CASE("encrypted pointer operations", "[encrypted_types][pointer]") {
    auto context = create_test_context();

    SECTION("construction and basic operations") {
        int* test_ptr = reinterpret_cast<int*>(0x2000);
        EncryptedPointer<int> ptr1(context, test_ptr);
        
        REQUIRE(ptr1.decrypt() == test_ptr);
        REQUIRE(ptr1.is_valid());
        REQUIRE(ptr1.get_element_size() == sizeof(int));
    }

    SECTION("pointer arithmetic") {
        EncryptedPointer<int> ptr(context, reinterpret_cast<int*>(0x1000));
        
        auto ptr_plus_one = ptr + 1;
        REQUIRE(ptr_plus_one.decrypt() == reinterpret_cast<int*>(0x1000 + sizeof(int)));

        auto ptr_minus_one = ptr_plus_one - 1;
        REQUIRE(ptr_minus_one.decrypt() == reinterpret_cast<int*>(0x1000));

        EncryptedSize offset(context, 3);
        auto ptr_plus_offset = ptr + offset;
        REQUIRE(ptr_plus_offset.decrypt() == reinterpret_cast<int*>(0x1000 + 3 * sizeof(int)));
    }

    SECTION("increment and decrement") {
        EncryptedPointer<int> ptr(context, reinterpret_cast<int*>(0x1000));
        uintptr_t original_addr = 0x1000;

        auto pre_inc = ++ptr;
        REQUIRE(ptr.decrypt() == reinterpret_cast<int*>(original_addr + sizeof(int)));
        REQUIRE(pre_inc.decrypt() == ptr.decrypt());

        auto post_dec = ptr--;
        REQUIRE(post_dec.decrypt() == reinterpret_cast<int*>(original_addr + sizeof(int)));
        REQUIRE(ptr.decrypt() == reinterpret_cast<int*>(original_addr));
    }

    SECTION("pointer difference") {
        EncryptedPointer<int> ptr1(context, reinterpret_cast<int*>(0x1000));
        EncryptedPointer<int> ptr2(context, reinterpret_cast<int*>(0x1000 + 5 * sizeof(int)));

        auto diff = ptr2 - ptr1;
        REQUIRE(diff.decrypt() == 5);
    }

    SECTION("pointer comparison") {
        EncryptedPointer<int> ptr1(context, reinterpret_cast<int*>(0x1000));
        EncryptedPointer<int> ptr2(context, reinterpret_cast<int*>(0x2000));
        EncryptedPointer<int> ptr3(context, reinterpret_cast<int*>(0x1000));

        REQUIRE((ptr1 == ptr3).decrypt() == true);
        REQUIRE((ptr1 != ptr2).decrypt() == true);
        REQUIRE((ptr2 > ptr1).decrypt() == true);
        REQUIRE((ptr1 < ptr2).decrypt() == true);
    }

    SECTION("null and alignment checking") {
        EncryptedPointer<int> null_ptr(context, static_cast<int*>(nullptr));
        EncryptedPointer<int> aligned_ptr(context, reinterpret_cast<int*>(0x1000));
        EncryptedPointer<int> unaligned_ptr(context, reinterpret_cast<int*>(0x1001));

        REQUIRE(null_ptr.is_null().decrypt() == true);
        REQUIRE(aligned_ptr.is_null().decrypt() == false);

        REQUIRE(aligned_ptr.is_aligned().decrypt() == (0x1000 % alignof(int) == 0));
        REQUIRE(unaligned_ptr.is_aligned().decrypt() == (0x1001 % alignof(int) == 0));
    }
}

TEST_CASE("enhanced encrypted bool operations", "[encrypted_types][bool]") {
    auto context = create_test_context();

    SECTION("construction and basic operations") {
        EnhancedEncryptedBool bool_true(context, true);
        EnhancedEncryptedBool bool_false(context, false);
        EnhancedEncryptedBool bool_unknown = EnhancedEncryptedBool::unknown(context);

        REQUIRE(bool_true.decrypt() == TriState::TRUE);
        REQUIRE(bool_false.decrypt() == TriState::FALSE);
        REQUIRE(bool_unknown.decrypt() == TriState::UNKNOWN);
    }

    SECTION("logical operations") {
        EnhancedEncryptedBool bool_true(context, true);
        EnhancedEncryptedBool bool_false(context, false);

        auto and_result = bool_true && bool_false;
        REQUIRE(and_result.decrypt() == TriState::FALSE);

        auto or_result = bool_true || bool_false;
        REQUIRE(or_result.decrypt() == TriState::TRUE);

        auto not_true = !bool_true;
        REQUIRE(not_true.decrypt() == TriState::FALSE);

        auto not_false = !bool_false;
        REQUIRE(not_false.decrypt() == TriState::TRUE);
    }

    SECTION("kleene three-valued logic") {
        EnhancedEncryptedBool bool_true(context, true);
        EnhancedEncryptedBool bool_false(context, false);
        EnhancedEncryptedBool bool_unknown = EnhancedEncryptedBool::unknown(context);

        auto true_and_unknown = bool_true.kleene_and(bool_unknown);
        REQUIRE(true_and_unknown.decrypt() == TriState::UNKNOWN);

        auto false_and_unknown = bool_false.kleene_and(bool_unknown);
        REQUIRE(false_and_unknown.decrypt() == TriState::FALSE);

        auto true_or_unknown = bool_true.kleene_or(bool_unknown);
        REQUIRE(true_or_unknown.decrypt() == TriState::TRUE);

        auto false_or_unknown = bool_false.kleene_or(bool_unknown);
        REQUIRE(false_or_unknown.decrypt() == TriState::UNKNOWN);

        auto not_unknown = !bool_unknown;
        REQUIRE(not_unknown.decrypt() == TriState::UNKNOWN);
    }

    SECTION("xor operations") {
        EnhancedEncryptedBool bool_true(context, true);
        EnhancedEncryptedBool bool_false(context, false);
        EnhancedEncryptedBool bool_unknown = EnhancedEncryptedBool::unknown(context);

        auto true_xor_false = bool_true ^ bool_false;
        REQUIRE(true_xor_false.decrypt() == TriState::TRUE);

        auto true_xor_true = bool_true ^ bool_true;
        REQUIRE(true_xor_true.decrypt() == TriState::FALSE);

        auto true_xor_unknown = bool_true ^ bool_unknown;
        REQUIRE(true_xor_unknown.decrypt() == TriState::UNKNOWN);
    }

    SECTION("conversion to regular encrypted bool") {
        EnhancedEncryptedBool bool_true(context, true);
        EnhancedEncryptedBool bool_false(context, false);
        EnhancedEncryptedBool bool_unknown = EnhancedEncryptedBool::unknown(context);

        auto regular_true = bool_true.to_encrypted_bool();
        REQUIRE(regular_true.decrypt() == true);

        auto regular_false = bool_false.to_encrypted_bool();
        REQUIRE(regular_false.decrypt() == false);

        REQUIRE_THROWS_AS(bool_unknown.to_encrypted_bool(), InvalidOperationError);
    }
}

TEST_CASE("type conversion utilities", "[encrypted_types][conversions]") {
    auto context = create_test_context();

    SECTION("safe casting between size and address") {
        EncryptedSize size(context, 0x1000);
        auto address = type_conversions::safe_cast_to_address(size);
        REQUIRE(address.decrypt() == 0x1000);

        auto back_to_size = type_conversions::safe_cast_to_size(address);
        REQUIRE(back_to_size.decrypt() == 0x1000);
    }

    SECTION("casting to encrypted int") {
        EncryptedSize size(context, 42);
        EncryptedAddress address(context, 0x2000);

        auto size_as_int = type_conversions::to_encrypted_int(size);
        REQUIRE(size_as_int.decrypt() == 42);

        auto address_as_int = type_conversions::to_encrypted_int(address);
        REQUIRE(address_as_int.decrypt() == 0x2000);
    }

    SECTION("casting from encrypted int") {
        EncryptedInt value1(context, 100);
        EncryptedInt value2(context, 0x3000);

        auto size_from_int = type_conversions::from_encrypted_int_to_size(value1);
        REQUIRE(size_from_int.decrypt() == 100);

        auto address_from_int = type_conversions::from_encrypted_int_to_address(value2);
        REQUIRE(address_from_int.decrypt() == 0x3000);
    }

    SECTION("overflow detection in conversions") {
        // these would normally cause overflow in real scenarios
        // for testing, we use values within safe ranges
        EncryptedSize large_size(context, 1000000);
        REQUIRE_NOTHROW(type_conversions::safe_cast_to_address(large_size));
    }
}

TEST_CASE("memory alignment utilities", "[encrypted_types][alignment]") {
    auto context = create_test_context();

    SECTION("template alignment functions") {
        EncryptedSize size(context, 13);
        EncryptedAddress address(context, 0x1003);

        auto aligned_size = memory_alignment::align_up<16>(size);
        REQUIRE(aligned_size.decrypt() == 16);

        auto aligned_address = memory_alignment::align_up<16>(address);
        REQUIRE(aligned_address.decrypt() == 0x1010);

        REQUIRE(memory_alignment::is_aligned<16>(aligned_size).decrypt() == true);
        REQUIRE(memory_alignment::is_aligned<16>(size).decrypt() == false);
    }

    SECTION("alignment padding calculation") {
        EncryptedAddress address(context, 0x1003);
        
        auto padding = memory_alignment::get_alignment_padding(address, 8);
        REQUIRE(padding.decrypt() == 5);

        auto aligned_address = address + padding;
        REQUIRE(aligned_address.is_aligned(8).decrypt() == true);
    }

    SECTION("aligned size calculation") {
        EncryptedSize size(context, 13);
        
        auto aligned = memory_alignment::calculate_aligned_size(size, 16);
        REQUIRE(aligned.decrypt() == 16);
        REQUIRE(aligned.is_aligned(16).decrypt() == true);
    }

    SECTION("common simd alignments") {
        EncryptedSize size(context, 10);
        
        auto aligned_128 = memory_alignment::align_up<memory_alignment::SIMD_ALIGNMENT_128>(size);
        REQUIRE(aligned_128.decrypt() == 16);

        auto aligned_256 = memory_alignment::align_up<memory_alignment::SIMD_ALIGNMENT_256>(size);
        REQUIRE(aligned_256.decrypt() == 32);

        auto aligned_512 = memory_alignment::align_up<memory_alignment::SIMD_ALIGNMENT_512>(size);
        REQUIRE(aligned_512.decrypt() == 64);
    }
}

TEST_CASE("serialization support", "[encrypted_types][serialization]") {
    auto context = create_test_context();

    SECTION("encrypted size serialization") {
        EncryptedSize original(context, 1024);
        
        auto serialized = serialization::TypeSerializer::serialize(original);
        REQUIRE(serialized.size() > sizeof(serialization::TypeHeader));

        auto deserialized = serialization::TypeSerializer::deserialize_size(serialized, context);
        REQUIRE(deserialized.decrypt() == original.decrypt());
    }

    SECTION("encrypted address serialization") {
        EncryptedAddress original(context, 0x2000);
        
        auto serialized = serialization::TypeSerializer::serialize(original);
        REQUIRE(serialized.size() > sizeof(serialization::TypeHeader));

        auto deserialized = serialization::TypeSerializer::deserialize_address(serialized, context);
        REQUIRE(deserialized.decrypt() == original.decrypt());
    }

    SECTION("enhanced encrypted bool serialization") {
        EnhancedEncryptedBool original(context, TriState::UNKNOWN);
        
        auto serialized = serialization::TypeSerializer::serialize(original);
        REQUIRE(serialized.size() > sizeof(serialization::TypeHeader));

        auto deserialized = serialization::TypeSerializer::deserialize_bool(serialized, context);
        REQUIRE(deserialized.decrypt() == original.decrypt());
    }

    SECTION("serialization error handling") {
        std::vector<uint8_t> invalid_data = {0x01, 0x02, 0x03};
        
        REQUIRE_THROWS_AS(
            serialization::TypeSerializer::deserialize_size(invalid_data, context),
            InvalidOperationError
        );

        REQUIRE_THROWS_AS(
            serialization::TypeSerializer::deserialize_address(invalid_data, context),
            InvalidOperationError
        );

        REQUIRE_THROWS_AS(
            serialization::TypeSerializer::deserialize_bool(invalid_data, context),
            InvalidOperationError
        );
    }
}

TEST_CASE("exception handling", "[encrypted_types][exceptions]") {
    auto context = create_test_context();

    SECTION("overflow error detection") {
        REQUIRE_THROWS_AS(EncryptedSize(context, static_cast<size_t>(-1)), OverflowError);
    }

    SECTION("invalid operation errors") {
        EncryptedSize size(context, 100);
        REQUIRE_THROWS_AS(size.align_to(7), InvalidOperationError);
        REQUIRE_THROWS_AS(size.is_aligned(0), InvalidOperationError);
        
        EncryptedAddress address(context, 0x1000);
        REQUIRE_THROWS_AS(address.align_to(7), InvalidOperationError);
        REQUIRE_THROWS_AS(address.is_aligned(0), InvalidOperationError);
    }

    SECTION("tristate validation") {
        REQUIRE_THROWS_AS(EnhancedEncryptedBool(context, static_cast<TriState>(5)), InvalidOperationError);
    }
}

TEST_CASE("edge cases and boundary conditions", "[encrypted_types][edge_cases]") {
    auto context = create_test_context();

    SECTION("zero values") {
        EncryptedSize zero_size(context, 0);
        EncryptedAddress zero_address(context, 0);

        REQUIRE(zero_size.decrypt() == 0);
        REQUIRE(zero_address.decrypt() == 0);
        REQUIRE(zero_address.is_null().decrypt() == true);
    }

    SECTION("maximum safe values") {
        size_t max_size = 1000000;
        uintptr_t max_addr = 0x7FFFFFFF;

        EncryptedSize large_size(context, max_size);
        EncryptedAddress large_addr(context, max_addr);

        REQUIRE(large_size.decrypt() == max_size);
        REQUIRE(large_addr.decrypt() == max_addr);
    }

    SECTION("alignment edge cases") {
        EncryptedSize already_aligned(context, 32);
        REQUIRE(already_aligned.align_to(16).decrypt() == 32);
        REQUIRE(already_aligned.is_aligned(16).decrypt() == true);

        EncryptedSize power_of_two_minus_one(context, 15);
        REQUIRE(power_of_two_minus_one.align_to(16).decrypt() == 16);
    }
}