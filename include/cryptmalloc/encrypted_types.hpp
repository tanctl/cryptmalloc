/**
 * @file encrypted_types.hpp
 * @brief type-safe encrypted data types with operator overloading for natural memory management syntax
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <iostream>
#include <iomanip>

#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/bfv_operations.hpp"
#include "cryptmalloc/bfv_comparisons.hpp"
#include "cryptmalloc/core.hpp"

namespace cryptmalloc {

// Forward declarations
class EncryptedSize;
class EncryptedAddress;
class EncryptedPointer;
class EnhancedEncryptedBool;

// ========== Custom Exception Hierarchy ==========

/**
 * @brief base exception for all encryption-related errors
 */
class EncryptionError : public std::runtime_error {
public:
    explicit EncryptionError(const std::string& message) 
        : std::runtime_error("EncryptionError: " + message) {}
};

/**
 * @brief exception for arithmetic overflow in encrypted operations
 */
class OverflowError : public EncryptionError {
public:
    explicit OverflowError(const std::string& message)
        : EncryptionError("Overflow: " + message) {}
};

/**
 * @brief exception for invalid operations on encrypted types
 */
class InvalidOperationError : public EncryptionError {
public:
    explicit InvalidOperationError(const std::string& message)
        : EncryptionError("InvalidOperation: " + message) {}
};

/**
 * @brief exception for type conversion errors
 */
class ConversionError : public EncryptionError {
public:
    explicit ConversionError(const std::string& message)
        : EncryptionError("Conversion: " + message) {}
};

// ========== Memory Alignment Utilities ==========

/**
 * @brief memory alignment constants for SIMD and cache optimization
 */
namespace alignment {
    constexpr size_t CACHE_LINE = 64;    ///< typical L1 cache line size
    constexpr size_t SIMD_128 = 16;      ///< 128-bit SIMD alignment
    constexpr size_t SIMD_256 = 32;      ///< 256-bit SIMD alignment
    constexpr size_t SIMD_512 = 64;      ///< 512-bit SIMD alignment
    constexpr size_t PAGE_SIZE = 4096;   ///< typical page size
}

/**
 * @brief memory alignment utilities
 */
class AlignmentUtils {
public:
    /**
     * @brief check if value is aligned to specified boundary
     */
    template<typename T>
    static bool is_aligned(T value, size_t alignment) noexcept {
        return (static_cast<uintptr_t>(value) % alignment) == 0;
    }

    /**
     * @brief align value up to specified boundary
     */
    template<typename T>
    static T align_up(T value, size_t alignment) noexcept {
        static_assert(std::is_integral_v<T>, "T must be integral type");
        return static_cast<T>((static_cast<uintptr_t>(value) + alignment - 1) & ~(alignment - 1));
    }

    /**
     * @brief align value down to specified boundary
     */
    template<typename T>
    static T align_down(T value, size_t alignment) noexcept {
        static_assert(std::is_integral_v<T>, "T must be integral type");
        return static_cast<T>(static_cast<uintptr_t>(value) & ~(alignment - 1));
    }

    /**
     * @brief calculate padding needed for alignment
     */
    template<typename T>
    static size_t padding_for_alignment(T value, size_t alignment) noexcept {
        return align_up(value, alignment) - static_cast<uintptr_t>(value);
    }
};

// ========== Type Conversion Utilities ==========

/**
 * @brief type conversion matrix with safety guarantees
 */
class TypeConverter {
public:
    /**
     * @brief bounds checking for safe conversions
     */
    template<typename From, typename To>
    static bool is_safe_conversion(From value) noexcept {
        static_assert(std::is_arithmetic_v<From> && std::is_arithmetic_v<To>,
                      "Types must be arithmetic");
        
        if constexpr (std::is_same_v<From, To>) {
            return true;
        }
        
        if constexpr (std::is_signed_v<From> && std::is_unsigned_v<To>) {
            return value >= 0 && static_cast<uintmax_t>(value) <= std::numeric_limits<To>::max();
        } else if constexpr (std::is_unsigned_v<From> && std::is_signed_v<To>) {
            return value <= static_cast<uintmax_t>(std::numeric_limits<To>::max());
        } else {
            return value >= std::numeric_limits<To>::min() && 
                   value <= std::numeric_limits<To>::max();
        }
    }

    /**
     * @brief safe conversion with validation
     */
    template<typename To, typename From>
    static Result<To> safe_convert(From value) {
        if (!is_safe_conversion<From, To>(value)) {
            return Result<To>("Value out of range for target type");
        }
        return Result<To>(static_cast<To>(value));
    }
};

// ========== Enhanced EncryptedBool with Three-Valued Logic ==========

/**
 * @brief enhanced encrypted boolean with three-valued logic support
 * supports true, false, and unknown states for conditional operations
 */
class EnhancedEncryptedBool {
public:
    /**
     * @brief three-valued logic states
     */
    enum class State {
        FALSE = 0,
        TRUE = 1, 
        UNKNOWN = 2
    };

private:
    EncryptedBool impl_;
    State known_state_;
    bool is_known_;

public:
    /**
     * @brief construct from plaintext boolean
     */
    EnhancedEncryptedBool(bool value, std::shared_ptr<BFVContext> context)
        : impl_(value, context), known_state_(value ? State::TRUE : State::FALSE), is_known_(true) {}

    /**
     * @brief construct unknown state
     */
    explicit EnhancedEncryptedBool(std::shared_ptr<BFVContext> context)
        : impl_(false, context), known_state_(State::UNKNOWN), is_known_(false) {}

    /**
     * @brief construct from existing EncryptedBool
     */
    explicit EnhancedEncryptedBool(const EncryptedBool& other)
        : impl_(other), known_state_(State::UNKNOWN), is_known_(false) {}

    // logical operators with three-valued logic
    EnhancedEncryptedBool operator&&(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator||(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator!() const;

    // comparison operators
    bool operator==(const EnhancedEncryptedBool& other) const;
    bool operator!=(const EnhancedEncryptedBool& other) const;

    /**
     * @brief get current state
     */
    State state() const noexcept { return known_state_; }

    /**
     * @brief check if state is known
     */
    bool is_state_known() const noexcept { return is_known_; }

    /**
     * @brief get underlying EncryptedBool
     */
    const EncryptedBool& underlying() const noexcept { return impl_; }

    /**
     * @brief decrypt to plaintext
     */
    Result<bool> decrypt() const { return impl_.decrypt(); }

    /**
     * @brief convert to string representation
     */
    std::string to_string() const;
};

// ========== EncryptedSize for Memory Block Sizes ==========

/**
 * @brief type-safe encrypted size for memory block sizes and allocation requests
 */
class EncryptedSize {
private:
    EncryptedInt impl_;
    static constexpr int64_t MIN_SIZE = 0;
    static constexpr int64_t MAX_SIZE = static_cast<int64_t>(SIZE_MAX >> 1); // avoid overflow

public:
    /**
     * @brief construct from plaintext size
     */
    explicit EncryptedSize(size_t size, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from EncryptedInt with validation
     */
    explicit EncryptedSize(const EncryptedInt& value);

    /**
     * @brief copy constructor
     */
    EncryptedSize(const EncryptedSize& other) = default;

    /**
     * @brief move constructor
     */
    EncryptedSize(EncryptedSize&& other) noexcept = default;

    /**
     * @brief copy assignment
     */
    EncryptedSize& operator=(const EncryptedSize& other) = default;

    /**
     * @brief move assignment
     */
    EncryptedSize& operator=(EncryptedSize&& other) noexcept = default;

    // arithmetic operators
    EncryptedSize operator+(const EncryptedSize& other) const;
    EncryptedSize operator-(const EncryptedSize& other) const;
    EncryptedSize operator*(const EncryptedSize& other) const;
    EncryptedSize operator/(const EncryptedSize& other) const;
    EncryptedSize operator%(const EncryptedSize& other) const;

    // compound assignment operators
    EncryptedSize& operator+=(const EncryptedSize& other);
    EncryptedSize& operator-=(const EncryptedSize& other);
    EncryptedSize& operator*=(const EncryptedSize& other);
    EncryptedSize& operator/=(const EncryptedSize& other);
    EncryptedSize& operator%=(const EncryptedSize& other);

    // comparison operators
    EnhancedEncryptedBool operator==(const EncryptedSize& other) const;
    EnhancedEncryptedBool operator!=(const EncryptedSize& other) const;
    EnhancedEncryptedBool operator<(const EncryptedSize& other) const;
    EnhancedEncryptedBool operator>(const EncryptedSize& other) const;
    EnhancedEncryptedBool operator<=(const EncryptedSize& other) const;
    EnhancedEncryptedBool operator>=(const EncryptedSize& other) const;

    // memory alignment operations
    EncryptedSize align_to(size_t alignment) const;
    EncryptedSize align_up_to(size_t alignment) const;
    EncryptedSize align_down_to(size_t alignment) const;
    EncryptedSize padding_for(size_t alignment) const;

    // utility methods
    Result<size_t> decrypt() const;
    const EncryptedInt& underlying() const noexcept { return impl_; }
    bool is_valid() const noexcept;

    // type conversions
    explicit operator EncryptedInt() const { return impl_; }
    Result<EncryptedAddress> to_address() const;

    // serialization support
    std::string serialize() const;
    static Result<EncryptedSize> deserialize(const std::string& data, std::shared_ptr<BFVContext> context);
};

// ========== EncryptedAddress for Memory Addresses ==========

/**
 * @brief type-safe encrypted address for memory addresses and pointer arithmetic
 */
class EncryptedAddress {
private:
    EncryptedInt impl_;
    static constexpr int64_t MIN_ADDRESS = 0;
    static constexpr int64_t MAX_ADDRESS = INTPTR_MAX;

public:
    /**
     * @brief construct from plaintext address
     */
    explicit EncryptedAddress(uintptr_t address, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from void pointer
     */
    explicit EncryptedAddress(const void* ptr, std::shared_ptr<BFVContext> context);

    /**
     * @brief construct from EncryptedInt with validation
     */
    explicit EncryptedAddress(const EncryptedInt& value);

    /**
     * @brief copy constructor
     */
    EncryptedAddress(const EncryptedAddress& other) = default;

    /**
     * @brief move constructor
     */
    EncryptedAddress(EncryptedAddress&& other) noexcept = default;

    /**
     * @brief copy assignment
     */
    EncryptedAddress& operator=(const EncryptedAddress& other) = default;

    /**
     * @brief move assignment
     */
    EncryptedAddress& operator=(EncryptedAddress&& other) noexcept = default;

    // pointer arithmetic
    EncryptedAddress operator+(const EncryptedSize& offset) const;
    EncryptedAddress operator-(const EncryptedSize& offset) const;
    EncryptedSize operator-(const EncryptedAddress& other) const;

    // compound assignment for pointer arithmetic
    EncryptedAddress& operator+=(const EncryptedSize& offset);
    EncryptedAddress& operator-=(const EncryptedSize& offset);

    // comparison operators
    EnhancedEncryptedBool operator==(const EncryptedAddress& other) const;
    EnhancedEncryptedBool operator!=(const EncryptedAddress& other) const;
    EnhancedEncryptedBool operator<(const EncryptedAddress& other) const;
    EnhancedEncryptedBool operator>(const EncryptedAddress& other) const;
    EnhancedEncryptedBool operator<=(const EncryptedAddress& other) const;
    EnhancedEncryptedBool operator>=(const EncryptedAddress& other) const;

    // memory alignment operations
    EncryptedAddress align_to(size_t alignment) const;
    EncryptedAddress align_up_to(size_t alignment) const;
    EncryptedAddress align_down_to(size_t alignment) const;
    EncryptedSize offset_to_alignment(size_t alignment) const;

    // utility methods
    Result<uintptr_t> decrypt() const;
    const EncryptedInt& underlying() const noexcept { return impl_; }
    bool is_valid() const noexcept;

    // type conversions
    explicit operator EncryptedInt() const { return impl_; }
    Result<void*> to_pointer() const;

    // serialization support
    std::string serialize() const;
    static Result<EncryptedAddress> deserialize(const std::string& data, std::shared_ptr<BFVContext> context);
};

// ========== EncryptedPointer with Metadata ==========

/**
 * @brief metadata for encrypted pointer operations
 */
struct PointerMetadata {
    size_t element_size = 1;        ///< size of pointed-to element
    size_t array_length = 1;        ///< length if pointing to array
    size_t alignment = 1;           ///< required alignment
    bool is_array = false;          ///< whether this points to an array
    bool is_valid = true;           ///< validity flag
    std::string type_name;          ///< human-readable type name

    /**
     * @brief validate metadata consistency
     */
    bool is_consistent() const noexcept {
        return element_size > 0 && array_length > 0 && alignment > 0 &&
               (alignment & (alignment - 1)) == 0; // power of 2 check
    }
};

/**
 * @brief type-safe encrypted pointer with metadata for safe pointer operations
 */
class EncryptedPointer {
private:
    EncryptedAddress address_;
    PointerMetadata metadata_;

public:
    /**
     * @brief construct from address and metadata
     */
    EncryptedPointer(const EncryptedAddress& address, const PointerMetadata& metadata);

    /**
     * @brief construct from plaintext pointer with metadata
     */
    template<typename T>
    EncryptedPointer(T* ptr, std::shared_ptr<BFVContext> context, size_t array_length = 1);

    /**
     * @brief copy constructor
     */
    EncryptedPointer(const EncryptedPointer& other) = default;

    /**
     * @brief move constructor
     */
    EncryptedPointer(EncryptedPointer&& other) noexcept = default;

    /**
     * @brief copy assignment
     */
    EncryptedPointer& operator=(const EncryptedPointer& other) = default;

    /**
     * @brief move assignment
     */
    EncryptedPointer& operator=(EncryptedPointer&& other) noexcept = default;

    // pointer arithmetic with bounds checking
    EncryptedPointer operator+(const EncryptedSize& offset) const;
    EncryptedPointer operator-(const EncryptedSize& offset) const;
    EncryptedSize operator-(const EncryptedPointer& other) const;

    // array indexing
    EncryptedPointer operator[](const EncryptedSize& index) const;

    // compound assignment
    EncryptedPointer& operator+=(const EncryptedSize& offset);
    EncryptedPointer& operator-=(const EncryptedSize& offset);

    // comparison operators
    EnhancedEncryptedBool operator==(const EncryptedPointer& other) const;
    EnhancedEncryptedBool operator!=(const EncryptedPointer& other) const;
    EnhancedEncryptedBool operator<(const EncryptedPointer& other) const;
    EnhancedEncryptedBool operator>(const EncryptedPointer& other) const;
    EnhancedEncryptedBool operator<=(const EncryptedPointer& other) const;
    EnhancedEncryptedBool operator>=(const EncryptedPointer& other) const;

    // metadata operations
    const PointerMetadata& metadata() const noexcept { return metadata_; }
    void update_metadata(const PointerMetadata& new_metadata);
    EnhancedEncryptedBool is_aligned() const;
    EnhancedEncryptedBool is_in_bounds(const EncryptedSize& index) const;

    // utility methods
    const EncryptedAddress& address() const noexcept { return address_; }
    Result<void*> decrypt() const;
    bool is_valid() const noexcept;

    // type-safe operations
    EncryptedSize size_in_bytes() const;
    EncryptedSize total_size() const;
    EncryptedPointer align_to(size_t alignment) const;

    // serialization support
    std::string serialize() const;
    static Result<EncryptedPointer> deserialize(const std::string& data, std::shared_ptr<BFVContext> context);
};

// ========== Stream Operators for Debugging ==========

std::ostream& operator<<(std::ostream& os, const EnhancedEncryptedBool& value);
std::ostream& operator<<(std::ostream& os, const EncryptedSize& value);
std::ostream& operator<<(std::ostream& os, const EncryptedAddress& value);
std::ostream& operator<<(std::ostream& os, const EncryptedPointer& value);

// ========== Type Traits for Template Metaprogramming ==========

/**
 * @brief type trait to check if type is an encrypted type
 */
template<typename T>
struct is_encrypted_type : std::false_type {};

template<>
struct is_encrypted_type<EncryptedSize> : std::true_type {};

template<>
struct is_encrypted_type<EncryptedAddress> : std::true_type {};

template<>
struct is_encrypted_type<EncryptedPointer> : std::true_type {};

template<>
struct is_encrypted_type<EnhancedEncryptedBool> : std::true_type {};

template<typename T>
constexpr bool is_encrypted_type_v = is_encrypted_type<T>::value;

} // namespace cryptmalloc