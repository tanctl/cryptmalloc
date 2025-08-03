#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include "cryptmalloc/bfv_context.hpp"
#include "cryptmalloc/bfv_operations.hpp"
#include "cryptmalloc/bfv_comparisons.hpp"

namespace cryptmalloc {

class EncryptionError : public std::runtime_error {
  public:
    explicit EncryptionError(const std::string& message) : std::runtime_error(message) {}
};

class OverflowError : public EncryptionError {
  public:
    explicit OverflowError(const std::string& message) : EncryptionError(message) {}
};

class InvalidOperationError : public EncryptionError {
  public:
    explicit InvalidOperationError(const std::string& message) : EncryptionError(message) {}
};

enum class TriState { FALSE = 0, TRUE = 1, UNKNOWN = 2 };

class EncryptedSize {
  public:
    explicit EncryptedSize(std::shared_ptr<BFVContext> context);
    EncryptedSize(std::shared_ptr<BFVContext> context, size_t size);
    explicit EncryptedSize(const EncryptedInt& encrypted_int);

    EncryptedSize(const EncryptedSize& other);
    EncryptedSize& operator=(const EncryptedSize& other);
    EncryptedSize(EncryptedSize&& other) noexcept;
    EncryptedSize& operator=(EncryptedSize&& other) noexcept;

    EncryptedSize operator+(const EncryptedSize& other) const;
    EncryptedSize operator-(const EncryptedSize& other) const;
    EncryptedSize operator*(const EncryptedSize& other) const;
    EncryptedSize operator/(const EncryptedSize& other) const;
    EncryptedSize operator%(const EncryptedSize& other) const;

    EncryptedSize& operator+=(const EncryptedSize& other);
    EncryptedSize& operator-=(const EncryptedSize& other);
    EncryptedSize& operator*=(const EncryptedSize& other);
    EncryptedSize& operator/=(const EncryptedSize& other);
    EncryptedSize& operator%=(const EncryptedSize& other);

    EncryptedSize operator+(size_t value) const;
    EncryptedSize operator-(size_t value) const;
    EncryptedSize operator*(size_t value) const;
    EncryptedSize operator/(size_t value) const;
    EncryptedSize operator%(size_t value) const;

    EncryptedSize& operator+=(size_t value);
    EncryptedSize& operator-=(size_t value);
    EncryptedSize& operator*=(size_t value);
    EncryptedSize& operator/=(size_t value);
    EncryptedSize& operator%=(size_t value);

    EncryptedBool operator==(const EncryptedSize& other) const;
    EncryptedBool operator!=(const EncryptedSize& other) const;
    EncryptedBool operator<(const EncryptedSize& other) const;
    EncryptedBool operator>(const EncryptedSize& other) const;
    EncryptedBool operator<=(const EncryptedSize& other) const;
    EncryptedBool operator>=(const EncryptedSize& other) const;

    EncryptedBool operator==(size_t value) const;
    EncryptedBool operator!=(size_t value) const;
    EncryptedBool operator<(size_t value) const;
    EncryptedBool operator>(size_t value) const;
    EncryptedBool operator<=(size_t value) const;
    EncryptedBool operator>=(size_t value) const;

    size_t decrypt() const;
    bool is_valid() const;
    EncryptedInt to_encrypted_int() const;

    EncryptedSize align_to(size_t alignment) const;
    EncryptedBool is_aligned(size_t alignment) const;
    static size_t get_simd_alignment();
    static size_t get_cache_line_size();

    std::shared_ptr<BFVContext> get_context() const { return encrypted_value_.get_context(); }

  private:
    EncryptedInt encrypted_value_;
    void validate_size_bounds(int64_t value) const;
};

class EncryptedAddress {
  public:
    explicit EncryptedAddress(std::shared_ptr<BFVContext> context);
    EncryptedAddress(std::shared_ptr<BFVContext> context, uintptr_t address);
    explicit EncryptedAddress(const EncryptedInt& encrypted_int);

    EncryptedAddress(const EncryptedAddress& other);
    EncryptedAddress& operator=(const EncryptedAddress& other);
    EncryptedAddress(EncryptedAddress&& other) noexcept;
    EncryptedAddress& operator=(EncryptedAddress&& other) noexcept;

    EncryptedAddress operator+(const EncryptedSize& offset) const;
    EncryptedAddress operator-(const EncryptedSize& offset) const;
    EncryptedSize operator-(const EncryptedAddress& other) const;

    EncryptedAddress& operator+=(const EncryptedSize& offset);
    EncryptedAddress& operator-=(const EncryptedSize& offset);

    EncryptedAddress operator+(size_t offset) const;
    EncryptedAddress operator-(size_t offset) const;
    EncryptedAddress& operator+=(size_t offset);
    EncryptedAddress& operator-=(size_t offset);

    EncryptedBool operator==(const EncryptedAddress& other) const;
    EncryptedBool operator!=(const EncryptedAddress& other) const;
    EncryptedBool operator<(const EncryptedAddress& other) const;
    EncryptedBool operator>(const EncryptedAddress& other) const;
    EncryptedBool operator<=(const EncryptedAddress& other) const;
    EncryptedBool operator>=(const EncryptedAddress& other) const;

    uintptr_t decrypt() const;
    bool is_valid() const;
    EncryptedInt to_encrypted_int() const;

    EncryptedAddress align_to(size_t alignment) const;
    EncryptedBool is_aligned(size_t alignment) const;
    EncryptedBool is_null() const;

    std::shared_ptr<BFVContext> get_context() const { return encrypted_value_.get_context(); }

  private:
    EncryptedInt encrypted_value_;
    void validate_address_bounds(int64_t value) const;
};

template <typename T>
class EncryptedPointer {
  public:
    explicit EncryptedPointer(std::shared_ptr<BFVContext> context);
    EncryptedPointer(std::shared_ptr<BFVContext> context, T* pointer);
    EncryptedPointer(const EncryptedAddress& address, size_t element_size = sizeof(T));

    EncryptedPointer(const EncryptedPointer& other);
    EncryptedPointer& operator=(const EncryptedPointer& other);
    EncryptedPointer(EncryptedPointer&& other) noexcept;
    EncryptedPointer& operator=(EncryptedPointer&& other) noexcept;

    EncryptedPointer operator+(const EncryptedSize& offset) const;
    EncryptedPointer operator-(const EncryptedSize& offset) const;
    EncryptedSize operator-(const EncryptedPointer& other) const;

    EncryptedPointer& operator+=(const EncryptedSize& offset);
    EncryptedPointer& operator-=(const EncryptedSize& offset);

    EncryptedPointer operator+(ptrdiff_t offset) const;
    EncryptedPointer operator-(ptrdiff_t offset) const;
    EncryptedPointer& operator+=(ptrdiff_t offset);
    EncryptedPointer& operator-=(ptrdiff_t offset);

    EncryptedPointer& operator++();
    EncryptedPointer operator++(int);
    EncryptedPointer& operator--();
    EncryptedPointer operator--(int);

    EncryptedBool operator==(const EncryptedPointer& other) const;
    EncryptedBool operator!=(const EncryptedPointer& other) const;
    EncryptedBool operator<(const EncryptedPointer& other) const;
    EncryptedBool operator>(const EncryptedPointer& other) const;
    EncryptedBool operator<=(const EncryptedPointer& other) const;
    EncryptedBool operator>=(const EncryptedPointer& other) const;

    T* decrypt() const;
    bool is_valid() const;
    EncryptedAddress get_address() const { return address_; }
    size_t get_element_size() const { return element_size_; }

    EncryptedBool is_null() const;
    EncryptedBool is_aligned() const;

    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable for encrypted pointer");

    std::shared_ptr<BFVContext> get_context() const { return address_.get_context(); }

  private:
    EncryptedAddress address_;
    size_t element_size_ = sizeof(T);
};

class EnhancedEncryptedBool {
  public:
    explicit EnhancedEncryptedBool(std::shared_ptr<BFVContext> context);
    EnhancedEncryptedBool(std::shared_ptr<BFVContext> context, bool value);
    EnhancedEncryptedBool(std::shared_ptr<BFVContext> context, TriState state);
    explicit EnhancedEncryptedBool(const EncryptedBool& encrypted_bool);

    EnhancedEncryptedBool(const EnhancedEncryptedBool& other);
    EnhancedEncryptedBool& operator=(const EnhancedEncryptedBool& other);
    EnhancedEncryptedBool(EnhancedEncryptedBool&& other) noexcept;
    EnhancedEncryptedBool& operator=(EnhancedEncryptedBool&& other) noexcept;

    EnhancedEncryptedBool operator&&(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator||(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator!() const;

    EnhancedEncryptedBool operator&(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator|(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool operator^(const EnhancedEncryptedBool& other) const;

    TriState decrypt() const;
    bool is_valid() const;
    EncryptedBool to_encrypted_bool() const;

    static EnhancedEncryptedBool unknown(std::shared_ptr<BFVContext> context);
    EnhancedEncryptedBool kleene_and(const EnhancedEncryptedBool& other) const;
    EnhancedEncryptedBool kleene_or(const EnhancedEncryptedBool& other) const;

    std::shared_ptr<BFVContext> get_context() const { return state_.get_context(); }

  private:
    EncryptedInt state_;
    void validate_tristate_value(int64_t value) const;
};

namespace type_conversions {

template <typename From, typename To>
struct conversion_traits {
    static constexpr bool is_safe = false;
    static constexpr bool requires_bounds_check = true;
};

template <>
struct conversion_traits<EncryptedSize, EncryptedAddress> {
    static constexpr bool is_safe = false;
    static constexpr bool requires_bounds_check = true;
};

template <>
struct conversion_traits<EncryptedAddress, EncryptedSize> {
    static constexpr bool is_safe = false;
    static constexpr bool requires_bounds_check = true;
};

EncryptedSize safe_cast_to_size(const EncryptedAddress& address);
EncryptedAddress safe_cast_to_address(const EncryptedSize& size);

template <typename T>
EncryptedPointer<T> safe_cast_to_pointer(const EncryptedAddress& address);

EncryptedInt to_encrypted_int(const EncryptedSize& size);
EncryptedInt to_encrypted_int(const EncryptedAddress& address);

EncryptedSize from_encrypted_int_to_size(const EncryptedInt& value);
EncryptedAddress from_encrypted_int_to_address(const EncryptedInt& value);

}  // namespace type_conversions

namespace memory_alignment {

constexpr size_t SIMD_ALIGNMENT_128 = 16;
constexpr size_t SIMD_ALIGNMENT_256 = 32;
constexpr size_t SIMD_ALIGNMENT_512 = 64;
constexpr size_t CACHE_LINE_SIZE = 64;

template <size_t Alignment>
EncryptedSize align_up(const EncryptedSize& size);

template <size_t Alignment>
EncryptedAddress align_up(const EncryptedAddress& address);

template <size_t Alignment>
EncryptedBool is_aligned(const EncryptedSize& size);

template <size_t Alignment>
EncryptedBool is_aligned(const EncryptedAddress& address);

EncryptedSize get_alignment_padding(const EncryptedAddress& address, size_t alignment);
EncryptedSize calculate_aligned_size(const EncryptedSize& size, size_t alignment);

}  // namespace memory_alignment

namespace serialization {

struct TypeHeader {
    uint32_t version = 1;
    uint32_t type_id = 0;
    uint64_t data_size = 0;
    uint32_t checksum = 0;
};

enum class TypeId : uint32_t {
    ENCRYPTED_SIZE = 1,
    ENCRYPTED_ADDRESS = 2,
    ENCRYPTED_POINTER = 3,
    ENHANCED_ENCRYPTED_BOOL = 4
};

class TypeSerializer {
  public:
    static std::vector<uint8_t> serialize(const EncryptedSize& value);
    static std::vector<uint8_t> serialize(const EncryptedAddress& value);
    static std::vector<uint8_t> serialize(const EnhancedEncryptedBool& value);

    template <typename T>
    static std::vector<uint8_t> serialize(const EncryptedPointer<T>& value);

    static EncryptedSize deserialize_size(const std::vector<uint8_t>& data,
                                         std::shared_ptr<BFVContext> context);
    static EncryptedAddress deserialize_address(const std::vector<uint8_t>& data,
                                               std::shared_ptr<BFVContext> context);
    static EnhancedEncryptedBool deserialize_bool(const std::vector<uint8_t>& data,
                                                 std::shared_ptr<BFVContext> context);

    template <typename T>
    static EncryptedPointer<T> deserialize_pointer(const std::vector<uint8_t>& data,
                                                   std::shared_ptr<BFVContext> context);

  private:
    static TypeHeader create_header(TypeId type_id, size_t data_size);
    static bool validate_header(const TypeHeader& header, TypeId expected_type);
    static uint32_t calculate_checksum(const std::vector<uint8_t>& data);
};

}  // namespace serialization

}  // namespace cryptmalloc