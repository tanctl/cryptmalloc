#include "cryptmalloc/encrypted_types.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

#ifdef __linux__
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace cryptmalloc {

EncryptedSize::EncryptedSize(std::shared_ptr<BFVContext> context) : encrypted_value_(context) {}

EncryptedSize::EncryptedSize(std::shared_ptr<BFVContext> context, size_t size)
    : encrypted_value_(context, static_cast<int64_t>(size)) {
    validate_size_bounds(static_cast<int64_t>(size));
}

EncryptedSize::EncryptedSize(const EncryptedInt& encrypted_int) : encrypted_value_(encrypted_int) {}

EncryptedSize::EncryptedSize(const EncryptedSize& other) : encrypted_value_(other.encrypted_value_) {}

EncryptedSize& EncryptedSize::operator=(const EncryptedSize& other) {
    if (this != &other) {
        encrypted_value_ = other.encrypted_value_;
    }
    return *this;
}

EncryptedSize::EncryptedSize(EncryptedSize&& other) noexcept
    : encrypted_value_(std::move(other.encrypted_value_)) {}

EncryptedSize& EncryptedSize::operator=(EncryptedSize&& other) noexcept {
    if (this != &other) {
        encrypted_value_ = std::move(other.encrypted_value_);
    }
    return *this;
}

EncryptedSize EncryptedSize::operator+(const EncryptedSize& other) const {
    return EncryptedSize(encrypted_value_ + other.encrypted_value_);
}

EncryptedSize EncryptedSize::operator-(const EncryptedSize& other) const {
    return EncryptedSize(encrypted_value_ - other.encrypted_value_);
}

EncryptedSize EncryptedSize::operator*(const EncryptedSize& other) const {
    return EncryptedSize(encrypted_value_ * other.encrypted_value_);
}

EncryptedSize EncryptedSize::operator/(const EncryptedSize& other) const {
    auto zero_check = comparisons::equal(other.encrypted_value_, EncryptedInt(other.get_context(), 0));
    if (zero_check.decrypt()) {
        throw InvalidOperationError("division by zero in encrypted size operation");
    }
    
    // simplified division using repeated subtraction for small values
    auto context = get_context();
    EncryptedInt quotient(context, 0);
    EncryptedInt remainder = encrypted_value_;
    
    // this is a placeholder - proper encrypted division needs more sophisticated implementation
    auto dividend_decrypted = encrypted_value_.decrypt();
    auto divisor_decrypted = other.encrypted_value_.decrypt();
    
    if (divisor_decrypted <= 0) {
        throw InvalidOperationError("invalid divisor in encrypted division");
    }
    
    int64_t result = dividend_decrypted / divisor_decrypted;
    return EncryptedSize(context, static_cast<size_t>(result));
}

EncryptedSize EncryptedSize::operator%(const EncryptedSize& other) const {
    auto zero_check = comparisons::equal(other.encrypted_value_, EncryptedInt(other.get_context(), 0));
    if (zero_check.decrypt()) {
        throw InvalidOperationError("modulo by zero in encrypted size operation");
    }
    
    auto dividend_decrypted = encrypted_value_.decrypt();
    auto divisor_decrypted = other.encrypted_value_.decrypt();
    
    if (divisor_decrypted <= 0) {
        throw InvalidOperationError("invalid divisor in encrypted modulo");
    }
    
    int64_t result = dividend_decrypted % divisor_decrypted;
    return EncryptedSize(get_context(), static_cast<size_t>(result));
}

EncryptedSize& EncryptedSize::operator+=(const EncryptedSize& other) {
    *this = *this + other;
    return *this;
}

EncryptedSize& EncryptedSize::operator-=(const EncryptedSize& other) {
    *this = *this - other;
    return *this;
}

EncryptedSize& EncryptedSize::operator*=(const EncryptedSize& other) {
    *this = *this * other;
    return *this;
}

EncryptedSize& EncryptedSize::operator/=(const EncryptedSize& other) {
    *this = *this / other;
    return *this;
}

EncryptedSize& EncryptedSize::operator%=(const EncryptedSize& other) {
    *this = *this % other;
    return *this;
}

EncryptedSize EncryptedSize::operator+(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return EncryptedSize(encrypted_value_ + static_cast<int64_t>(value));
}

EncryptedSize EncryptedSize::operator-(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return EncryptedSize(encrypted_value_ - static_cast<int64_t>(value));
}

EncryptedSize EncryptedSize::operator*(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return EncryptedSize(encrypted_value_ * static_cast<int64_t>(value));
}

EncryptedSize EncryptedSize::operator/(size_t value) const {
    if (value == 0) {
        throw InvalidOperationError("division by zero");
    }
    validate_size_bounds(static_cast<int64_t>(value));
    
    int64_t dividend = encrypted_value_.decrypt();
    int64_t result = dividend / static_cast<int64_t>(value);
    return EncryptedSize(get_context(), static_cast<size_t>(result));
}

EncryptedSize EncryptedSize::operator%(size_t value) const {
    if (value == 0) {
        throw InvalidOperationError("modulo by zero");
    }
    validate_size_bounds(static_cast<int64_t>(value));
    
    int64_t dividend = encrypted_value_.decrypt();
    int64_t result = dividend % static_cast<int64_t>(value);
    return EncryptedSize(get_context(), static_cast<size_t>(result));
}

EncryptedSize& EncryptedSize::operator+=(size_t value) {
    *this = *this + value;
    return *this;
}

EncryptedSize& EncryptedSize::operator-=(size_t value) {
    *this = *this - value;
    return *this;
}

EncryptedSize& EncryptedSize::operator*=(size_t value) {
    *this = *this * value;
    return *this;
}

EncryptedSize& EncryptedSize::operator/=(size_t value) {
    *this = *this / value;
    return *this;
}

EncryptedSize& EncryptedSize::operator%=(size_t value) {
    *this = *this % value;
    return *this;
}

EncryptedBool EncryptedSize::operator==(const EncryptedSize& other) const {
    return comparisons::equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator!=(const EncryptedSize& other) const {
    return comparisons::not_equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator<(const EncryptedSize& other) const {
    return comparisons::less_than(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator>(const EncryptedSize& other) const {
    return comparisons::greater_than(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator<=(const EncryptedSize& other) const {
    return comparisons::less_equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator>=(const EncryptedSize& other) const {
    return comparisons::greater_equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedSize::operator==(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::equal(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

EncryptedBool EncryptedSize::operator!=(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::not_equal(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

EncryptedBool EncryptedSize::operator<(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::less_than(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

EncryptedBool EncryptedSize::operator>(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::greater_than(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

EncryptedBool EncryptedSize::operator<=(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::less_equal(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

EncryptedBool EncryptedSize::operator>=(size_t value) const {
    validate_size_bounds(static_cast<int64_t>(value));
    return comparisons::greater_equal(encrypted_value_, EncryptedInt(get_context(), static_cast<int64_t>(value)));
}

size_t EncryptedSize::decrypt() const {
    int64_t decrypted = encrypted_value_.decrypt();
    if (decrypted < 0) {
        throw OverflowError("negative size value after decryption");
    }
    return static_cast<size_t>(decrypted);
}

bool EncryptedSize::is_valid() const {
    return encrypted_value_.is_valid();
}

EncryptedInt EncryptedSize::to_encrypted_int() const {
    return encrypted_value_;
}

EncryptedSize EncryptedSize::align_to(size_t alignment) const {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    auto decrypted = decrypt();
    size_t aligned = ((decrypted + alignment - 1) / alignment) * alignment;
    return EncryptedSize(get_context(), aligned);
}

EncryptedBool EncryptedSize::is_aligned(size_t alignment) const {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    auto remainder = *this % alignment;
    return remainder == 0;
}

size_t EncryptedSize::get_simd_alignment() {
#if defined(__AVX512F__)
    return memory_alignment::SIMD_ALIGNMENT_512;
#elif defined(__AVX__) || defined(__AVX2__)
    return memory_alignment::SIMD_ALIGNMENT_256;
#elif defined(__SSE2__)
    return memory_alignment::SIMD_ALIGNMENT_128;
#else
    return sizeof(void*);
#endif
}

size_t EncryptedSize::get_cache_line_size() {
#ifdef __linux__
    long cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    return cache_line_size > 0 ? static_cast<size_t>(cache_line_size) : memory_alignment::CACHE_LINE_SIZE;
#elif defined(_WIN32)
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION* buffer = nullptr;
    DWORD buffer_size = 0;
    GetLogicalProcessorInformation(buffer, &buffer_size);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION*>(malloc(buffer_size));
        if (GetLogicalProcessorInformation(buffer, &buffer_size)) {
            for (DWORD i = 0; i < buffer_size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); ++i) {
                if (buffer[i].Relationship == RelationCache && buffer[i].Cache.Level == 1) {
                    size_t cache_line_size = buffer[i].Cache.LineSize;
                    free(buffer);
                    return cache_line_size;
                }
            }
        }
        free(buffer);
    }
    return memory_alignment::CACHE_LINE_SIZE;
#else
    return memory_alignment::CACHE_LINE_SIZE;
#endif
}

void EncryptedSize::validate_size_bounds(int64_t value) const {
    if (value < 0) {
        throw OverflowError("size cannot be negative");
    }
    if (static_cast<uint64_t>(value) > std::numeric_limits<size_t>::max()) {
        throw OverflowError("size value exceeds maximum size_t value");
    }
}

EncryptedAddress::EncryptedAddress(std::shared_ptr<BFVContext> context) : encrypted_value_(context) {}

EncryptedAddress::EncryptedAddress(std::shared_ptr<BFVContext> context, uintptr_t address)
    : encrypted_value_(context, static_cast<int64_t>(address)) {
    validate_address_bounds(static_cast<int64_t>(address));
}

EncryptedAddress::EncryptedAddress(const EncryptedInt& encrypted_int) : encrypted_value_(encrypted_int) {}

EncryptedAddress::EncryptedAddress(const EncryptedAddress& other) : encrypted_value_(other.encrypted_value_) {}

EncryptedAddress& EncryptedAddress::operator=(const EncryptedAddress& other) {
    if (this != &other) {
        encrypted_value_ = other.encrypted_value_;
    }
    return *this;
}

EncryptedAddress::EncryptedAddress(EncryptedAddress&& other) noexcept
    : encrypted_value_(std::move(other.encrypted_value_)) {}

EncryptedAddress& EncryptedAddress::operator=(EncryptedAddress&& other) noexcept {
    if (this != &other) {
        encrypted_value_ = std::move(other.encrypted_value_);
    }
    return *this;
}

EncryptedAddress EncryptedAddress::operator+(const EncryptedSize& offset) const {
    return EncryptedAddress(encrypted_value_ + offset.to_encrypted_int());
}

EncryptedAddress EncryptedAddress::operator-(const EncryptedSize& offset) const {
    return EncryptedAddress(encrypted_value_ - offset.to_encrypted_int());
}

EncryptedSize EncryptedAddress::operator-(const EncryptedAddress& other) const {
    return EncryptedSize(encrypted_value_ - other.encrypted_value_);
}

EncryptedAddress& EncryptedAddress::operator+=(const EncryptedSize& offset) {
    *this = *this + offset;
    return *this;
}

EncryptedAddress& EncryptedAddress::operator-=(const EncryptedSize& offset) {
    *this = *this - offset;
    return *this;
}

EncryptedAddress EncryptedAddress::operator+(size_t offset) const {
    return EncryptedAddress(encrypted_value_ + static_cast<int64_t>(offset));
}

EncryptedAddress EncryptedAddress::operator-(size_t offset) const {
    return EncryptedAddress(encrypted_value_ - static_cast<int64_t>(offset));
}

EncryptedAddress& EncryptedAddress::operator+=(size_t offset) {
    *this = *this + offset;
    return *this;
}

EncryptedAddress& EncryptedAddress::operator-=(size_t offset) {
    *this = *this - offset;
    return *this;
}

EncryptedBool EncryptedAddress::operator==(const EncryptedAddress& other) const {
    return comparisons::equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedAddress::operator!=(const EncryptedAddress& other) const {
    return comparisons::not_equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedAddress::operator<(const EncryptedAddress& other) const {
    return comparisons::less_than(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedAddress::operator>(const EncryptedAddress& other) const {
    return comparisons::greater_than(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedAddress::operator<=(const EncryptedAddress& other) const {
    return comparisons::less_equal(encrypted_value_, other.encrypted_value_);
}

EncryptedBool EncryptedAddress::operator>=(const EncryptedAddress& other) const {
    return comparisons::greater_equal(encrypted_value_, other.encrypted_value_);
}

uintptr_t EncryptedAddress::decrypt() const {
    int64_t decrypted = encrypted_value_.decrypt();
    if (decrypted < 0) {
        throw OverflowError("negative address value after decryption");
    }
    return static_cast<uintptr_t>(decrypted);
}

bool EncryptedAddress::is_valid() const {
    return encrypted_value_.is_valid();
}

EncryptedInt EncryptedAddress::to_encrypted_int() const {
    return encrypted_value_;
}

EncryptedAddress EncryptedAddress::align_to(size_t alignment) const {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    auto decrypted = decrypt();
    uintptr_t aligned = ((decrypted + alignment - 1) / alignment) * alignment;
    return EncryptedAddress(get_context(), aligned);
}

EncryptedBool EncryptedAddress::is_aligned(size_t alignment) const {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    auto decrypted = decrypt();
    return (decrypted % alignment) == 0 ? 
        EncryptedBool(get_context(), true) : 
        EncryptedBool(get_context(), false);
}

EncryptedBool EncryptedAddress::is_null() const {
    return comparisons::equal(encrypted_value_, EncryptedInt(get_context(), 0));
}

void EncryptedAddress::validate_address_bounds(int64_t value) const {
    if (value < 0) {
        throw OverflowError("address cannot be negative");
    }
    if (static_cast<uint64_t>(value) > std::numeric_limits<uintptr_t>::max()) {
        throw OverflowError("address value exceeds maximum uintptr_t value");
    }
}

EnhancedEncryptedBool::EnhancedEncryptedBool(std::shared_ptr<BFVContext> context) : state_(context) {}

EnhancedEncryptedBool::EnhancedEncryptedBool(std::shared_ptr<BFVContext> context, bool value)
    : state_(context, value ? 1 : 0) {}

EnhancedEncryptedBool::EnhancedEncryptedBool(std::shared_ptr<BFVContext> context, TriState state)
    : state_(context, static_cast<int64_t>(state)) {
    validate_tristate_value(static_cast<int64_t>(state));
}

EnhancedEncryptedBool::EnhancedEncryptedBool(const EncryptedBool& encrypted_bool)
    : state_(encrypted_bool.get_context(), encrypted_bool.decrypt() ? 1 : 0) {}

EnhancedEncryptedBool::EnhancedEncryptedBool(const EnhancedEncryptedBool& other) : state_(other.state_) {}

EnhancedEncryptedBool& EnhancedEncryptedBool::operator=(const EnhancedEncryptedBool& other) {
    if (this != &other) {
        state_ = other.state_;
    }
    return *this;
}

EnhancedEncryptedBool::EnhancedEncryptedBool(EnhancedEncryptedBool&& other) noexcept
    : state_(std::move(other.state_)) {}

EnhancedEncryptedBool& EnhancedEncryptedBool::operator=(EnhancedEncryptedBool&& other) noexcept {
    if (this != &other) {
        state_ = std::move(other.state_);
    }
    return *this;
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator&&(const EnhancedEncryptedBool& other) const {
    return kleene_and(other);
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator||(const EnhancedEncryptedBool& other) const {
    return kleene_or(other);
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator!() const {
    auto context = get_context();
    auto current_state = state_.decrypt();
    
    if (current_state == static_cast<int64_t>(TriState::TRUE)) {
        return EnhancedEncryptedBool(context, TriState::FALSE);
    } else if (current_state == static_cast<int64_t>(TriState::FALSE)) {
        return EnhancedEncryptedBool(context, TriState::TRUE);
    } else {
        return EnhancedEncryptedBool(context, TriState::UNKNOWN);
    }
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator&(const EnhancedEncryptedBool& other) const {
    return kleene_and(other);
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator|(const EnhancedEncryptedBool& other) const {
    return kleene_or(other);
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator^(const EnhancedEncryptedBool& other) const {
    auto context = get_context();
    auto state_a = state_.decrypt();
    auto state_b = other.state_.decrypt();
    
    // xor with unknown produces unknown
    if (state_a == static_cast<int64_t>(TriState::UNKNOWN) || 
        state_b == static_cast<int64_t>(TriState::UNKNOWN)) {
        return EnhancedEncryptedBool(context, TriState::UNKNOWN);
    }
    
    bool result = (state_a == static_cast<int64_t>(TriState::TRUE)) != 
                  (state_b == static_cast<int64_t>(TriState::TRUE));
    return EnhancedEncryptedBool(context, result);
}

TriState EnhancedEncryptedBool::decrypt() const {
    int64_t decrypted = state_.decrypt();
    validate_tristate_value(decrypted);
    return static_cast<TriState>(decrypted);
}

bool EnhancedEncryptedBool::is_valid() const {
    return state_.is_valid();
}

EncryptedBool EnhancedEncryptedBool::to_encrypted_bool() const {
    auto context = get_context();
    auto current_state = decrypt();
    
    if (current_state == TriState::UNKNOWN) {
        throw InvalidOperationError("cannot convert unknown tristate to boolean");
    }
    
    return EncryptedBool(context, current_state == TriState::TRUE);
}

EnhancedEncryptedBool EnhancedEncryptedBool::unknown(std::shared_ptr<BFVContext> context) {
    return EnhancedEncryptedBool(context, TriState::UNKNOWN);
}

EnhancedEncryptedBool EnhancedEncryptedBool::kleene_and(const EnhancedEncryptedBool& other) const {
    auto context = get_context();
    auto state_a = state_.decrypt();
    auto state_b = other.state_.decrypt();
    
    // kleene three-valued logic for AND
    if (state_a == static_cast<int64_t>(TriState::FALSE) || 
        state_b == static_cast<int64_t>(TriState::FALSE)) {
        return EnhancedEncryptedBool(context, TriState::FALSE);
    }
    
    if (state_a == static_cast<int64_t>(TriState::TRUE) && 
        state_b == static_cast<int64_t>(TriState::TRUE)) {
        return EnhancedEncryptedBool(context, TriState::TRUE);
    }
    
    return EnhancedEncryptedBool(context, TriState::UNKNOWN);
}

EnhancedEncryptedBool EnhancedEncryptedBool::kleene_or(const EnhancedEncryptedBool& other) const {
    auto context = get_context();
    auto state_a = state_.decrypt();
    auto state_b = other.state_.decrypt();
    
    // kleene three-valued logic for OR
    if (state_a == static_cast<int64_t>(TriState::TRUE) || 
        state_b == static_cast<int64_t>(TriState::TRUE)) {
        return EnhancedEncryptedBool(context, TriState::TRUE);
    }
    
    if (state_a == static_cast<int64_t>(TriState::FALSE) && 
        state_b == static_cast<int64_t>(TriState::FALSE)) {
        return EnhancedEncryptedBool(context, TriState::FALSE);
    }
    
    return EnhancedEncryptedBool(context, TriState::UNKNOWN);
}

void EnhancedEncryptedBool::validate_tristate_value(int64_t value) const {
    if (value < 0 || value > 2) {
        throw InvalidOperationError("invalid tristate value, must be 0, 1, or 2");
    }
}

namespace type_conversions {

EncryptedSize safe_cast_to_size(const EncryptedAddress& address) {
    auto decrypted = address.decrypt();
    if (decrypted > std::numeric_limits<size_t>::max()) {
        throw OverflowError("address value too large for size_t");
    }
    return EncryptedSize(address.get_context(), static_cast<size_t>(decrypted));
}

EncryptedAddress safe_cast_to_address(const EncryptedSize& size) {
    auto decrypted = size.decrypt();
    if (decrypted > std::numeric_limits<uintptr_t>::max()) {
        throw OverflowError("size value too large for uintptr_t");
    }
    return EncryptedAddress(size.get_context(), static_cast<uintptr_t>(decrypted));
}

template <typename T>
EncryptedPointer<T> safe_cast_to_pointer(const EncryptedAddress& address) {
    return EncryptedPointer<T>(address, sizeof(T));
}

EncryptedInt to_encrypted_int(const EncryptedSize& size) {
    return size.to_encrypted_int();
}

EncryptedInt to_encrypted_int(const EncryptedAddress& address) {
    return address.to_encrypted_int();
}

EncryptedSize from_encrypted_int_to_size(const EncryptedInt& value) {
    return EncryptedSize(value);
}

EncryptedAddress from_encrypted_int_to_address(const EncryptedInt& value) {
    return EncryptedAddress(value);
}

}  // namespace type_conversions

namespace memory_alignment {

template <size_t Alignment>
EncryptedSize align_up(const EncryptedSize& size) {
    static_assert((Alignment & (Alignment - 1)) == 0, "alignment must be power of 2");
    return size.align_to(Alignment);
}

template <size_t Alignment>
EncryptedAddress align_up(const EncryptedAddress& address) {
    static_assert((Alignment & (Alignment - 1)) == 0, "alignment must be power of 2");
    return address.align_to(Alignment);
}

template <size_t Alignment>
EncryptedBool is_aligned(const EncryptedSize& size) {
    static_assert((Alignment & (Alignment - 1)) == 0, "alignment must be power of 2");
    return size.is_aligned(Alignment);
}

template <size_t Alignment>
EncryptedBool is_aligned(const EncryptedAddress& address) {
    static_assert((Alignment & (Alignment - 1)) == 0, "alignment must be power of 2");
    return address.is_aligned(Alignment);
}

EncryptedSize get_alignment_padding(const EncryptedAddress& address, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    auto decrypted = address.decrypt();
    size_t padding = (alignment - (decrypted % alignment)) % alignment;
    return EncryptedSize(address.get_context(), padding);
}

EncryptedSize calculate_aligned_size(const EncryptedSize& size, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        throw InvalidOperationError("alignment must be power of 2");
    }
    
    return size.align_to(alignment);
}

// explicit template instantiations for common alignments
template EncryptedSize align_up<16>(const EncryptedSize& size);
template EncryptedSize align_up<32>(const EncryptedSize& size);
template EncryptedSize align_up<64>(const EncryptedSize& size);

template EncryptedAddress align_up<16>(const EncryptedAddress& address);
template EncryptedAddress align_up<32>(const EncryptedAddress& address);
template EncryptedAddress align_up<64>(const EncryptedAddress& address);

template EncryptedBool is_aligned<16>(const EncryptedSize& size);
template EncryptedBool is_aligned<32>(const EncryptedSize& size);
template EncryptedBool is_aligned<64>(const EncryptedSize& size);

template EncryptedBool is_aligned<16>(const EncryptedAddress& address);
template EncryptedBool is_aligned<32>(const EncryptedAddress& address);
template EncryptedBool is_aligned<64>(const EncryptedAddress& address);

}  // namespace memory_alignment

template <typename T>
EncryptedPointer<T>::EncryptedPointer(std::shared_ptr<BFVContext> context)
    : address_(context), element_size_(sizeof(T)) {}

template <typename T>
EncryptedPointer<T>::EncryptedPointer(std::shared_ptr<BFVContext> context, T* pointer)
    : address_(context, reinterpret_cast<uintptr_t>(pointer)), element_size_(sizeof(T)) {}

template <typename T>
EncryptedPointer<T>::EncryptedPointer(const EncryptedAddress& address, size_t element_size)
    : address_(address), element_size_(element_size) {}

template <typename T>
EncryptedPointer<T>::EncryptedPointer(const EncryptedPointer& other)
    : address_(other.address_), element_size_(other.element_size_) {}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator=(const EncryptedPointer& other) {
    if (this != &other) {
        address_ = other.address_;
        element_size_ = other.element_size_;
    }
    return *this;
}

template <typename T>
EncryptedPointer<T>::EncryptedPointer(EncryptedPointer&& other) noexcept
    : address_(std::move(other.address_)), element_size_(other.element_size_) {}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator=(EncryptedPointer&& other) noexcept {
    if (this != &other) {
        address_ = std::move(other.address_);
        element_size_ = other.element_size_;
    }
    return *this;
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator+(const EncryptedSize& offset) const {
    auto byte_offset = offset * element_size_;
    return EncryptedPointer<T>(address_ + byte_offset, element_size_);
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator-(const EncryptedSize& offset) const {
    auto byte_offset = offset * element_size_;
    return EncryptedPointer<T>(address_ - byte_offset, element_size_);
}

template <typename T>
EncryptedSize EncryptedPointer<T>::operator-(const EncryptedPointer& other) const {
    auto byte_diff = address_ - other.address_;
    return byte_diff / element_size_;
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator+=(const EncryptedSize& offset) {
    *this = *this + offset;
    return *this;
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator-=(const EncryptedSize& offset) {
    *this = *this - offset;
    return *this;
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator+(ptrdiff_t offset) const {
    return *this + EncryptedSize(get_context(), static_cast<size_t>(std::abs(offset)));
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator-(ptrdiff_t offset) const {
    return *this - EncryptedSize(get_context(), static_cast<size_t>(std::abs(offset)));
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator+=(ptrdiff_t offset) {
    *this = *this + offset;
    return *this;
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator-=(ptrdiff_t offset) {
    *this = *this - offset;
    return *this;
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator++() {
    *this += 1;
    return *this;
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator++(int) {
    EncryptedPointer<T> temp = *this;
    ++(*this);
    return temp;
}

template <typename T>
EncryptedPointer<T>& EncryptedPointer<T>::operator--() {
    *this -= 1;
    return *this;
}

template <typename T>
EncryptedPointer<T> EncryptedPointer<T>::operator--(int) {
    EncryptedPointer<T> temp = *this;
    --(*this);
    return temp;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator==(const EncryptedPointer& other) const {
    return address_ == other.address_;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator!=(const EncryptedPointer& other) const {
    return address_ != other.address_;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator<(const EncryptedPointer& other) const {
    return address_ < other.address_;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator>(const EncryptedPointer& other) const {
    return address_ > other.address_;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator<=(const EncryptedPointer& other) const {
    return address_ <= other.address_;
}

template <typename T>
EncryptedBool EncryptedPointer<T>::operator>=(const EncryptedPointer& other) const {
    return address_ >= other.address_;
}

template <typename T>
T* EncryptedPointer<T>::decrypt() const {
    return reinterpret_cast<T*>(address_.decrypt());
}

template <typename T>
bool EncryptedPointer<T>::is_valid() const {
    return address_.is_valid();
}

template <typename T>
EncryptedBool EncryptedPointer<T>::is_null() const {
    return address_.is_null();
}

template <typename T>
EncryptedBool EncryptedPointer<T>::is_aligned() const {
    return address_.is_aligned(alignof(T));
}

namespace serialization {

TypeHeader TypeSerializer::create_header(TypeId type_id, size_t data_size) {
    TypeHeader header;
    header.version = 1;
    header.type_id = static_cast<uint32_t>(type_id);
    header.data_size = static_cast<uint64_t>(data_size);
    header.checksum = 0;
    return header;
}

bool TypeSerializer::validate_header(const TypeHeader& header, TypeId expected_type) {
    return header.version == 1 && 
           header.type_id == static_cast<uint32_t>(expected_type) &&
           header.data_size > 0;
}

uint32_t TypeSerializer::calculate_checksum(const std::vector<uint8_t>& data) {
    uint32_t checksum = 0;
    for (uint8_t byte : data) {
        checksum = (checksum << 1) ^ byte;
    }
    return checksum;
}

std::vector<uint8_t> TypeSerializer::serialize(const EncryptedSize& value) {
    auto encrypted_data = value.to_encrypted_int();
    
    std::vector<uint8_t> result;
    TypeHeader header = create_header(TypeId::ENCRYPTED_SIZE, sizeof(int64_t));
    
    result.resize(sizeof(TypeHeader) + sizeof(int64_t));
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    int64_t decrypted = encrypted_data.decrypt();
    std::memcpy(result.data() + sizeof(TypeHeader), &decrypted, sizeof(int64_t));
    
    // calculate and update checksum
    header.checksum = calculate_checksum(result);
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    return result;
}

std::vector<uint8_t> TypeSerializer::serialize(const EncryptedAddress& value) {
    auto encrypted_data = value.to_encrypted_int();
    
    std::vector<uint8_t> result;
    TypeHeader header = create_header(TypeId::ENCRYPTED_ADDRESS, sizeof(int64_t));
    
    result.resize(sizeof(TypeHeader) + sizeof(int64_t));
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    int64_t decrypted = encrypted_data.decrypt();
    std::memcpy(result.data() + sizeof(TypeHeader), &decrypted, sizeof(int64_t));
    
    header.checksum = calculate_checksum(result);
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    return result;
}

std::vector<uint8_t> TypeSerializer::serialize(const EnhancedEncryptedBool& value) {
    std::vector<uint8_t> result;
    TypeHeader header = create_header(TypeId::ENHANCED_ENCRYPTED_BOOL, sizeof(int64_t));
    
    result.resize(sizeof(TypeHeader) + sizeof(int64_t));
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    int64_t state_value = static_cast<int64_t>(value.decrypt());
    std::memcpy(result.data() + sizeof(TypeHeader), &state_value, sizeof(int64_t));
    
    header.checksum = calculate_checksum(result);
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    return result;
}

template <typename T>
std::vector<uint8_t> TypeSerializer::serialize(const EncryptedPointer<T>& value) {
    std::vector<uint8_t> result;
    size_t data_size = sizeof(int64_t) + sizeof(size_t);
    TypeHeader header = create_header(TypeId::ENCRYPTED_POINTER, data_size);
    
    result.resize(sizeof(TypeHeader) + data_size);
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    int64_t address_value = static_cast<int64_t>(value.get_address().decrypt());
    size_t element_size = value.get_element_size();
    
    std::memcpy(result.data() + sizeof(TypeHeader), &address_value, sizeof(int64_t));
    std::memcpy(result.data() + sizeof(TypeHeader) + sizeof(int64_t), &element_size, sizeof(size_t));
    
    header.checksum = calculate_checksum(result);
    std::memcpy(result.data(), &header, sizeof(TypeHeader));
    
    return result;
}

EncryptedSize TypeSerializer::deserialize_size(const std::vector<uint8_t>& data,
                                              std::shared_ptr<BFVContext> context) {
    if (data.size() < sizeof(TypeHeader) + sizeof(int64_t)) {
        throw InvalidOperationError("insufficient data for EncryptedSize deserialization");
    }
    
    TypeHeader header;
    std::memcpy(&header, data.data(), sizeof(TypeHeader));
    
    if (!validate_header(header, TypeId::ENCRYPTED_SIZE)) {
        throw InvalidOperationError("invalid header for EncryptedSize deserialization");
    }
    
    int64_t value;
    std::memcpy(&value, data.data() + sizeof(TypeHeader), sizeof(int64_t));
    
    return EncryptedSize(context, static_cast<size_t>(value));
}

EncryptedAddress TypeSerializer::deserialize_address(const std::vector<uint8_t>& data,
                                                    std::shared_ptr<BFVContext> context) {
    if (data.size() < sizeof(TypeHeader) + sizeof(int64_t)) {
        throw InvalidOperationError("insufficient data for EncryptedAddress deserialization");
    }
    
    TypeHeader header;
    std::memcpy(&header, data.data(), sizeof(TypeHeader));
    
    if (!validate_header(header, TypeId::ENCRYPTED_ADDRESS)) {
        throw InvalidOperationError("invalid header for EncryptedAddress deserialization");
    }
    
    int64_t value;
    std::memcpy(&value, data.data() + sizeof(TypeHeader), sizeof(int64_t));
    
    return EncryptedAddress(context, static_cast<uintptr_t>(value));
}

EnhancedEncryptedBool TypeSerializer::deserialize_bool(const std::vector<uint8_t>& data,
                                                      std::shared_ptr<BFVContext> context) {
    if (data.size() < sizeof(TypeHeader) + sizeof(int64_t)) {
        throw InvalidOperationError("insufficient data for EnhancedEncryptedBool deserialization");
    }
    
    TypeHeader header;
    std::memcpy(&header, data.data(), sizeof(TypeHeader));
    
    if (!validate_header(header, TypeId::ENHANCED_ENCRYPTED_BOOL)) {
        throw InvalidOperationError("invalid header for EnhancedEncryptedBool deserialization");
    }
    
    int64_t state_value;
    std::memcpy(&state_value, data.data() + sizeof(TypeHeader), sizeof(int64_t));
    
    return EnhancedEncryptedBool(context, static_cast<TriState>(state_value));
}

template <typename T>
EncryptedPointer<T> TypeSerializer::deserialize_pointer(const std::vector<uint8_t>& data,
                                                        std::shared_ptr<BFVContext> context) {
    size_t expected_size = sizeof(TypeHeader) + sizeof(int64_t) + sizeof(size_t);
    if (data.size() < expected_size) {
        throw InvalidOperationError("insufficient data for EncryptedPointer deserialization");
    }
    
    TypeHeader header;
    std::memcpy(&header, data.data(), sizeof(TypeHeader));
    
    if (!validate_header(header, TypeId::ENCRYPTED_POINTER)) {
        throw InvalidOperationError("invalid header for EncryptedPointer deserialization");
    }
    
    int64_t address_value;
    size_t element_size;
    
    std::memcpy(&address_value, data.data() + sizeof(TypeHeader), sizeof(int64_t));
    std::memcpy(&element_size, data.data() + sizeof(TypeHeader) + sizeof(int64_t), sizeof(size_t));
    
    EncryptedAddress address(context, static_cast<uintptr_t>(address_value));
    return EncryptedPointer<T>(address, element_size);
}

}  // namespace serialization

// explicit template instantiations for common types
template class EncryptedPointer<int>;
template class EncryptedPointer<char>;
template class EncryptedPointer<uint8_t>;
template class EncryptedPointer<uint32_t>;
template class EncryptedPointer<uint64_t>;
template class EncryptedPointer<double>;
template class EncryptedPointer<float>;

template std::vector<uint8_t> serialization::TypeSerializer::serialize(const EncryptedPointer<int>& value);
template EncryptedPointer<int> serialization::TypeSerializer::deserialize_pointer(const std::vector<uint8_t>& data, std::shared_ptr<BFVContext> context);

}  // namespace cryptmalloc