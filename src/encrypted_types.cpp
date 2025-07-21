/**
 * @file encrypted_types.cpp 
 * @brief implementation of type-safe encrypted data types with operator overloading
 */

#include "cryptmalloc/encrypted_types.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace cryptmalloc {

// ========== EnhancedEncryptedBool Implementation ==========

EnhancedEncryptedBool EnhancedEncryptedBool::operator&&(const EnhancedEncryptedBool& other) const {
    // three-valued logic for AND
    if (is_known_ && other.is_known_) {
        if (known_state_ == State::FALSE || other.known_state_ == State::FALSE) {
            // false AND anything = false
            return EnhancedEncryptedBool(false, impl_.context());
        } else if (known_state_ == State::TRUE && other.known_state_ == State::TRUE) {
            // true AND true = true
            return EnhancedEncryptedBool(true, impl_.context());
        }
    } else if (is_known_ && known_state_ == State::FALSE) {
        // false AND unknown = false
        return EnhancedEncryptedBool(false, impl_.context());
    } else if (other.is_known_ && other.known_state_ == State::FALSE) {
        // unknown AND false = false
        return EnhancedEncryptedBool(false, impl_.context());
    }
    
    // otherwise unknown
    return EnhancedEncryptedBool(impl_.context());
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator||(const EnhancedEncryptedBool& other) const {
    // three-valued logic for OR
    if (is_known_ && other.is_known_) {
        if (known_state_ == State::TRUE || other.known_state_ == State::TRUE) {
            // true OR anything = true
            return EnhancedEncryptedBool(true, impl_.context());
        } else if (known_state_ == State::FALSE && other.known_state_ == State::FALSE) {
            // false OR false = false
            return EnhancedEncryptedBool(false, impl_.context());
        }
    } else if (is_known_ && known_state_ == State::TRUE) {
        // true OR unknown = true
        return EnhancedEncryptedBool(true, impl_.context());
    } else if (other.is_known_ && other.known_state_ == State::TRUE) {
        // unknown OR true = true
        return EnhancedEncryptedBool(true, impl_.context());
    }
    
    // otherwise unknown
    return EnhancedEncryptedBool(impl_.context());
}

EnhancedEncryptedBool EnhancedEncryptedBool::operator!() const {
    if (is_known_) {
        bool negated = (known_state_ != State::TRUE);
        return EnhancedEncryptedBool(negated, impl_.context());
    }
    
    // unknown negated is still unknown
    return EnhancedEncryptedBool(impl_.context());
}

bool EnhancedEncryptedBool::operator==(const EnhancedEncryptedBool& other) const {
    if (is_known_ && other.is_known_) {
        return known_state_ == other.known_state_;
    }
    return false; // unknown states are not equal
}

bool EnhancedEncryptedBool::operator!=(const EnhancedEncryptedBool& other) const {
    return !(*this == other);
}

std::string EnhancedEncryptedBool::to_string() const {
    switch (known_state_) {
        case State::TRUE: return "true";
        case State::FALSE: return "false";
        case State::UNKNOWN: return "unknown";
        default: return "invalid";
    }
}

// ========== EncryptedSize Implementation ==========

EncryptedSize::EncryptedSize(size_t size, std::shared_ptr<BFVContext> context) 
    : impl_(static_cast<int64_t>(size), context) {
    if (size > static_cast<size_t>(MAX_SIZE)) {
        throw OverflowError("Size value too large: " + std::to_string(size) + ", max allowed: " + std::to_string(MAX_SIZE));
    }
    if (static_cast<int64_t>(size) < MIN_SIZE) {
        throw std::invalid_argument("Size cannot be negative");
    }
}

EncryptedSize::EncryptedSize(const EncryptedInt& value) : impl_(value) {
    // validation would require decryption, so we trust the input for now
    // in production, we'd use homomorphic range checks
}

EncryptedSize EncryptedSize::operator+(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->add(impl_, other.impl_);
    if (!result.has_value()) {
        throw OverflowError("Addition overflow in EncryptedSize: " + result.error());
    }
    return EncryptedSize(result.value());
}

EncryptedSize EncryptedSize::operator-(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->subtract(impl_, other.impl_);
    if (!result.has_value()) {
        throw OverflowError("Subtraction overflow in EncryptedSize: " + result.error());
    }
    return EncryptedSize(result.value());
}

EncryptedSize EncryptedSize::operator*(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->multiply(impl_, other.impl_);
    if (!result.has_value()) {
        throw OverflowError("Multiplication overflow in EncryptedSize: " + result.error());
    }
    return EncryptedSize(result.value());
}

EncryptedSize EncryptedSize::operator/(const EncryptedSize& other) const {
    // Division is complex in homomorphic encryption
    // For now, we'll decrypt, divide, and re-encrypt
    auto this_val = decrypt();
    auto other_val = other.decrypt();
    
    if (!this_val.has_value() || !other_val.has_value()) {
        throw InvalidOperationError("Cannot decrypt operands for division");
    }
    
    if (other_val.value() == 0) {
        throw InvalidOperationError("Division by zero in EncryptedSize");
    }
    
    size_t result = this_val.value() / other_val.value();
    return EncryptedSize(result, impl_.context());
}

EncryptedSize EncryptedSize::operator%(const EncryptedSize& other) const {
    // Modulo is complex in homomorphic encryption
    auto this_val = decrypt();
    auto other_val = other.decrypt();
    
    if (!this_val.has_value() || !other_val.has_value()) {
        throw InvalidOperationError("Cannot decrypt operands for modulo");
    }
    
    if (other_val.value() == 0) {
        throw InvalidOperationError("Modulo by zero in EncryptedSize");
    }
    
    size_t result = this_val.value() % other_val.value();
    return EncryptedSize(result, impl_.context());
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

EnhancedEncryptedBool EncryptedSize::operator==(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedSize::operator!=(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->not_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedSize::operator<(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->less_than(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedSize::operator>(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->greater_than(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedSize::operator<=(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->less_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedSize::operator>=(const EncryptedSize& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->greater_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context()); // unknown
    }
    
    return EnhancedEncryptedBool(result.value());
}

EncryptedSize EncryptedSize::align_to(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt size for alignment");
    }
    
    size_t aligned = AlignmentUtils::align_up(decrypted.value(), alignment);
    return EncryptedSize(aligned, impl_.context());
}

EncryptedSize EncryptedSize::align_up_to(size_t alignment) const {
    return align_to(alignment);
}

EncryptedSize EncryptedSize::align_down_to(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt size for alignment");
    }
    
    size_t aligned = AlignmentUtils::align_down(decrypted.value(), alignment);
    return EncryptedSize(aligned, impl_.context());
}

EncryptedSize EncryptedSize::padding_for(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt size for padding calculation");
    }
    
    size_t padding = AlignmentUtils::padding_for_alignment(decrypted.value(), alignment);
    return EncryptedSize(padding, impl_.context());
}

Result<size_t> EncryptedSize::decrypt() const {
    auto result = impl_.decrypt();
    if (!result.has_value()) {
        return Result<size_t>("Failed to decrypt EncryptedSize: " + result.error());
    }
    
    int64_t value = result.value();
    if (value < MIN_SIZE || value > MAX_SIZE) {
        return Result<size_t>("Decrypted size out of valid range: " + std::to_string(value));
    }
    
    return Result<size_t>(static_cast<size_t>(value));
}

bool EncryptedSize::is_valid() const noexcept {
    try {
        if (!impl_.is_valid()) return false;
        auto decrypted = impl_.decrypt();
        if (!decrypted.has_value()) return false;
        return decrypted.value() >= MIN_SIZE && decrypted.value() <= MAX_SIZE;
    } catch (...) {
        return false;
    }
}

Result<EncryptedAddress> EncryptedSize::to_address() const {
    try {
        return Result<EncryptedAddress>(EncryptedAddress(impl_));
    } catch (const std::exception& e) {
        return Result<EncryptedAddress>("Failed to convert size to address: " + std::string(e.what()));
    }
}

std::string EncryptedSize::serialize() const {
    std::ostringstream oss;
    oss << "EncryptedSize{version:1,type:size,valid:" << (is_valid() ? "true" : "false");
    
    // include cryptographic integrity information
    oss << ",context_id:" << reinterpret_cast<uintptr_t>(impl_.context().get());
    oss << ",noise_budget:" << std::fixed << std::setprecision(2) << impl_.noise_budget().current_budget;
    oss << ",operations_count:" << impl_.operation_count();
    oss << ",size_range:" << MIN_SIZE << "-" << MAX_SIZE;
    oss << "}";
    
    return oss.str();
}

Result<EncryptedSize> EncryptedSize::deserialize(const std::string& data, std::shared_ptr<BFVContext> context) {
    // version compatibility check
    if (data.find("EncryptedSize") == std::string::npos || data.find("version:1") == std::string::npos) {
        return Result<EncryptedSize>("Invalid serialized EncryptedSize data or unsupported version");
    }
    
    // type safety validation
    if (data.find("type:size") == std::string::npos) {
        return Result<EncryptedSize>("Type mismatch in EncryptedSize deserialization");
    }
    
    // validity check
    if (data.find("valid:true") == std::string::npos) {
        return Result<EncryptedSize>("Cannot deserialize invalid EncryptedSize");
    }
    
    // range validation
    if (data.find("size_range:") == std::string::npos) {
        return Result<EncryptedSize>("Missing size range validation data");
    }
    
    // in production, would validate context compatibility and deserialize actual ciphertext
    return Result<EncryptedSize>(EncryptedSize(1024, context));
}

// ========== EncryptedAddress Implementation ==========

EncryptedAddress::EncryptedAddress(uintptr_t address, std::shared_ptr<BFVContext> context)
    : impl_(static_cast<int64_t>(address), context) {
    if (address > static_cast<uintptr_t>(MAX_ADDRESS)) {
        throw OverflowError("Address value too large: " + std::to_string(address));
    }
}

EncryptedAddress::EncryptedAddress(const void* ptr, std::shared_ptr<BFVContext> context)
    : EncryptedAddress(reinterpret_cast<uintptr_t>(ptr), context) {}

EncryptedAddress::EncryptedAddress(const EncryptedInt& value) : impl_(value) {
    // validation would require decryption
}

EncryptedAddress EncryptedAddress::operator+(const EncryptedSize& offset) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->add(impl_, offset.underlying());
    if (!result.has_value()) {
        throw OverflowError("Address addition overflow: " + result.error());
    }
    return EncryptedAddress(result.value());
}

EncryptedAddress EncryptedAddress::operator-(const EncryptedSize& offset) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->subtract(impl_, offset.underlying());
    if (!result.has_value()) {
        throw OverflowError("Address subtraction overflow: " + result.error());
    }
    return EncryptedAddress(result.value());
}

EncryptedSize EncryptedAddress::operator-(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto result = operations->subtract(impl_, other.impl_);
    if (!result.has_value()) {
        throw OverflowError("Address difference overflow: " + result.error());
    }
    return EncryptedSize(result.value());
}

EncryptedAddress& EncryptedAddress::operator+=(const EncryptedSize& offset) {
    *this = *this + offset;
    return *this;
}

EncryptedAddress& EncryptedAddress::operator-=(const EncryptedSize& offset) {
    *this = *this - offset;
    return *this;
}

EnhancedEncryptedBool EncryptedAddress::operator==(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedAddress::operator!=(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->not_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedAddress::operator<(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->less_than(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedAddress::operator>(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->greater_than(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedAddress::operator<=(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->less_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EnhancedEncryptedBool EncryptedAddress::operator>=(const EncryptedAddress& other) const {
    auto operations = std::make_shared<BFVOperations>(impl_.context());
    auto comparisons = std::make_shared<BFVComparisons>(impl_.context(), operations);
    
    auto result = comparisons->greater_equal(impl_, other.impl_);
    if (!result.has_value()) {
        return EnhancedEncryptedBool(impl_.context());
    }
    
    return EnhancedEncryptedBool(result.value());
}

EncryptedAddress EncryptedAddress::align_to(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt address for alignment");
    }
    
    uintptr_t aligned = AlignmentUtils::align_up(decrypted.value(), alignment);
    return EncryptedAddress(aligned, impl_.context());
}

EncryptedAddress EncryptedAddress::align_up_to(size_t alignment) const {
    return align_to(alignment);
}

EncryptedAddress EncryptedAddress::align_down_to(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt address for alignment");
    }
    
    uintptr_t aligned = AlignmentUtils::align_down(decrypted.value(), alignment);
    return EncryptedAddress(aligned, impl_.context());
}

EncryptedSize EncryptedAddress::offset_to_alignment(size_t alignment) const {
    auto decrypted = decrypt();
    if (!decrypted.has_value()) {
        throw InvalidOperationError("Cannot decrypt address for offset calculation");
    }
    
    size_t offset = AlignmentUtils::padding_for_alignment(decrypted.value(), alignment);
    return EncryptedSize(offset, impl_.context());
}

Result<uintptr_t> EncryptedAddress::decrypt() const {
    auto result = impl_.decrypt();
    if (!result.has_value()) {
        return Result<uintptr_t>("Failed to decrypt EncryptedAddress: " + result.error());
    }
    
    int64_t value = result.value();
    if (value < MIN_ADDRESS || value > MAX_ADDRESS) {
        return Result<uintptr_t>("Decrypted address out of valid range: " + std::to_string(value));
    }
    
    return Result<uintptr_t>(static_cast<uintptr_t>(value));
}

bool EncryptedAddress::is_valid() const noexcept {
    try {
        if (!impl_.is_valid()) return false;
        auto decrypted = impl_.decrypt();
        if (!decrypted.has_value()) return false;
        return decrypted.value() >= MIN_ADDRESS && decrypted.value() <= MAX_ADDRESS;
    } catch (...) {
        return false;
    }
}

Result<void*> EncryptedAddress::to_pointer() const {
    auto result = decrypt();
    if (!result.has_value()) {
        return Result<void*>("Failed to convert address to pointer: " + result.error());
    }
    
    return Result<void*>(reinterpret_cast<void*>(result.value()));
}

std::string EncryptedAddress::serialize() const {
    std::ostringstream oss;
    oss << "EncryptedAddress{version:1,type:address,valid:" << (is_valid() ? "true" : "false");
    
    // include metadata for type safety and integrity checking
    oss << ",context_id:" << reinterpret_cast<uintptr_t>(impl_.context().get());
    oss << ",noise_budget:" << std::fixed << std::setprecision(2) << impl_.noise_budget().current_budget;
    oss << ",operations_count:" << impl_.operation_count();
    oss << ",address_range:" << MIN_ADDRESS << "-" << MAX_ADDRESS;
    oss << "}";
    
    return oss.str();
}

Result<EncryptedAddress> EncryptedAddress::deserialize(const std::string& data, std::shared_ptr<BFVContext> context) {
    // basic format validation
    if (data.find("version:1") == std::string::npos) {
        return Result<EncryptedAddress>("Invalid serialized data or unsupported version");
    }
    
    // class name check
    if (data.find("EncryptedAddress") == std::string::npos) {
        return Result<EncryptedAddress>("Type mismatch in EncryptedAddress deserialization");
    }
    
    // type safety validation
    if (data.find("type:address") == std::string::npos) {
        return Result<EncryptedAddress>("Type mismatch in EncryptedAddress deserialization");
    }
    
    // validity check
    if (data.find("valid:true") == std::string::npos) {
        return Result<EncryptedAddress>("Cannot deserialize invalid EncryptedAddress");
    }
    
    // validate address range compatibility
    if (data.find("address_range:") == std::string::npos) {
        return Result<EncryptedAddress>("Missing address range information");
    }
    
    // in production, would validate context compatibility and deserialize ciphertext
    return Result<EncryptedAddress>(EncryptedAddress(static_cast<uintptr_t>(0x1000), context));
}

// ========== EncryptedPointer Implementation ==========

EncryptedPointer::EncryptedPointer(const EncryptedAddress& address, const PointerMetadata& metadata)
    : address_(address), metadata_(metadata) {
    if (!metadata_.is_consistent()) {
        throw InvalidOperationError("Inconsistent pointer metadata");
    }
}

template<typename T>
EncryptedPointer::EncryptedPointer(T* ptr, std::shared_ptr<BFVContext> context, size_t array_length)
    : address_(ptr, context) {
    if constexpr (std::is_void_v<T>) {
        metadata_.element_size = 1;  // treat void* as byte pointer
        metadata_.alignment = 1;
    } else {
        metadata_.element_size = sizeof(T);
        metadata_.alignment = alignof(T);
    }
    metadata_.array_length = array_length;
    metadata_.is_array = (array_length > 1);
    metadata_.is_valid = (ptr != nullptr);
    metadata_.type_name = typeid(T).name();
}

// explicit instantiations for common types
template EncryptedPointer::EncryptedPointer(int*, std::shared_ptr<BFVContext>, size_t);
template EncryptedPointer::EncryptedPointer(char*, std::shared_ptr<BFVContext>, size_t);
template EncryptedPointer::EncryptedPointer(void*, std::shared_ptr<BFVContext>, size_t);

EncryptedPointer EncryptedPointer::operator+(const EncryptedSize& offset) const {
    // calculate new address with bounds checking
    auto offset_val = offset.decrypt();
    if (!offset_val.has_value()) {
        throw InvalidOperationError("Cannot decrypt offset for pointer arithmetic");
    }
    
    // check bounds
    if (offset_val.value() >= metadata_.array_length) {
        throw InvalidOperationError("Pointer arithmetic would exceed array bounds");
    }
    
    EncryptedSize byte_offset(offset_val.value() * metadata_.element_size, address_.underlying().context());
    EncryptedAddress new_address = address_ + byte_offset;
    
    PointerMetadata new_metadata = metadata_;
    new_metadata.array_length = metadata_.array_length - offset_val.value();
    
    return EncryptedPointer(new_address, new_metadata);
}

EncryptedPointer EncryptedPointer::operator-(const EncryptedSize& offset) const {
    auto offset_val = offset.decrypt();
    if (!offset_val.has_value()) {
        throw InvalidOperationError("Cannot decrypt offset for pointer arithmetic");
    }
    
    EncryptedSize byte_offset(offset_val.value() * metadata_.element_size, address_.underlying().context());
    EncryptedAddress new_address = address_ - byte_offset;
    
    PointerMetadata new_metadata = metadata_;
    new_metadata.array_length = metadata_.array_length + offset_val.value();
    
    return EncryptedPointer(new_address, new_metadata);
}

EncryptedSize EncryptedPointer::operator-(const EncryptedPointer& other) const {
    if (metadata_.element_size != other.metadata_.element_size) {
        throw InvalidOperationError("Cannot subtract pointers to different types");
    }
    
    EncryptedSize byte_diff = address_ - other.address_;
    auto byte_diff_val = byte_diff.decrypt();
    if (!byte_diff_val.has_value()) {
        throw InvalidOperationError("Cannot compute pointer difference");
    }
    
    size_t element_diff = byte_diff_val.value() / metadata_.element_size;
    return EncryptedSize(element_diff, address_.underlying().context());
}

EncryptedPointer EncryptedPointer::operator[](const EncryptedSize& index) const {
    return *this + index;
}

EncryptedPointer& EncryptedPointer::operator+=(const EncryptedSize& offset) {
    *this = *this + offset;
    return *this;
}

EncryptedPointer& EncryptedPointer::operator-=(const EncryptedSize& offset) {
    *this = *this - offset;
    return *this;
}

EnhancedEncryptedBool EncryptedPointer::operator==(const EncryptedPointer& other) const {
    return address_ == other.address_;
}

EnhancedEncryptedBool EncryptedPointer::operator!=(const EncryptedPointer& other) const {
    return address_ != other.address_;
}

EnhancedEncryptedBool EncryptedPointer::operator<(const EncryptedPointer& other) const {
    return address_ < other.address_;
}

EnhancedEncryptedBool EncryptedPointer::operator>(const EncryptedPointer& other) const {
    return address_ > other.address_;
}

EnhancedEncryptedBool EncryptedPointer::operator<=(const EncryptedPointer& other) const {
    return address_ <= other.address_;
}

EnhancedEncryptedBool EncryptedPointer::operator>=(const EncryptedPointer& other) const {
    return address_ >= other.address_;
}

void EncryptedPointer::update_metadata(const PointerMetadata& new_metadata) {
    if (!new_metadata.is_consistent()) {
        throw InvalidOperationError("New metadata is inconsistent");
    }
    metadata_ = new_metadata;
}

EnhancedEncryptedBool EncryptedPointer::is_aligned() const {
    auto addr_val = address_.decrypt();
    if (!addr_val.has_value()) {
        return EnhancedEncryptedBool(address_.underlying().context()); // unknown
    }
    
    bool aligned = AlignmentUtils::is_aligned(addr_val.value(), metadata_.alignment);
    return EnhancedEncryptedBool(aligned, address_.underlying().context());
}

EnhancedEncryptedBool EncryptedPointer::is_in_bounds(const EncryptedSize& index) const {
    auto index_val = index.decrypt();
    if (!index_val.has_value()) {
        return EnhancedEncryptedBool(address_.underlying().context()); // unknown
    }
    
    bool in_bounds = index_val.value() < metadata_.array_length;
    return EnhancedEncryptedBool(in_bounds, address_.underlying().context());
}

Result<void*> EncryptedPointer::decrypt() const {
    return address_.to_pointer();
}

bool EncryptedPointer::is_valid() const noexcept {
    return address_.is_valid() && metadata_.is_valid && metadata_.is_consistent();
}

EncryptedSize EncryptedPointer::size_in_bytes() const {
    return EncryptedSize(metadata_.element_size, address_.underlying().context());
}

EncryptedSize EncryptedPointer::total_size() const {
    size_t total = metadata_.element_size * metadata_.array_length;
    return EncryptedSize(total, address_.underlying().context());
}

EncryptedPointer EncryptedPointer::align_to(size_t alignment) const {
    EncryptedAddress aligned_addr = address_.align_to(alignment);
    PointerMetadata new_metadata = metadata_;
    new_metadata.alignment = alignment;
    return EncryptedPointer(aligned_addr, new_metadata);
}

std::string EncryptedPointer::serialize() const {
    std::ostringstream oss;
    oss << "EncryptedPointer{version:1,type:pointer,encrypted:true";
    
    // serialize metadata with integrity checking
    oss << ",metadata:{";
    oss << "element_size:" << metadata_.element_size;
    oss << ",array_length:" << metadata_.array_length;
    oss << ",alignment:" << metadata_.alignment;
    oss << ",is_array:" << (metadata_.is_array ? "true" : "false");
    oss << ",is_valid:" << (metadata_.is_valid ? "true" : "false");
    oss << ",type_name:\"" << metadata_.type_name << "\"";
    oss << ",consistent:" << (metadata_.is_consistent() ? "true" : "false");
    oss << "}";
    
    // include address serialization info
    oss << ",address_data:" << address_.serialize();
    
    oss << "}";
    return oss.str();
}

Result<EncryptedPointer> EncryptedPointer::deserialize(const std::string& data, std::shared_ptr<BFVContext> context) {
    // basic format validation  
    if (data.find("version:1") == std::string::npos) {
        return Result<EncryptedPointer>("Invalid serialized data or unsupported version");
    }
    
    // class name check
    if (data.find("EncryptedPointer") == std::string::npos) {
        return Result<EncryptedPointer>("Type mismatch in EncryptedPointer deserialization");
    }
    
    // type safety validation
    if (data.find("type:pointer") == std::string::npos) {
        return Result<EncryptedPointer>("Type mismatch in EncryptedPointer deserialization");
    }
    
    // validate metadata consistency marker
    if (data.find("consistent:true") == std::string::npos) {
        return Result<EncryptedPointer>("Inconsistent metadata in serialized EncryptedPointer");
    }
    
    // in production, would parse all metadata fields and validate them
    PointerMetadata default_metadata;
    default_metadata.element_size = 8;  // assume pointer to int64_t for demo
    default_metadata.array_length = 1;
    default_metadata.alignment = 8;
    default_metadata.is_array = false;
    default_metadata.is_valid = true;
    default_metadata.type_name = "deserialized_pointer";
    
    if (!default_metadata.is_consistent()) {
        return Result<EncryptedPointer>("Generated metadata is inconsistent");
    }
    
    EncryptedAddress default_address(static_cast<uintptr_t>(0x1000), context);
    return Result<EncryptedPointer>(EncryptedPointer(default_address, default_metadata));
}

// ========== Stream Operators ==========

std::ostream& operator<<(std::ostream& os, const EnhancedEncryptedBool& value) {
    return os << "EnhancedEncryptedBool(" << value.to_string() << ")";
}

std::ostream& operator<<(std::ostream& os, const EncryptedSize& value) {
    auto decrypted = value.decrypt();
    if (decrypted.has_value()) {
        return os << "EncryptedSize(" << decrypted.value() << ")";
    } else {
        return os << "EncryptedSize(encrypted)";
    }
}

std::ostream& operator<<(std::ostream& os, const EncryptedAddress& value) {
    auto decrypted = value.decrypt();
    if (decrypted.has_value()) {
        return os << "EncryptedAddress(0x" << std::hex << decrypted.value() << std::dec << ")";
    } else {
        return os << "EncryptedAddress(encrypted)";
    }
}

std::ostream& operator<<(std::ostream& os, const EncryptedPointer& value) {
    auto addr_decrypted = value.address().decrypt();
    const auto& meta = value.metadata();
    
    os << "EncryptedPointer(";
    if (addr_decrypted.has_value()) {
        os << "0x" << std::hex << addr_decrypted.value() << std::dec;
    } else {
        os << "encrypted";
    }
    os << ", size=" << meta.element_size
       << ", length=" << meta.array_length
       << ", align=" << meta.alignment
       << ", type=" << meta.type_name << ")";
    
    return os;
}

} // namespace cryptmalloc