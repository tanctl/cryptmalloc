/**
 * @file core.hpp
 * @brief core definitions and utilities for cryptmalloc
 */

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

namespace cryptmalloc {

/**
 * @brief version information for the cryptmalloc library
 */
struct Version {
    static constexpr int major = 1;
    static constexpr int minor = 0;
    static constexpr int patch = 0;

    static constexpr const char* string = "1.0.0";
};

/**
 * @brief encryption parameters and configuration
 */
struct EncryptionConfig {
    size_t security_level = 128;
    size_t ring_dimension = 16384;
    size_t plaintext_modulus = 65537;
};

/**
 * @brief result type for operations that may fail
 */
template <typename T>
class Result {
   public:
    Result(const T& value) : value_(value) {}
    Result(T&& value) : value_(std::move(value)) {}
    Result(const std::string& error) : error_(error) {}

    bool has_value() const noexcept {
        return value_.has_value();
    }
    const T& value() const {
        return value_.value();
    }
    const std::string& error() const {
        return error_;
    }

    explicit operator bool() const noexcept {
        return value_.has_value();
    }

   private:
    std::optional<T> value_;
    std::string error_;
};

/**
 * @brief specialization of Result for void type
 */
template<>
class Result<void> {
public:
    Result() : has_value_(true) {}
    Result(const std::string& error) : error_(error), has_value_(false) {}
    
    bool has_value() const noexcept { return has_value_; }
    const std::string& error() const { return error_; }
    explicit operator bool() const noexcept { return has_value_; }
    
    // helper method to create successful result
    static Result<void> success() { return Result<void>(); }
    
private:
    std::string error_;
    bool has_value_;
};

/**
 * @brief base class for encrypted memory operations
 */
class CryptmallocBase {
   public:
    virtual ~CryptmallocBase() = default;

    virtual Result<void*> allocate(size_t size) = 0;
    virtual Result<void> deallocate(void* ptr) = 0;
    virtual Result<size_t> get_encrypted_size(size_t plaintext_size) const = 0;
};

}  // namespace cryptmalloc