/**
 * @file allocator.hpp
 * @brief encrypted memory allocator interface and implementation
 */

#pragma once

#include <memory>
#include <mutex>
#include <unordered_map>

#include "cryptmalloc/core.hpp"
#include "cryptmalloc/openfhe_context.hpp"

namespace cryptmalloc {

/**
 * @brief metadata for encrypted memory blocks
 */
struct EncryptedBlock {
    size_t original_size;
    size_t encrypted_size;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext;
};

/**
 * @brief encrypted memory allocator using OpenFHE
 */
class EncryptedAllocator : public CryptmallocBase {
   public:
    /**
     * @brief construct allocator with encryption context
     */
    explicit EncryptedAllocator(std::shared_ptr<OpenFHEContext> context);

    /**
     * @brief allocate encrypted memory block
     * @param size size in bytes to allocate
     * @return pointer to encrypted memory or error
     */
    Result<void*> allocate(size_t size) override;

    /**
     * @brief deallocate encrypted memory block
     * @param ptr pointer to encrypted memory
     * @return success or error result
     */
    Result<void> deallocate(void* ptr) override;

    /**
     * @brief get encrypted size for given plaintext size
     * @param plaintext_size size of plaintext data
     * @return encrypted size or error
     */
    Result<size_t> get_encrypted_size(size_t plaintext_size) const override;

    /**
     * @brief write data to encrypted memory block
     * @param ptr pointer to encrypted memory
     * @param data data to write
     * @param size size of data
     * @return success or error result
     */
    Result<void> write(void* ptr, const void* data, size_t size);

    /**
     * @brief read data from encrypted memory block
     * @param ptr pointer to encrypted memory
     * @param data buffer for decrypted data
     * @param size size to read
     * @return bytes read or error
     */
    Result<size_t> read(void* ptr, void* data, size_t size);

    /**
     * @brief get statistics about allocated blocks
     */
    struct Statistics {
        size_t total_blocks;
        size_t total_plaintext_size;
        size_t total_encrypted_size;
    };

    Statistics get_statistics() const;

   private:
    std::shared_ptr<OpenFHEContext> context_;
    std::unordered_map<void*, std::unique_ptr<EncryptedBlock>> blocks_;
    mutable std::mutex mutex_;

    void* allocate_raw(size_t size);
    void deallocate_raw(void* ptr);
};

/**
 * @brief STL-compatible allocator for encrypted containers
 */
template <typename T>
class StlEncryptedAllocator {
   public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    template <typename U>
    struct rebind {
        using other = StlEncryptedAllocator<U>;
    };

    explicit StlEncryptedAllocator(std::shared_ptr<EncryptedAllocator> allocator)
        : allocator_(allocator) {}

    template <typename U>
    StlEncryptedAllocator(const StlEncryptedAllocator<U>& other) : allocator_(other.allocator_) {}

    pointer allocate(size_type n) {
        auto result = allocator_->allocate(n * sizeof(T));
        if(!result) {
            throw std::bad_alloc();
        }
        return static_cast<pointer>(result.value());
    }

    void deallocate(pointer p, size_type) {
        allocator_->deallocate(p);
    }

    template <typename U>
    bool operator==(const StlEncryptedAllocator<U>& other) const {
        return allocator_ == other.allocator_;
    }

    template <typename U>
    bool operator!=(const StlEncryptedAllocator<U>& other) const {
        return !(*this == other);
    }

   private:
    std::shared_ptr<EncryptedAllocator> allocator_;

    template <typename U>
    friend class StlEncryptedAllocator;
};

}  // namespace cryptmalloc