#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>

namespace cryptmalloc {

enum class AllocationStrategy { STANDARD, ENCRYPTED, HYBRID };

class EncryptedAllocator {
  public:
    explicit EncryptedAllocator(AllocationStrategy strategy = AllocationStrategy::ENCRYPTED);

    virtual ~EncryptedAllocator() = default;

    virtual void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) = 0;

    virtual void deallocate(void* ptr, size_t size) noexcept = 0;

    virtual bool owns(void* ptr) const noexcept = 0;

    AllocationStrategy get_strategy() const noexcept {
        return strategy_;
    }

    virtual size_t total_allocated() const noexcept = 0;

    virtual size_t allocation_count() const noexcept = 0;

  protected:
    AllocationStrategy strategy_;
};

template <typename T>
class encrypted_allocator {
  public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = size_t;
    using difference_type = ptrdiff_t;

    template <typename U>
    struct rebind {
        using other = encrypted_allocator<U>;
    };

    explicit encrypted_allocator(std::shared_ptr<EncryptedAllocator> allocator)
        : allocator_(std::move(allocator)) {}

    template <typename U>
    encrypted_allocator(const encrypted_allocator<U>& other) : allocator_(other.allocator_) {}

    pointer allocate(size_type n) {
        return static_cast<pointer>(allocator_->allocate(n * sizeof(T), alignof(T)));
    }

    void deallocate(pointer p, size_type n) noexcept {
        allocator_->deallocate(p, n * sizeof(T));
    }

    template <typename... Args>
    void construct(pointer p, Args&&... args) {
        new (p) T(std::forward<Args>(args)...);
    }

    void destroy(pointer p) {
        p->~T();
    }

    template <typename U>
    bool operator==(const encrypted_allocator<U>& other) const noexcept {
        return allocator_ == other.allocator_;
    }

    template <typename U>
    bool operator!=(const encrypted_allocator<U>& other) const noexcept {
        return !(*this == other);
    }

  private:
    std::shared_ptr<EncryptedAllocator> allocator_;

    template <typename U>
    friend class encrypted_allocator;
};

std::shared_ptr<EncryptedAllocator> create_allocator(
    AllocationStrategy strategy = AllocationStrategy::ENCRYPTED);

}