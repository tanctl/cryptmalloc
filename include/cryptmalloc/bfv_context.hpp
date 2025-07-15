#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "cryptmalloc/core.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

enum class SecurityLevel { SECURITY_128 = 128, SECURITY_192 = 192, SECURITY_256 = 256 };

enum class ParameterSet {
    FAST_OPERATIONS,   // optimized for speed
    MEMORY_EFFICIENT,  // optimized for memory usage
    HIGH_PRECISION,    // optimized for large integer operations
    BALANCED           // balanced performance/memory
};

struct BFVParameters {
    SecurityLevel security_level = SecurityLevel::SECURITY_128;
    ParameterSet parameter_set = ParameterSet::BALANCED;
    uint32_t polynomial_degree = 0;
    uint64_t plaintext_modulus = 0;
    uint32_t multiplicative_depth = 2;
    uint32_t rotation_indices = 0;
    bool enable_relinearization = true;
    bool enable_rotation = false;

    static BFVParameters for_security_level(SecurityLevel level);
    static BFVParameters for_allocator_use_case();
    bool validate() const;
};

class SecureMemory {
  public:
    static void* allocate_secure(size_t size);
    static void deallocate_secure(void* ptr, size_t size);
    static void secure_zero(void* ptr, size_t size);

    template <typename T>
    class secure_allocator {
      public:
        using value_type = T;
        T* allocate(size_t n) {
            return static_cast<T*>(allocate_secure(n * sizeof(T)));
        }
        void deallocate(T* p, size_t n) {
            deallocate_secure(p, n * sizeof(T));
        }
        template <typename U>
        bool operator==(const secure_allocator<U>&) const {
            return true;
        }
        template <typename U>
        bool operator!=(const secure_allocator<U>&) const {
            return false;
        }
    };
};

class BFVContext {
  public:
    explicit BFVContext(const BFVParameters& params);
    ~BFVContext();

    BFVContext(const BFVContext&) = delete;
    BFVContext& operator=(const BFVContext&) = delete;
    BFVContext(BFVContext&&) noexcept;
    BFVContext& operator=(BFVContext&&) noexcept;

    bool is_initialized() const {
        return initialized_.load();
    }
    bool is_key_generated() const {
        return keys_generated_.load();
    }
    const BFVParameters& get_parameters() const {
        return params_;
    }

    void generate_keys();
    void generate_relinearization_keys();
    void generate_rotation_keys(const std::vector<int32_t>& indices = {});
    void clear_keys();

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> encrypt(int64_t value) const;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> encrypt(const std::vector<int64_t>& values) const;
    int64_t decrypt_single(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const;
    std::vector<int64_t> decrypt_batch(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> add(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> multiply(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> rotate(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, int32_t index) const;

    bool serialize_context(const std::string& filepath) const;
    bool deserialize_context(const std::string& filepath);
    bool serialize_keys(const std::string& filepath) const;
    bool deserialize_keys(const std::string& filepath);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> get_crypto_context() const;

    struct PerformanceMetrics {
        double key_generation_time_ms = 0.0;
        double context_creation_time_ms = 0.0;
        size_t memory_usage_bytes = 0;
        uint32_t effective_polynomial_degree = 0;
        uint64_t effective_plaintext_modulus = 0;
    };

    PerformanceMetrics get_performance_metrics() const {
        return metrics_;
    }

  private:
    BFVParameters params_;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> crypto_context_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key_pair_;

    mutable std::mutex context_mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> keys_generated_{false};
    PerformanceMetrics metrics_;

    void initialize_context();
    void validate_parameters() const;
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> create_cc_params() const;
    void secure_cleanup();

    uint32_t calculate_optimal_polynomial_degree() const;
    uint64_t calculate_optimal_plaintext_modulus() const;
    uint32_t calculate_multiplicative_depth() const;
};

std::string security_level_to_string(SecurityLevel level);
std::string parameter_set_to_string(ParameterSet set);
BFVParameters get_recommended_parameters(SecurityLevel security, ParameterSet param_set);

class CiphertextPool {
  public:
    static CiphertextPool& instance();

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> acquire();
    void release(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>&& ct);
    void clear();

    size_t pool_size() const {
        return pool_size_.load();
    }
    size_t active_count() const {
        return active_count_.load();
    }

  private:
    CiphertextPool() = default;
    ~CiphertextPool() = default;

    mutable std::mutex pool_mutex_;
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> pool_;
    std::atomic<size_t> pool_size_{0};
    std::atomic<size_t> active_count_{0};
};

}