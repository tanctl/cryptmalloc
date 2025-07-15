/**
 * @file bfv_context.hpp
 * @brief robust BFV encryption context with secure key management for integer operations
 */

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cryptmalloc/core.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

/**
 * @brief security levels for BFV parameter selection
 */
enum class SecurityLevel {
    HEStd_128_classic = 128,  ///< 128-bit classical security
    HEStd_192_classic = 192,  ///< 192-bit classical security
    HEStd_256_classic = 256   ///< 256-bit classical security
};

/**
 * @brief BFV scheme parameters optimized for integer operations
 */
struct BFVParameters {
    SecurityLevel security_level = SecurityLevel::HEStd_128_classic;
    uint32_t ring_dimension = 16384;     ///< polynomial modulus degree
    uint64_t plaintext_modulus = 65537;  ///< plaintext modulus (prime)
    uint32_t multiplicative_depth = 3;   ///< maximum multiplication depth
    uint32_t batch_size = 8192;          ///< SIMD batch size
    double standard_deviation = 3.2;     ///< error distribution parameter
    lbcrypto::ScalingTechnique scaling_tech = lbcrypto::FLEXIBLEAUTO;  ///< scaling technique
    bool enable_relinearization = true;     ///< enable relinearization keys
    bool enable_rotation = false;           ///< enable rotation keys
    std::vector<int32_t> rotation_indices;  ///< rotation indices to precompute

    /**
     * @brief validate parameter consistency
     * @return true if parameters are valid
     */
    bool validate() const;

    /**
     * @brief get recommended parameters for security level
     * @param level desired security level
     * @param int_range maximum integer range required
     * @param mult_depth required multiplicative depth
     * @return optimized parameters
     */
    static BFVParameters recommended(SecurityLevel level, uint64_t int_range = 1000000,
                                     uint32_t mult_depth = 3);
};

/**
 * @brief secure key bundle with explicit memory cleanup
 */
class SecureKeyBundle {
   public:
    using CryptoContextBFV = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
    using PublicKey = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
    using PrivateKey = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
    using EvalKey = lbcrypto::EvalKey<lbcrypto::DCRTPoly>;

    SecureKeyBundle() = default;
    ~SecureKeyBundle();

    // non-copyable for security
    SecureKeyBundle(const SecureKeyBundle&) = delete;
    SecureKeyBundle& operator=(const SecureKeyBundle&) = delete;

    // movable
    SecureKeyBundle(SecureKeyBundle&& other) noexcept;
    SecureKeyBundle& operator=(SecureKeyBundle&& other) noexcept;

    /**
     * @brief generate all keys for given context and parameters
     * @param context OpenFHE crypto context
     * @param params BFV parameters
     * @return result indicating success or failure
     */
    Result<void> generate_keys(const CryptoContextBFV& context, const BFVParameters& params);

    /**
     * @brief serialize keys to encrypted binary format
     * @param password password for key encryption
     * @return serialized key data or error
     */
    Result<std::vector<uint8_t>> serialize(const std::string& password) const;

    /**
     * @brief deserialize keys from encrypted binary format
     * @param data serialized key data
     * @param password password for key decryption
     * @param context target crypto context
     * @return result indicating success or failure
     */
    Result<void> deserialize(const std::vector<uint8_t>& data, const std::string& password,
                             const CryptoContextBFV& context);

    /**
     * @brief check if all required keys are available
     */
    bool is_complete() const noexcept;

    /**
     * @brief get public key
     */
    const PublicKey& public_key() const {
        return public_key_;
    }

    /**
     * @brief get private key
     */
    const PrivateKey& private_key() const {
        return private_key_;
    }

    /**
     * @brief check if relinearization keys are available
     * Note: Eval keys are managed internally by the crypto context
     */
    bool has_relin_keys() const noexcept {
        return keys_generated_;  // Generated with context if enabled
    }

    /**
     * @brief check if rotation keys are available  
     * Note: Eval keys are managed internally by the crypto context
     */
    bool has_rotation_keys() const noexcept {
        return keys_generated_;  // Generated with context if enabled
    }

    /**
     * @brief explicitly clear all keys from memory
     */
    void secure_clear();

   private:
    PublicKey public_key_;
    PrivateKey private_key_;

    std::atomic<bool> keys_generated_{false};
    mutable std::mutex keys_mutex_;

    void secure_zero_memory(void* ptr, size_t size);
};

/**
 * @brief thread-safe BFV context with secure key management
 */
class BFVContext {
   public:
    using CryptoContextBFV = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
    using Plaintext = lbcrypto::Plaintext;
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    /**
     * @brief construct BFV context with parameters
     * @param params BFV scheme parameters
     */
    explicit BFVContext(const BFVParameters& params = BFVParameters{});

    /**
     * @brief destructor with secure cleanup
     */
    ~BFVContext();

    // non-copyable for security
    BFVContext(const BFVContext&) = delete;
    BFVContext& operator=(const BFVContext&) = delete;

    // movable
    BFVContext(BFVContext&& other) noexcept;
    BFVContext& operator=(BFVContext&& other) noexcept;

    /**
     * @brief initialize context with secure key generation
     * @param force_new_keys force generation of new keys even if cached
     * @return result indicating success or failure
     */
    Result<void> initialize(bool force_new_keys = false);

    /**
     * @brief check if context is properly initialized
     */
    bool is_initialized() const noexcept;

    /**
     * @brief get current parameters
     */
    const BFVParameters& parameters() const noexcept {
        return params_;
    }

    /**
     * @brief get crypto context
     */
    const CryptoContextBFV& crypto_context() const;

    /**
     * @brief get key bundle
     */
    const SecureKeyBundle& keys() const;

    /**
     * @brief encrypt integer value
     * @param value integer to encrypt
     * @return encrypted ciphertext or error
     */
    Result<Ciphertext> encrypt(int64_t value);

    /**
     * @brief encrypt vector of integers
     * @param values vector of integers to encrypt
     * @return encrypted ciphertext or error
     */
    Result<Ciphertext> encrypt(const std::vector<int64_t>& values);

    /**
     * @brief decrypt ciphertext to integer
     * @param ciphertext encrypted data
     * @return decrypted integer or error
     */
    Result<int64_t> decrypt_int(const Ciphertext& ciphertext);

    /**
     * @brief decrypt ciphertext to vector of integers
     * @param ciphertext encrypted data
     * @param size expected vector size
     * @return decrypted vector or error
     */
    Result<std::vector<int64_t>> decrypt_vector(const Ciphertext& ciphertext, size_t size = 0);

    /**
     * @brief perform homomorphic addition
     * @param lhs left operand
     * @param rhs right operand
     * @return result ciphertext or error
     */
    Result<Ciphertext> add(const Ciphertext& lhs, const Ciphertext& rhs);

    /**
     * @brief perform homomorphic subtraction
     * @param lhs left operand
     * @param rhs right operand
     * @return result ciphertext or error
     */
    Result<Ciphertext> subtract(const Ciphertext& lhs, const Ciphertext& rhs);

    /**
     * @brief perform homomorphic multiplication
     * @param lhs left operand
     * @param rhs right operand
     * @return result ciphertext or error
     */
    Result<Ciphertext> multiply(const Ciphertext& lhs, const Ciphertext& rhs);

    /**
     * @brief serialize entire context state
     * @param password encryption password
     * @return serialized context data or error
     */
    Result<std::vector<uint8_t>> serialize_context(const std::string& password) const;

    /**
     * @brief deserialize context state
     * @param data serialized context data
     * @param password decryption password
     * @return result indicating success or failure
     */
    Result<void> deserialize_context(const std::vector<uint8_t>& data, const std::string& password);

    /**
     * @brief get context statistics
     */
    struct Statistics {
        size_t ring_dimension;
        uint64_t plaintext_modulus;
        uint32_t multiplicative_depth;
        size_t ciphertext_size_bytes;
        bool relinearization_enabled;
        size_t rotation_keys_count;
        double noise_estimate;
    };

    Statistics get_statistics() const;

    /**
     * @brief estimate noise in ciphertext
     * @param ciphertext encrypted data to analyze
     * @return noise estimate or error
     */
    Result<double> estimate_noise(const Ciphertext& ciphertext) const;

    // parameter optimization helpers (made public for BFVParameters::recommended)
    static uint32_t calculate_optimal_ring_dim(SecurityLevel level, uint32_t mult_depth);
    static uint64_t select_plaintext_modulus(uint64_t int_range, uint32_t batch_size);
    static std::vector<uint64_t> generate_coeff_modulus(uint32_t ring_dim, uint32_t mult_depth,
                                                        SecurityLevel level);

   private:
    BFVParameters params_;
    CryptoContextBFV crypto_context_;
    std::unique_ptr<SecureKeyBundle> keys_;

    std::atomic<bool> initialized_{false};
    mutable std::mutex context_mutex_;

    // internal parameter validation and setup
    Result<void> validate_and_setup_parameters();
    Result<void> create_crypto_context();
    Result<void> generate_and_setup_keys();

    // secure memory management
    void secure_cleanup();
};

/**
 * @brief thread-safe context manager for multiple BFV contexts
 */
class BFVContextManager {
   public:
    /**
     * @brief get or create context for given parameters
     * @param params BFV parameters
     * @return shared context instance
     */
    static std::shared_ptr<BFVContext> get_context(const BFVParameters& params);

    /**
     * @brief clear all cached contexts
     */
    static void clear_cache();

    /**
     * @brief get cache statistics
     */
    static size_t cache_size();

   private:
    static std::unordered_map<std::string, std::weak_ptr<BFVContext>> context_cache_;
    static std::mutex cache_mutex_;

    static std::string params_hash(const BFVParameters& params);
};

}  // namespace cryptmalloc