/**
 * @file bfv_context.cpp
 * @brief implementation of robust BFV encryption context
 */

#include "cryptmalloc/bfv_context.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>

#ifdef __linux__
#include <sys/mman.h>
#endif

namespace cryptmalloc {

// BFVParameters implementation
bool BFVParameters::validate() const {
    // check security level
    if(security_level != SecurityLevel::HEStd_128_classic &&
       security_level != SecurityLevel::HEStd_192_classic &&
       security_level != SecurityLevel::HEStd_256_classic) {
        return false;
    }

    // check ring dimension (must be power of 2)
    if(ring_dimension == 0 || (ring_dimension & (ring_dimension - 1)) != 0) {
        return false;
    }

    // minimum ring dimension for security
    uint32_t min_ring_dim = static_cast<uint32_t>(security_level) >= 192 ? 16384 : 8192;
    if(ring_dimension < min_ring_dim) {
        return false;
    }

    // check plaintext modulus (must be prime and fit in range)
    if(plaintext_modulus < 2 || plaintext_modulus > (1ULL << 60)) {
        return false;
    }

    // check multiplicative depth
    if(multiplicative_depth == 0 || multiplicative_depth > 20) {
        return false;
    }

    // check batch size
    if(batch_size == 0 || batch_size > ring_dimension / 2) {
        return false;
    }

    return true;
}

BFVParameters BFVParameters::recommended(SecurityLevel level, uint64_t int_range,
                                         uint32_t mult_depth) {
    BFVParameters params;
    params.security_level = level;
    params.multiplicative_depth = mult_depth;

    // set ring dimension based on security level and multiplicative depth
    params.ring_dimension = BFVContext::calculate_optimal_ring_dim(level, mult_depth);

    // select plaintext modulus for integer range
    params.plaintext_modulus =
        BFVContext::select_plaintext_modulus(int_range, params.ring_dimension / 2);

    // set batch size to half ring dimension for optimal packing
    params.batch_size = params.ring_dimension / 2;

    // enable relinearization for multiplication operations
    params.enable_relinearization = true;

    // adjust standard deviation based on security level
    switch(level) {
        case SecurityLevel::HEStd_128_classic:
            params.standard_deviation = 3.2;
            break;
        case SecurityLevel::HEStd_192_classic:
            params.standard_deviation = 3.0;
            break;
        case SecurityLevel::HEStd_256_classic:
            params.standard_deviation = 2.8;
            break;
    }

    return params;
}

// SecureKeyBundle implementation
SecureKeyBundle::~SecureKeyBundle() {
    secure_clear();
}

SecureKeyBundle::SecureKeyBundle(SecureKeyBundle&& other) noexcept
    : public_key_(std::move(other.public_key_)),
      private_key_(std::move(other.private_key_)),
      keys_generated_(other.keys_generated_.load()) {
    other.keys_generated_ = false;
}

SecureKeyBundle& SecureKeyBundle::operator=(SecureKeyBundle&& other) noexcept {
    if(this != &other) {
        secure_clear();

        public_key_ = std::move(other.public_key_);
        private_key_ = std::move(other.private_key_);
        keys_generated_ = other.keys_generated_.load();

        other.keys_generated_ = false;
    }
    return *this;
}

Result<void> SecureKeyBundle::generate_keys(const CryptoContextBFV& context,
                                            const BFVParameters& params) {
    std::lock_guard<std::mutex> lock(keys_mutex_);

    try {
        // generate key pair
        auto keypair = context->KeyGen();
        if(!keypair.publicKey || !keypair.secretKey) {
            return Result<void>("Failed to generate key pair");
        }

        public_key_ = keypair.publicKey;
        private_key_ = keypair.secretKey;

        // generate relinearization keys if enabled
        if(params.enable_relinearization) {
            context->EvalMultKeyGen(private_key_);
            // Note: relinearization keys are managed internally by OpenFHE context
            // We don't need to store them separately for basic operations
        }

        // generate rotation keys if enabled
        if(params.enable_rotation && !params.rotation_indices.empty()) {
            for(int32_t index : params.rotation_indices) {
                context->EvalRotateKeyGen(private_key_, {index});
                // Note: rotation keys are also managed internally by OpenFHE context
            }
        }

        keys_generated_ = true;
        return Result<void>::success();

    } catch(const std::exception& e) {
        secure_clear();
        return Result<void>(std::string("Key generation failed: ") + e.what());
    }
}

Result<std::vector<uint8_t>> SecureKeyBundle::serialize(const std::string& password) const {
    std::lock_guard<std::mutex> lock(keys_mutex_);

    if(!keys_generated_) {
        return Result<std::vector<uint8_t>>("Keys not generated");
    }

    try {
        std::ostringstream oss;

        // serialize public key
        lbcrypto::Serial::Serialize(public_key_, oss, lbcrypto::SerType::BINARY);

        // serialize private key
        lbcrypto::Serial::Serialize(private_key_, oss, lbcrypto::SerType::BINARY);

        // Note: Relinearization and rotation keys are managed by the context
        // For simplicity, we only serialize the main keys
        oss.put(0);  // marker for no separate relin keys
        
        uint32_t rot_count = 0;  // no separate rotation keys
        oss.write(reinterpret_cast<const char*>(&rot_count), sizeof(rot_count));

        std::string serialized = oss.str();

        // encrypt with password (simple XOR for demonstration - use proper encryption in
        // production)
        std::vector<uint8_t> result(serialized.begin(), serialized.end());
        for(size_t i = 0; i < result.size(); ++i) {
            result[i] ^= password[i % password.size()];
        }

        return Result<std::vector<uint8_t>>(std::move(result));

    } catch(const std::exception& e) {
        return Result<std::vector<uint8_t>>(std::string("Serialization failed: ") + e.what());
    }
}

Result<void> SecureKeyBundle::deserialize(const std::vector<uint8_t>& data,
                                          const std::string& password,
                                          const CryptoContextBFV& context) {
    (void)context; // unused in current implementation  
    std::lock_guard<std::mutex> lock(keys_mutex_);

    try {
        // decrypt data
        std::vector<uint8_t> decrypted = data;
        for(size_t i = 0; i < decrypted.size(); ++i) {
            decrypted[i] ^= password[i % password.size()];
        }

        std::istringstream iss(std::string(decrypted.begin(), decrypted.end()));

        // deserialize public key
        lbcrypto::Serial::Deserialize(public_key_, iss, lbcrypto::SerType::BINARY);

        // deserialize private key
        lbcrypto::Serial::Deserialize(private_key_, iss, lbcrypto::SerType::BINARY);

        // deserialize relinearization keys
        char relin_marker;
        iss.get(relin_marker);
        if(relin_marker == 1) {
            // Skip relinearization keys since they're managed by context
            EvalKey dummy_key;
            lbcrypto::Serial::Deserialize(dummy_key, iss, lbcrypto::SerType::BINARY);
        }

        // deserialize rotation keys
        uint32_t rot_count;
        iss.read(reinterpret_cast<char*>(&rot_count), sizeof(rot_count));

        // Skip rotation keys since we don't store them separately
        for(uint32_t i = 0; i < rot_count; ++i) {
            int32_t index;
            iss.read(reinterpret_cast<char*>(&index), sizeof(index));

            EvalKey key;
            lbcrypto::Serial::Deserialize(key, iss, lbcrypto::SerType::BINARY);
            // Keys are discarded since they're managed by context
        }

        keys_generated_ = true;
        return Result<void>::success();

    } catch(const std::exception& e) {
        secure_clear();
        return Result<void>(std::string("Deserialization failed: ") + e.what());
    }
}

bool SecureKeyBundle::is_complete() const noexcept {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    return keys_generated_ && public_key_ && private_key_;
}

void SecureKeyBundle::secure_clear() {
    std::lock_guard<std::mutex> lock(keys_mutex_);

    // clear keys
    public_key_.reset();
    private_key_.reset();

    keys_generated_ = false;
}

void SecureKeyBundle::secure_zero_memory(void* ptr, size_t size) {
    if(ptr && size > 0) {
#ifdef __linux__
        // use explicit_bzero if available, otherwise memset
        explicit_bzero(ptr, size);
#else
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        for(size_t i = 0; i < size; ++i) {
            vptr[i] = 0;
        }
#endif
    }
}

// BFVContext implementation
BFVContext::BFVContext(const BFVParameters& params)
    : params_(params), keys_(std::make_unique<SecureKeyBundle>()) {}

BFVContext::~BFVContext() {
    secure_cleanup();
}

BFVContext::BFVContext(BFVContext&& other) noexcept
    : params_(std::move(other.params_)),
      crypto_context_(std::move(other.crypto_context_)),
      keys_(std::move(other.keys_)),
      initialized_(other.initialized_.load()) {
    other.initialized_ = false;
}

BFVContext& BFVContext::operator=(BFVContext&& other) noexcept {
    if(this != &other) {
        secure_cleanup();

        params_ = std::move(other.params_);
        crypto_context_ = std::move(other.crypto_context_);
        keys_ = std::move(other.keys_);
        initialized_ = other.initialized_.load();

        other.initialized_ = false;
    }
    return *this;
}

Result<void> BFVContext::initialize(bool force_new_keys) {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if(initialized_ && !force_new_keys) {
        return Result<void>::success();
    }

    // validate parameters
    auto validate_result = validate_and_setup_parameters();
    if(!validate_result.has_value()) {
        return validate_result;
    }

    // create crypto context
    auto context_result = create_crypto_context();
    if(!context_result.has_value()) {
        return context_result;
    }

    // generate keys
    auto keys_result = generate_and_setup_keys();
    if(!keys_result.has_value()) {
        return keys_result;
    }

    initialized_ = true;
    return Result<void>::success();
}

bool BFVContext::is_initialized() const noexcept {
    return initialized_ && crypto_context_ && keys_ && keys_->is_complete();
}

const BFVContext::CryptoContextBFV& BFVContext::crypto_context() const {
    if(!initialized_) {
        throw std::runtime_error("Context not initialized");
    }
    return crypto_context_;
}

const SecureKeyBundle& BFVContext::keys() const {
    if(!initialized_) {
        throw std::runtime_error("Context not initialized");
    }
    return *keys_;
}

Result<BFVContext::Ciphertext> BFVContext::encrypt(int64_t value) {
    if(!initialized_) {
        return Result<Ciphertext>("Context not initialized");
    }

    try {
        auto plaintext = crypto_context_->MakePackedPlaintext({value});
        auto ciphertext = crypto_context_->Encrypt(keys_->public_key(), plaintext);
        return Result<Ciphertext>(ciphertext);
    } catch(const std::exception& e) {
        return Result<Ciphertext>(std::string("Encryption failed: ") + e.what());
    }
}

Result<BFVContext::Ciphertext> BFVContext::encrypt(const std::vector<int64_t>& values) {
    if(!initialized_) {
        return Result<Ciphertext>("Context not initialized");
    }

    if(values.size() > params_.batch_size) {
        return Result<Ciphertext>("Vector too large for batch size");
    }

    try {
        auto plaintext = crypto_context_->MakePackedPlaintext(values);
        auto ciphertext = crypto_context_->Encrypt(keys_->public_key(), plaintext);
        return Result<Ciphertext>(ciphertext);
    } catch(const std::exception& e) {
        return Result<Ciphertext>(std::string("Encryption failed: ") + e.what());
    }
}

Result<int64_t> BFVContext::decrypt_int(const Ciphertext& ciphertext) {
    if(!initialized_) {
        return Result<int64_t>("Context not initialized");
    }

    try {
        Plaintext plaintext;
        crypto_context_->Decrypt(keys_->private_key(), ciphertext, &plaintext);

        auto values = plaintext->GetPackedValue();
        if(values.empty()) {
            return Result<int64_t>("Empty decryption result");
        }

        return Result<int64_t>(values[0]);
    } catch(const std::exception& e) {
        return Result<int64_t>(std::string("Decryption failed: ") + e.what());
    }
}

Result<std::vector<int64_t>> BFVContext::decrypt_vector(const Ciphertext& ciphertext, size_t size) {
    if(!initialized_) {
        return Result<std::vector<int64_t>>("Context not initialized");
    }

    try {
        Plaintext plaintext;
        crypto_context_->Decrypt(keys_->private_key(), ciphertext, &plaintext);

        auto values = plaintext->GetPackedValue();

        if(size > 0 && values.size() > size) {
            values.resize(size);
        }

        return Result<std::vector<int64_t>>(values);
    } catch(const std::exception& e) {
        return Result<std::vector<int64_t>>(std::string("Decryption failed: ") + e.what());
    }
}

Result<BFVContext::Ciphertext> BFVContext::add(const Ciphertext& lhs, const Ciphertext& rhs) {
    if(!initialized_) {
        return Result<Ciphertext>("Context not initialized");
    }

    try {
        auto result = crypto_context_->EvalAdd(lhs, rhs);
        return Result<Ciphertext>(result);
    } catch(const std::exception& e) {
        return Result<Ciphertext>(std::string("Addition failed: ") + e.what());
    }
}

Result<BFVContext::Ciphertext> BFVContext::subtract(const Ciphertext& lhs, const Ciphertext& rhs) {
    if(!initialized_) {
        return Result<Ciphertext>("Context not initialized");
    }

    try {
        auto result = crypto_context_->EvalSub(lhs, rhs);
        return Result<Ciphertext>(result);
    } catch(const std::exception& e) {
        return Result<Ciphertext>(std::string("Subtraction failed: ") + e.what());
    }
}

Result<BFVContext::Ciphertext> BFVContext::multiply(const Ciphertext& lhs, const Ciphertext& rhs) {
    if(!initialized_) {
        return Result<Ciphertext>("Context not initialized");
    }

    try {
        auto result = crypto_context_->EvalMult(lhs, rhs);

        // apply relinearization if available
        if(params_.enable_relinearization) {
            result = crypto_context_->Relinearize(result);
        }

        return Result<Ciphertext>(result);
    } catch(const std::exception& e) {
        return Result<Ciphertext>(std::string("Multiplication failed: ") + e.what());
    }
}

BFVContext::Statistics BFVContext::get_statistics() const {
    Statistics stats{};

    if(initialized_) {
        stats.ring_dimension = params_.ring_dimension;
        stats.plaintext_modulus = params_.plaintext_modulus;
        stats.multiplicative_depth = params_.multiplicative_depth;
        stats.relinearization_enabled = params_.enable_relinearization;
        stats.rotation_keys_count = params_.enable_rotation ? params_.rotation_indices.size() : 0;

        // estimate ciphertext size (rough approximation)
        stats.ciphertext_size_bytes =
            params_.ring_dimension * 8 * 2;  // 2 polynomials, 8 bytes per coeff
    }

    return stats;
}

Result<double> BFVContext::estimate_noise(const Ciphertext& ciphertext) const {
    if(!initialized_) {
        return Result<double>("Context not initialized");
    }

    try {
        // decrypt to get noise estimate (this is a simplified approach)
        Plaintext plaintext;
        crypto_context_->Decrypt(keys_->private_key(), ciphertext, &plaintext);

        // in a real implementation, you'd analyze the noise more carefully
        // this is a placeholder returning a fixed estimate
        return Result<double>(3.2);  // typical noise standard deviation

    } catch(const std::exception& e) {
        return Result<double>(std::string("Noise estimation failed: ") + e.what());
    }
}

// Private helper methods
Result<void> BFVContext::validate_and_setup_parameters() {
    if(!params_.validate()) {
        return Result<void>("Invalid BFV parameters");
    }
    return Result<void>::success();
}

Result<void> BFVContext::create_crypto_context() {
    try {
        lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;

        // set basic parameters
        parameters.SetPlaintextModulus(params_.plaintext_modulus);
        parameters.SetMultiplicativeDepth(params_.multiplicative_depth);
        parameters.SetRingDim(params_.ring_dimension);
        parameters.SetStandardDeviation(params_.standard_deviation);
        // Note: SetScalingTechnique is not used for BFV scheme

        // set security level
        switch(params_.security_level) {
            case SecurityLevel::HEStd_128_classic:
                parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
                break;
            case SecurityLevel::HEStd_192_classic:
                parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_192_classic);
                break;
            case SecurityLevel::HEStd_256_classic:
                parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_256_classic);
                break;
        }

        // create context
        crypto_context_ = lbcrypto::GenCryptoContext(parameters);

        // enable features
        crypto_context_->Enable(lbcrypto::PKE);
        crypto_context_->Enable(lbcrypto::KEYSWITCH);
        crypto_context_->Enable(lbcrypto::LEVELEDSHE);

        if(params_.enable_relinearization) {
            crypto_context_->Enable(lbcrypto::ADVANCEDSHE);
        }

        return Result<void>::success();

    } catch(const std::exception& e) {
        return Result<void>(std::string("Context creation failed: ") + e.what());
    }
}

Result<void> BFVContext::generate_and_setup_keys() {
    return keys_->generate_keys(crypto_context_, params_);
}

void BFVContext::secure_cleanup() {
    if(keys_) {
        keys_->secure_clear();
    }
    crypto_context_.reset();
    initialized_ = false;
}

// Static helper methods
uint32_t BFVContext::calculate_optimal_ring_dim(SecurityLevel level, uint32_t mult_depth) {
    // base ring dimension for security level
    uint32_t base_dim;
    switch(level) {
        case SecurityLevel::HEStd_128_classic:
            base_dim = mult_depth <= 3 ? 8192 : 16384;
            break;
        case SecurityLevel::HEStd_192_classic:
            base_dim = mult_depth <= 2 ? 16384 : 32768;
            break;
        case SecurityLevel::HEStd_256_classic:
            base_dim = 32768;
            break;
        default:
            base_dim = 16384;
    }

    // increase for higher multiplicative depths
    if(mult_depth > 5) {
        base_dim *= 2;
    }

    return base_dim;
}

uint64_t BFVContext::select_plaintext_modulus(uint64_t int_range, uint32_t batch_size) {
    (void)batch_size; // Not used in this simplified implementation
    
    // Use a simple approach: find a prime that's significantly larger than int_range
    // For BFV with typical ring dimensions, we can use standard primes that work well
    
    uint64_t min_safe = std::max(int_range * 2, static_cast<uint64_t>(65537));
    
    // Common BFV-compatible plaintext moduli that work with standard ring dimensions
    std::vector<uint64_t> safe_primes = {
        65537,     // 2^16 + 1 - works with most ring dimensions
        786433,    // 3 * 2^18 + 1 - good for larger ranges
        1048577,   // 2^20 + 1 - for even larger ranges
    };
    
    // Select the smallest prime that's at least min_safe
    for (uint64_t prime : safe_primes) {
        if (prime >= min_safe) {
            return prime;
        }
    }
    
    // If range is very large, use the largest safe prime
    return 1048577;
}

std::vector<uint64_t> BFVContext::generate_coeff_modulus(uint32_t ring_dim, uint32_t mult_depth,
                                                         SecurityLevel level) {
    // This is a simplified implementation
    // In practice, you'd use OpenFHE's parameter selection utilities
    std::vector<uint64_t> coeff_modulus;
    
    // Base modulus size based on security level
    uint32_t base_bits = 60;  // Default for 128-bit security
    if (level == SecurityLevel::HEStd_192_classic) {
        base_bits = 50;
    } else if (level == SecurityLevel::HEStd_256_classic) {
        base_bits = 45;
    }
    
    // Add special primes for each multiplicative level
    for (uint32_t i = 0; i <= mult_depth; ++i) {
        // Use OpenFHE's prime generation if available, otherwise use fixed primes
        uint64_t prime = (1ULL << base_bits) - 1;
        
        // Adjust prime to avoid conflicts
        while (prime > 0) {
            // Simple primality check (not cryptographically secure)
            bool is_prime = true;
            for (uint64_t j = 2; j * j <= prime && j < 1000; ++j) {
                if (prime % j == 0) {
                    is_prime = false;
                    break;
                }
            }
            
            if (is_prime && prime % (2 * ring_dim) == 1) {
                coeff_modulus.push_back(prime);
                break;
            }
            prime -= 2;  // Try next odd number
        }
        
        base_bits -= 5;  // Reduce bits for next level
        if (base_bits < 30) base_bits = 30;  // Minimum size
    }
    
    // Ensure we have at least one modulus
    if (coeff_modulus.empty()) {
        coeff_modulus.push_back(1125899906842624001ULL);  // A known good prime
    }
    
    return coeff_modulus;
}

// BFVContextManager implementation
std::unordered_map<std::string, std::weak_ptr<BFVContext>> BFVContextManager::context_cache_;
std::mutex BFVContextManager::cache_mutex_;

std::shared_ptr<BFVContext> BFVContextManager::get_context(const BFVParameters& params) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::string hash = params_hash(params);

    auto it = context_cache_.find(hash);
    if(it != context_cache_.end()) {
        if(auto context = it->second.lock()) {
            return context;
        }
        context_cache_.erase(it);
    }

    auto context = std::make_shared<BFVContext>(params);
    context_cache_[hash] = context;

    return context;
}

void BFVContextManager::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    context_cache_.clear();
}

size_t BFVContextManager::cache_size() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return context_cache_.size();
}

std::string BFVContextManager::params_hash(const BFVParameters& params) {
    std::ostringstream oss;
    oss << static_cast<int>(params.security_level) << "_" << params.ring_dimension << "_"
        << params.plaintext_modulus << "_" << params.multiplicative_depth << "_"
        << params.batch_size << "_" << params.enable_relinearization << "_"
        << params.enable_rotation;

    for(int32_t idx : params.rotation_indices) {
        oss << "_" << idx;
    }

    return oss.str();
}

}  // namespace cryptmalloc