#include "cryptmalloc/bfv_context.hpp"
#include <chrono>
#include <fstream>
#include <stdexcept>

#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace cryptmalloc {

void* SecureMemory::allocate_secure(size_t size) {
#ifdef __linux__
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        throw std::bad_alloc();
    }
    if (mlock(ptr, size) != 0) {
        munmap(ptr, size);
        throw std::bad_alloc();
    }
    return ptr;
#elif defined(_WIN32)
    void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        throw std::bad_alloc();
    }
    if (!VirtualLock(ptr, size)) {
        VirtualFree(ptr, 0, MEM_RELEASE);
        throw std::bad_alloc();
    }
    return ptr;
#else
    return std::aligned_alloc(64, size);
#endif
}

void SecureMemory::deallocate_secure(void* ptr, size_t size) {
    if (!ptr)
        return;

    secure_zero(ptr, size);

#ifdef __linux__
    munlock(ptr, size);
    munmap(ptr, size);
#elif defined(_WIN32)
    VirtualUnlock(ptr, size);
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    std::free(ptr);
#endif
}

void SecureMemory::secure_zero(void* ptr, size_t size) {
    if (!ptr)
        return;

#ifdef __linux__
    explicit_bzero(ptr, size);
#elif defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    volatile char* p = static_cast<volatile char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
#endif
}

BFVParameters BFVParameters::for_security_level(SecurityLevel level) {
    BFVParameters params;
    params.security_level = level;

    switch (level) {
        case SecurityLevel::SECURITY_128:
            params.polynomial_degree = 8192;
            params.plaintext_modulus = 65537;
            break;
        case SecurityLevel::SECURITY_192:
            params.polynomial_degree = 16384;
            params.plaintext_modulus = 65537;
            break;
        case SecurityLevel::SECURITY_256:
            params.polynomial_degree = 32768;
            params.plaintext_modulus = 65537;
            break;
    }

    return params;
}

BFVParameters BFVParameters::for_allocator_use_case() {
    BFVParameters params = for_security_level(SecurityLevel::SECURITY_128);
    params.parameter_set = ParameterSet::MEMORY_EFFICIENT;
    params.multiplicative_depth = 3;     // for allocation algorithms
    params.plaintext_modulus = 1032193;  // larger for address calculations
    params.enable_relinearization = true;
    params.enable_rotation = true;
    params.rotation_indices = 16;  // for memory management operations
    return params;
}

bool BFVParameters::validate() const {
    if (polynomial_degree != 0 && (polynomial_degree & (polynomial_degree - 1)) != 0) {
        return false;  // must be power of 2
    }

    if (multiplicative_depth == 0 || multiplicative_depth > 10) {
        return false;  // reasonable depth range
    }

    if (plaintext_modulus != 0 && plaintext_modulus < 2) {
        return false;  // must be at least 2
    }

    return true;
}

BFVContext::BFVContext(const BFVParameters& params) : params_(params) {
    auto start = std::chrono::high_resolution_clock::now();

    validate_parameters();
    initialize_context();

    auto end = std::chrono::high_resolution_clock::now();
    metrics_.context_creation_time_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    initialized_.store(true);
}

BFVContext::~BFVContext() {
    secure_cleanup();
}

BFVContext::BFVContext(BFVContext&& other) noexcept
    : params_(std::move(other.params_)),
      crypto_context_(std::move(other.crypto_context_)),
      key_pair_(std::move(other.key_pair_)),
      metrics_(other.metrics_) {
    initialized_.store(other.initialized_.load());
    keys_generated_.store(other.keys_generated_.load());
    other.initialized_.store(false);
    other.keys_generated_.store(false);
}

BFVContext& BFVContext::operator=(BFVContext&& other) noexcept {
    if (this != &other) {
        secure_cleanup();

        params_ = std::move(other.params_);
        crypto_context_ = std::move(other.crypto_context_);
        key_pair_ = std::move(other.key_pair_);
        metrics_ = other.metrics_;

        initialized_.store(other.initialized_.load());
        keys_generated_.store(other.keys_generated_.load());
        other.initialized_.store(false);
        other.keys_generated_.store(false);
    }
    return *this;
}

void BFVContext::generate_keys() {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!initialized_.load()) {
        throw std::runtime_error("context not initialized");
    }

    auto start = std::chrono::high_resolution_clock::now();

    key_pair_ = crypto_context_->KeyGen();
    if (!key_pair_.publicKey || !key_pair_.secretKey) {
        throw std::runtime_error("key generation failed");
    }

    if (params_.enable_relinearization) {
        crypto_context_->EvalMultKeyGen(key_pair_.secretKey);
    }

    auto end = std::chrono::high_resolution_clock::now();
    metrics_.key_generation_time_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    keys_generated_.store(true);
}

void BFVContext::generate_relinearization_keys() {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    crypto_context_->EvalMultKeyGen(key_pair_.secretKey);
}

void BFVContext::generate_rotation_keys(const std::vector<int32_t>& indices) {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    if (indices.empty()) {
        // generate common rotation keys for memory management
        std::vector<int32_t> default_indices;
        uint32_t slots = params_.polynomial_degree / 2;
        for (uint32_t i = 1; i <= std::min(params_.rotation_indices, slots); i *= 2) {
            default_indices.push_back(static_cast<int32_t>(i));
            default_indices.push_back(-static_cast<int32_t>(i));
        }
        crypto_context_->EvalRotateKeyGen(key_pair_.secretKey, default_indices);
    } else {
        crypto_context_->EvalRotateKeyGen(key_pair_.secretKey, indices);
    }
}

void BFVContext::clear_keys() {
    std::lock_guard<std::mutex> lock(context_mutex_);

    // secure cleanup of key material
    if (key_pair_.publicKey) {
        key_pair_.publicKey.reset();
    }
    if (key_pair_.secretKey) {
        key_pair_.secretKey.reset();
    }

    keys_generated_.store(false);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::encrypt(int64_t value) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    auto plaintext = crypto_context_->MakePackedPlaintext({value});
    return crypto_context_->Encrypt(key_pair_.publicKey, plaintext);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::encrypt(
    const std::vector<int64_t>& values) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    auto plaintext = crypto_context_->MakePackedPlaintext(values);
    return crypto_context_->Encrypt(key_pair_.publicKey, plaintext);
}

int64_t BFVContext::decrypt_single(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    lbcrypto::Plaintext plaintext;
    crypto_context_->Decrypt(key_pair_.secretKey, ciphertext, &plaintext);

    auto values = plaintext->GetPackedValue();
    if (values.empty()) {
        throw std::runtime_error("decryption failed");
    }

    return values[0];
}

std::vector<int64_t> BFVContext::decrypt_batch(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        throw std::runtime_error("keys not generated");
    }

    lbcrypto::Plaintext plaintext;
    crypto_context_->Decrypt(key_pair_.secretKey, ciphertext, &plaintext);

    return plaintext->GetPackedValue();
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::add(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) const {
    return crypto_context_->EvalAdd(ct1, ct2);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::multiply(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) const {
    return crypto_context_->EvalMult(ct1, ct2);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::rotate(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, int32_t index) const {
    return crypto_context_->EvalRotate(ciphertext, index);
}

bool BFVContext::serialize_context(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!initialized_.load()) {
        return false;
    }

    try {
        if (!lbcrypto::Serial::SerializeToFile(
                filepath, crypto_context_, lbcrypto::SerType::BINARY)) {
            return false;
        }

        // add integrity verification
        std::ofstream meta_file(filepath + ".meta");
        if (!meta_file)
            return false;

        meta_file << "security_level=" << static_cast<int>(params_.security_level) << "\n";
        meta_file << "polynomial_degree=" << params_.polynomial_degree << "\n";
        meta_file << "plaintext_modulus=" << params_.plaintext_modulus << "\n";
        meta_file << "multiplicative_depth=" << params_.multiplicative_depth << "\n";

        return true;
    } catch (...) {
        return false;
    }
}

bool BFVContext::deserialize_context(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(context_mutex_);

    try {
        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> loaded_context;
        if (!lbcrypto::Serial::DeserializeFromFile(
                filepath, loaded_context, lbcrypto::SerType::BINARY)) {
            return false;
        }

        // verify integrity
        std::ifstream meta_file(filepath + ".meta");
        if (!meta_file)
            return false;

        std::string line;
        while (std::getline(meta_file, line)) {
            // basic integrity check - could be enhanced with crypto hashes
            if (line.find("security_level=") == 0) {
                int level = std::stoi(line.substr(15));
                if (level != static_cast<int>(params_.security_level)) {
                    return false;
                }
            }
        }

        crypto_context_ = loaded_context;
        initialized_.store(true);
        return true;
    } catch (...) {
        return false;
    }
}

bool BFVContext::serialize_keys(const std::string& /* filepath */) const {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!keys_generated_.load()) {
        return false;
    }

    try {
        // Note: KeyPair serialization not supported in OpenFHE 1.3.1
        // Serialize keys individually instead
        return false;  // placeholder implementation
    } catch (...) {
        return false;
    }
}

bool BFVContext::deserialize_keys(const std::string& /* filepath */) {
    std::lock_guard<std::mutex> lock(context_mutex_);

    if (!initialized_.load()) {
        return false;
    }

    try {
        // Note: KeyPair serialization not supported in OpenFHE 1.3.1
        // Serialize keys individually instead
        return false;  // placeholder implementation
    } catch (...) {
        return false;
    }
}

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> BFVContext::get_crypto_context() const {
    std::lock_guard<std::mutex> lock(context_mutex_);
    return crypto_context_;
}

void BFVContext::initialize_context() {
    auto cc_params = create_cc_params();
    crypto_context_ = lbcrypto::GenCryptoContext(cc_params);

    if (!crypto_context_) {
        throw std::runtime_error("failed to create crypto context");
    }

    crypto_context_->Enable(lbcrypto::PKE);
    crypto_context_->Enable(lbcrypto::KEYSWITCH);
    crypto_context_->Enable(lbcrypto::LEVELEDSHE);

    if (params_.enable_rotation) {
        crypto_context_->Enable(lbcrypto::ADVANCEDSHE);
    }

    // store effective parameters
    metrics_.effective_polynomial_degree = crypto_context_->GetRingDimension();
    metrics_.effective_plaintext_modulus = crypto_context_->GetEncodingParams()->GetPlaintextModulus();
}

void BFVContext::validate_parameters() const {
    if (!params_.validate()) {
        throw std::invalid_argument("invalid parameters");
    }
}

lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> BFVContext::create_cc_params() const {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;

    uint32_t poly_degree = params_.polynomial_degree ? params_.polynomial_degree
                                                     : calculate_optimal_polynomial_degree();

    uint64_t plaintext_mod = params_.plaintext_modulus ? params_.plaintext_modulus
                                                       : calculate_optimal_plaintext_modulus();

    parameters.SetPlaintextModulus(plaintext_mod);
    parameters.SetMultiplicativeDepth(params_.multiplicative_depth);
    parameters.SetRingDim(poly_degree);

    switch (params_.security_level) {
        case SecurityLevel::SECURITY_128:
            parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);
            break;
        case SecurityLevel::SECURITY_192:
            parameters.SetSecurityLevel(lbcrypto::HEStd_192_classic);
            break;
        case SecurityLevel::SECURITY_256:
            parameters.SetSecurityLevel(lbcrypto::HEStd_256_classic);
            break;
    }

    return parameters;
}

void BFVContext::secure_cleanup() {
    clear_keys();

    if (crypto_context_) {
        crypto_context_.reset();
    }

    initialized_.store(false);
}

uint32_t BFVContext::calculate_optimal_polynomial_degree() const {
    switch (params_.parameter_set) {
        case ParameterSet::FAST_OPERATIONS:
            return 16384;  // updated for OpenFHE 1.3.1 security requirements
        case ParameterSet::MEMORY_EFFICIENT:
            return 16384;  // updated for OpenFHE 1.3.1 security requirements
        case ParameterSet::HIGH_PRECISION:
            return 16384;  // larger for precision
        case ParameterSet::BALANCED:
        default:
            return 8192;
    }
}

uint64_t BFVContext::calculate_optimal_plaintext_modulus() const {
    switch (params_.parameter_set) {
        case ParameterSet::FAST_OPERATIONS:
            return 65537;  // small prime for speed
        case ParameterSet::MEMORY_EFFICIENT:
            return 65537;  // small prime for memory
        case ParameterSet::HIGH_PRECISION:
            return 1032193;  // larger prime for precision
        case ParameterSet::BALANCED:
        default:
            return 65537;
    }
}

uint32_t BFVContext::calculate_multiplicative_depth() const {
    // depth based on typical memory allocator operations
    return std::max(params_.multiplicative_depth, 2u);
}

std::string security_level_to_string(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::SECURITY_128:
            return "128-bit";
        case SecurityLevel::SECURITY_192:
            return "192-bit";
        case SecurityLevel::SECURITY_256:
            return "256-bit";
        default:
            return "unknown";
    }
}

std::string parameter_set_to_string(ParameterSet set) {
    switch (set) {
        case ParameterSet::FAST_OPERATIONS:
            return "fast_operations";
        case ParameterSet::MEMORY_EFFICIENT:
            return "memory_efficient";
        case ParameterSet::HIGH_PRECISION:
            return "high_precision";
        case ParameterSet::BALANCED:
            return "balanced";
        default:
            return "unknown";
    }
}

BFVParameters get_recommended_parameters(SecurityLevel security, ParameterSet param_set) {
    auto params = BFVParameters::for_security_level(security);
    params.parameter_set = param_set;

    switch (param_set) {
        case ParameterSet::FAST_OPERATIONS:
            params.polynomial_degree = 16384;
            params.multiplicative_depth = 2;
            break;
        case ParameterSet::MEMORY_EFFICIENT:
            params.polynomial_degree = 16384;
            params.plaintext_modulus = 65537;
            break;
        case ParameterSet::HIGH_PRECISION:
            params.polynomial_degree = 16384;
            params.plaintext_modulus = 65537;  // Use compatible modulus for OpenFHE 1.3.1
            params.multiplicative_depth = 4;
            break;
        case ParameterSet::BALANCED:
            // use defaults from for_security_level
            break;
    }

    return params;
}

CiphertextPool& CiphertextPool::instance() {
    static CiphertextPool instance;
    return instance;
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> CiphertextPool::acquire() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    if (!pool_.empty()) {
        auto ct = std::move(pool_.back());
        pool_.pop_back();
        pool_size_.fetch_sub(1);
        active_count_.fetch_add(1);
        return ct;
    }

    active_count_.fetch_add(1);
    return lbcrypto::Ciphertext<lbcrypto::DCRTPoly>();
}

void CiphertextPool::release(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>&& ct) {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    if (pool_.size() < 100) {  // limit pool size
        pool_.emplace_back(std::move(ct));
        pool_size_.fetch_add(1);
    }

    active_count_.fetch_sub(1);
}

void CiphertextPool::clear() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    pool_.clear();
    pool_size_.store(0);
    active_count_.store(0);
}

}  // namespace cryptmalloc