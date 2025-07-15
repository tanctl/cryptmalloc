/**
 * @file openfhe_context.cpp
 * @brief implementation of OpenFHE encryption context
 */

#include "cryptmalloc/openfhe_context.hpp"

#include <stdexcept>
#include <vector>

namespace cryptmalloc {

OpenFHEContext::OpenFHEContext(const EncryptionConfig& config)
    : config_(config), initialized_(false) {}

Result<void> OpenFHEContext::initialize() {
    try {
        setup_parameters();

        auto keypair = crypto_context_->KeyGen();
        public_key_ = keypair.publicKey;
        private_key_ = keypair.secretKey;

        crypto_context_->EvalMultKeyGen(private_key_);

        initialized_ = true;
        return Result<void>::success();
    } catch(const std::exception& e) {
        return Result<void>(std::string("Failed to initialize OpenFHE context: ") + e.what());
    }
}

Result<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> OpenFHEContext::encrypt(const void* data,
                                                                         size_t size) {
    if(!initialized_) {
        return Result<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>("Context not initialized");
    }

    try {
        // convert bytes to vector of integers for encryption
        std::vector<int64_t> plaintext_vec;
        const uint8_t* byte_data = static_cast<const uint8_t*>(data);

        plaintext_vec.reserve(size);
        for(size_t i = 0; i < size; ++i) {
            plaintext_vec.push_back(static_cast<int64_t>(byte_data[i]));
        }

        auto plaintext = crypto_context_->MakePackedPlaintext(plaintext_vec);
        auto ciphertext = crypto_context_->Encrypt(public_key_, plaintext);

        return Result<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(std::move(ciphertext));
    } catch(const std::exception& e) {
        return Result<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(std::string("Encryption failed: ") +
                                                                e.what());
    }
}

Result<size_t> OpenFHEContext::decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext,
                                       void* output, size_t output_size) {
    if(!initialized_) {
        return Result<size_t>("Context not initialized");
    }

    try {
        lbcrypto::Plaintext plaintext;
        crypto_context_->Decrypt(private_key_, ciphertext, &plaintext);

        auto decrypted_vec = plaintext->GetPackedValue();

        size_t bytes_to_copy = std::min(output_size, decrypted_vec.size());
        uint8_t* byte_output = static_cast<uint8_t*>(output);

        for(size_t i = 0; i < bytes_to_copy; ++i) {
            byte_output[i] = static_cast<uint8_t>(decrypted_vec[i]);
        }

        return Result<size_t>(bytes_to_copy);
    } catch(const std::exception& e) {
        return Result<size_t>(std::string("Decryption failed: ") + e.what());
    }
}

const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& OpenFHEContext::get_context() const {
    return crypto_context_;
}

const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& OpenFHEContext::get_public_key() const {
    return public_key_;
}

const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& OpenFHEContext::get_private_key() const {
    return private_key_;
}

bool OpenFHEContext::is_initialized() const noexcept {
    return initialized_;
}

void OpenFHEContext::setup_parameters() {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(config_.plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
    parameters.SetRingDim(config_.ring_dimension);

    crypto_context_ = lbcrypto::GenCryptoContext(parameters);
    crypto_context_->Enable(lbcrypto::PKE);
    crypto_context_->Enable(lbcrypto::KEYSWITCH);
    crypto_context_->Enable(lbcrypto::LEVELEDSHE);
}

}  // namespace cryptmalloc