/**
 * @file openfhe_context.hpp
 * @brief openfhe context management and encryption operations
 */

#pragma once

#include <memory>

#include "cryptmalloc/core.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

/**
 * @brief manages OpenFHE encryption context and operations
 */
class OpenFHEContext {
   public:
    /**
     * @brief construct context with default encryption parameters
     */
    explicit OpenFHEContext(const EncryptionConfig& config = {});

    /**
     * @brief initialize the encryption context
     * @return result indicating success or failure
     */
    Result<void> initialize();

    /**
     * @brief encrypt plaintext data
     * @param data pointer to plaintext data
     * @param size size of data in bytes
     * @return encrypted ciphertext or error
     */
    Result<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> encrypt(const void* data, size_t size);

    /**
     * @brief decrypt ciphertext to plaintext
     * @param ciphertext encrypted data
     * @param output buffer for decrypted data
     * @param output_size size of output buffer
     * @return success or error result
     */
    Result<size_t> decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, void* output,
                           size_t output_size);

    /**
     * @brief get the encryption scheme context
     */
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& get_context() const;

    /**
     * @brief get the public key
     */
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& get_public_key() const;

    /**
     * @brief get the private key
     */
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& get_private_key() const;

    /**
     * @brief check if context is initialized
     */
    bool is_initialized() const noexcept;

   private:
    EncryptionConfig config_;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> crypto_context_;
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key_;
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> private_key_;
    bool initialized_;

    void setup_parameters();
};

}  // namespace cryptmalloc