#pragma once

#include <memory>
#include "cryptmalloc/core.hpp"
#include "openfhe/pke/openfhe.h"

namespace cryptmalloc {

class OpenFHEContext {
  public:
    explicit OpenFHEContext(const EncryptionParams& params);

    ~OpenFHEContext() = default;

    OpenFHEContext(const OpenFHEContext&) = delete;
    OpenFHEContext& operator=(const OpenFHEContext&) = delete;
    OpenFHEContext(OpenFHEContext&&) = default;
    OpenFHEContext& operator=(OpenFHEContext&&) = default;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> encrypt(int64_t value);

    int64_t decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext);

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> add(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2);

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> multiply(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> get_context() const {
        return context_;
    }

    bool is_valid() const {
        return context_ != nullptr;
    }

  private:
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key_pair_;

    void setup_context(const EncryptionParams& params);
};

}