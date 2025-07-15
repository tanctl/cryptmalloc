#include "cryptmalloc/openfhe_context.hpp"
#include <stdexcept>

namespace cryptmalloc {

OpenFHEContext::OpenFHEContext(const EncryptionParams& params) {
    setup_context(params);
}

void OpenFHEContext::setup_context(const EncryptionParams& params) {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(params.plaintext_modulus);
    parameters.SetMultiplicativeDepth(params.depth);
    parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);
    parameters.SetRingDim(params.ring_dimension);

    context_ = lbcrypto::GenCryptoContext(parameters);
    if (!context_) {
        throw std::runtime_error("failed to create openfhe context");
    }

    context_->Enable(lbcrypto::PKE);
    context_->Enable(lbcrypto::KEYSWITCH);
    context_->Enable(lbcrypto::LEVELEDSHE);

    key_pair_ = context_->KeyGen();
    if (!key_pair_.publicKey || !key_pair_.secretKey) {
        throw std::runtime_error("failed to generate key pair");
    }

    // need eval keys for multiplication
    context_->EvalMultKeyGen(key_pair_.secretKey);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> OpenFHEContext::encrypt(int64_t value) {
    if (!context_) {
        throw std::runtime_error("context not initialized");
    }

    auto plaintext = context_->MakePackedPlaintext({value});
    return context_->Encrypt(key_pair_.publicKey, plaintext);
}

int64_t OpenFHEContext::decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) {
    if (!context_) {
        throw std::runtime_error("context not initialized");
    }

    lbcrypto::Plaintext plaintext;
    context_->Decrypt(key_pair_.secretKey, ciphertext, &plaintext);

    auto values = plaintext->GetPackedValue();
    if (values.empty()) {
        throw std::runtime_error("decryption produced empty result");
    }

    return values[0];
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> OpenFHEContext::add(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) {
    if (!context_) {
        throw std::runtime_error("context not initialized");
    }

    return context_->EvalAdd(ct1, ct2);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> OpenFHEContext::multiply(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct1,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct2) {
    if (!context_) {
        throw std::runtime_error("context not initialized");
    }

    return context_->EvalMult(ct1, ct2);
}

}  // namespace cryptmalloc