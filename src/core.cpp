#include "cryptmalloc/core.hpp"
#include <memory>
#include "cryptmalloc/openfhe_context.hpp"

namespace cryptmalloc {

bool CryptMalloc::initialized_ = false;
EncryptionParams CryptMalloc::params_ = {};

static std::unique_ptr<OpenFHEContext> global_context;

bool CryptMalloc::initialize() {
    return initialize(EncryptionParams{});
}

bool CryptMalloc::initialize(const EncryptionParams& params) {
    if (initialized_) {
        return true;
    }

    try {
        params_ = params;
        global_context = std::make_unique<OpenFHEContext>(params_);

        if (!global_context->is_valid()) {
            global_context.reset();
            return false;
        }

        initialized_ = true;
        return true;
    } catch (...) {
        global_context.reset();
        return false;
    }
}

void CryptMalloc::shutdown() {
    if (initialized_) {
        global_context.reset();
        initialized_ = false;
    }
}

bool CryptMalloc::is_initialized() {
    return initialized_;
}

const EncryptionParams& CryptMalloc::get_params() {
    return params_;
}

}  // namespace cryptmalloc