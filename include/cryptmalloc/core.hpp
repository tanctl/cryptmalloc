#pragma once

#include <cstddef>
#include <memory>
#include <string>

namespace cryptmalloc {

struct Version {
    static constexpr int major = 1;
    static constexpr int minor = 0;
    static constexpr int patch = 0;

    static std::string string() {
        return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
    }
};

struct EncryptionParams {
    size_t ring_dimension = 8192;
    size_t plaintext_modulus = 65537;
    double sigma = 3.2;
    size_t depth = 2;
};

class CryptMalloc {
  public:
    static bool initialize();

    static bool initialize(const EncryptionParams& params);

    static void shutdown();

    static bool is_initialized();

    static const EncryptionParams& get_params();

  private:
    static bool initialized_;
    static EncryptionParams params_;
};

}