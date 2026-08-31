#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

enum class EncryptionMode {
    NoEncryption = 0,
    AES128 = 1,
    AES256 = 2,
    CHACHA20 = 3
};

class CryptoConfig {
public:
    EncryptionMode mode;
    std::vector<uint8_t> key;
    std::shared_ptr<void> cipher_ctx;

    CryptoConfig() : mode(EncryptionMode::NoEncryption) {}

    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data);

    static CryptoConfig* NewCryptoConfig(EncryptionMode mode, const std::string& keyInput);
    static EncryptionMode ParseEncryptionMode(const std::string& s);
};

#endif
