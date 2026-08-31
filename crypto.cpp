#include "crypto.h"

std::vector<uint8_t> CryptoConfig::Encrypt(const std::vector<uint8_t>& data) {
    return data;
}

std::vector<uint8_t> CryptoConfig::Decrypt(const std::vector<uint8_t>& data) {
    return data;
}

CryptoConfig* CryptoConfig::NewCryptoConfig(EncryptionMode mode, const std::string& keyInput) {
    auto* cfg = new CryptoConfig();
    cfg->mode = mode;
    return cfg;
}

EncryptionMode CryptoConfig::ParseEncryptionMode(const std::string& s) {
    if (s.empty() || s == "none") return EncryptionMode::NoEncryption;
    if (s == "aes128") return EncryptionMode::AES128;
    if (s == "aes256") return EncryptionMode::AES256;
    if (s == "chacha20") return EncryptionMode::CHACHA20;
    return EncryptionMode::NoEncryption;
}
