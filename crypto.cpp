#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <algorithm>

namespace {
    std::vector<uint8_t> deriveKey(const std::string& keyInput, size_t keySize) {
        if (keyInput.empty()) throw std::runtime_error("encryption key cannot be empty");
        const std::string salt = "pingtunnel-salt";
        const int iterations = 10000;
        std::vector<uint8_t> dk(keySize);
        PKCS5_PBKDF2_HMAC(keyInput.c_str(), keyInput.size(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                          iterations, EVP_sha256(), keySize, dk.data());
        return dk;
    }
}

CryptoConfig* CryptoConfig::NewCryptoConfig(EncryptionMode mode, const std::string& keyInput) {
    auto* cfg = new CryptoConfig();
    cfg->mode = mode;
    if (mode == EncryptionMode::NoEncryption) return cfg;

    size_t keySize = 0;
    switch (mode) {
        case EncryptionMode::AES128: keySize = 16; break;
        case EncryptionMode::AES256: keySize = 32; break;
        case EncryptionMode::CHACHA20: keySize = 32; break;
        default: throw std::runtime_error("unsupported encryption mode");
    }

    cfg->key = deriveKey(keyInput, keySize);
    return cfg;
}

std::vector<uint8_t> CryptoConfig::Encrypt(const std::vector<uint8_t>& data) {
    if (mode == EncryptionMode::NoEncryption) return data;

    const EVP_CIPHER* cipher = nullptr;
    if (mode == EncryptionMode::AES128 || mode == EncryptionMode::AES256) {
        cipher = (key.size() == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    } else if (mode == EncryptionMode::CHACHA20) {
        cipher = EVP_chacha20_poly1305();
    } else {
        throw std::runtime_error("cipher not initialized");
    }

    int nonceSize = 12;
    std::vector<uint8_t> nonce(nonceSize);
    RAND_bytes(nonce.data(), nonceSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonceSize, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    std::vector<uint8_t> ciphertext(data.size() + 16);
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    int ciphertextLen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextLen += len;

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.reserve(nonce.size() + ciphertextLen + tag.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> CryptoConfig::Decrypt(const std::vector<uint8_t>& data) {
    if (mode == EncryptionMode::NoEncryption) return data;

    const EVP_CIPHER* cipher = nullptr;
    if (mode == EncryptionMode::AES128 || mode == EncryptionMode::AES256) {
        cipher = (key.size() == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    } else if (mode == EncryptionMode::CHACHA20) {
        cipher = EVP_chacha20_poly1305();
    } else {
        throw std::runtime_error("cipher not initialized");
    }

    int nonceSize = 12;
    int tagSize = 16;
    if (data.size() < nonceSize + tagSize) throw std::runtime_error("ciphertext too short");

    std::vector<uint8_t> nonce(data.begin(), data.begin() + nonceSize);
    std::vector<uint8_t> tag(data.end() - tagSize, data.end());
    std::vector<uint8_t> ciphertext(data.begin() + nonceSize, data.end() - tagSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonceSize, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintextLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagSize, tag.data());
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decryption failed");
    }
    plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintextLen);
    return plaintext;
}

EncryptionMode CryptoConfig::ParseEncryptionMode(const std::string& s) {
    if (s.empty() || s == "none") return EncryptionMode::NoEncryption;
    if (s == "aes128") return EncryptionMode::AES128;
    if (s == "aes256") return EncryptionMode::AES256;
    if (s == "chacha20" || s == "chacha20-poly1305") return EncryptionMode::CHACHA20;
    throw std::runtime_error("invalid encryption mode");
}
