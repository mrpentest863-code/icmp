#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>
#include <vector>

// -------------------------------------------------------------------
// Fonctions auxiliaires (internes)
// -------------------------------------------------------------------

static std::vector<uint8_t> deriveKey(const std::string& passphrase, size_t keyLen) {
    // Dérivation simple : SHA-256 de la passphrase (pour l'exemple)
    // En production, utilisez PKCS5_PBKDF2_HMAC avec un sel aléatoire stocké.
    std::vector<uint8_t> key(keyLen);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(ctx, passphrase.data(), passphrase.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);
    // On répète le hash si la clé demandée est plus grande que 32 octets (cas AES-256 : 32 octets, ChaCha20 : 32)
    if (keyLen > hashLen) {
        // Pour simplifier, on tronque ou on répète (ici on ne gère que 16 ou 32 octets)
        throw std::runtime_error("Key length too long for simple derivation");
    }
    std::copy(hash.begin(), hash.begin() + keyLen, key.begin());
    return key;
}

static std::vector<uint8_t> generateIV(size_t len) {
    std::vector<uint8_t> iv(len);
    if (RAND_bytes(iv.data(), static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return iv;
}

// -------------------------------------------------------------------
// CryptoConfig
// -------------------------------------------------------------------

CryptoConfig::CryptoConfig(EncryptionMode mode, const std::string& keyInput)
    : m_mode(mode), m_key(deriveKey(keyInput, keySizeForMode(mode))) {}

CryptoConfig::~CryptoConfig() = default;

size_t CryptoConfig::keySizeForMode(EncryptionMode mode) {
    switch (mode) {
        case EncryptionMode::AES128:   return 16;
        case EncryptionMode::AES256:   return 32;
        case EncryptionMode::CHACHA20: return 32;
        default:                       return 0;
    }
}

size_t CryptoConfig::ivSizeForMode(EncryptionMode mode) {
    switch (mode) {
        case EncryptionMode::AES128:   return 16; // CBC
        case EncryptionMode::AES256:   return 16;
        case EncryptionMode::CHACHA20: return 12; // Nonce de 12 octets recommandé
        default:                       return 0;
    }
}

const EVP_CIPHER* CryptoConfig::cipherForMode(EncryptionMode mode) {
    switch (mode) {
        case EncryptionMode::AES128:   return EVP_aes_128_cbc();
        case EncryptionMode::AES256:   return EVP_aes_256_cbc();
        case EncryptionMode::CHACHA20: return EVP_chacha20();
        default:                       return nullptr;
    }
}

std::vector<uint8_t> CryptoConfig::Encrypt(const std::vector<uint8_t>& data) {
    if (m_mode == EncryptionMode::NoEncryption) {
        return data; // pas de chiffrement
    }

    const EVP_CIPHER* cipher = cipherForMode(m_mode);
    if (!cipher) throw std::runtime_error("Unsupported encryption mode");

    size_t ivLen = ivSizeForMode(m_mode);
    std::vector<uint8_t> iv = generateIV(ivLen);

    // Contexte de chiffrement
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, m_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    // Taille maximale du ciphertext (ajoute un bloc si padding)
    std::vector<uint8_t> ciphertext(data.size() + EVP_CIPHER_CTX_block_size(ctx));
    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    totalLen += outLen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    totalLen += outLen;

    EVP_CIPHER_CTX_free(ctx);

    // Résultat = IV + ciphertext
    std::vector<uint8_t> result;
    result.reserve(ivLen + totalLen);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + totalLen);
    return result;
}

std::vector<uint8_t> CryptoConfig::Decrypt(const std::vector<uint8_t>& data) {
    if (m_mode == EncryptionMode::NoEncryption) {
        return data;
    }

    const EVP_CIPHER* cipher = cipherForMode(m_mode);
    if (!cipher) throw std::runtime_error("Unsupported encryption mode");

    size_t ivLen = ivSizeForMode(m_mode);
    if (data.size() < ivLen) throw std::runtime_error("Input too short (missing IV)");

    // Extraire l'IV
    std::vector<uint8_t> iv(data.begin(), data.begin() + ivLen);
    std::vector<uint8_t> ciphertext(data.begin() + ivLen, data.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, m_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int outLen = 0;
    int totalLen = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    totalLen += outLen;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong key/corrupted data)");
    }
    totalLen += outLen;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(totalLen);
    return plaintext;
}

// -------------------------------------------------------------------
// Méthodes statiques (factory)
// -------------------------------------------------------------------

CryptoConfig* CryptoConfig::NewCryptoConfig(EncryptionMode mode, const std::string& keyInput) {
    if (mode == EncryptionMode::NoEncryption) {
        // Aucune clé nécessaire
        return new CryptoConfig(mode, ""); // ou on pourrait laisser vide
    }
    if (keyInput.empty()) {
        throw std::invalid_argument("keyInput cannot be empty for encryption modes");
    }
    return new CryptoConfig(mode, keyInput);
}

EncryptionMode CryptoConfig::ParseEncryptionMode(const std::string& s) {
    if (s.empty() || s == "none") return EncryptionMode::NoEncryption;
    if (s == "aes128") return EncryptionMode::AES128;
    if (s == "aes256") return EncryptionMode::AES256;
    if (s == "chacha20") return EncryptionMode::CHACHA20;
    // Si inconnu, on lève une exception (plus sûr que de retourner NoEncryption silencieusement)
    throw std::invalid_argument("Unknown encryption mode: " + s);
}
