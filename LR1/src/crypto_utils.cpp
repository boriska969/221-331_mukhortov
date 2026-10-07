#include "crypto_utils.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>

namespace lr1 {
namespace {

struct CipherContextDeleter {
    void operator()(EVP_CIPHER_CTX* context) const { EVP_CIPHER_CTX_free(context); }
};
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter>;

}

Bytes deriveKey(const std::string& pin, const Bytes& salt) {
    Bytes key(kKeySize);
    const int status = PKCS5_PBKDF2_HMAC(
        pin.data(), static_cast<int>(pin.size()), salt.data(), static_cast<int>(salt.size()),
        kPbkdf2Iterations, EVP_sha256(), static_cast<int>(key.size()), key.data());
    if (status != 1) {
        wipe(key);
        return Bytes();
    }
    return key;
}

Bytes encryptCbc(const Bytes& key, const Bytes& iv, const Bytes& plain) {
    CipherContext context(EVP_CIPHER_CTX_new());
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr,
                                       key.data(), iv.data()) != 1) {
        return Bytes();
    }

    Bytes output(plain.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int updateLength = 0;
    if (EVP_EncryptUpdate(context.get(), output.data(), &updateLength, plain.data(),
                          static_cast<int>(plain.size())) != 1) {
        return Bytes();
    }
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(context.get(), output.data() + updateLength, &finalLength) != 1) {
        return Bytes();
    }
    output.resize(static_cast<std::size_t>(updateLength + finalLength));
    return output;
}

bool decryptCbcStreaming(const Bytes& key, const Bytes& iv, std::istream& input,
                         std::string& plainOut) {
    plainOut.clear();
    CipherContext context(EVP_CIPHER_CTX_new());
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr,
                                       key.data(), iv.data()) != 1) {
        return false;
    }

    Bytes inputBlock(kReadBlockSize);
    Bytes outputBlock(kReadBlockSize + EVP_MAX_BLOCK_LENGTH);
    bool ok = true;
    while (input) {
        input.read(reinterpret_cast<char*>(inputBlock.data()),
                   static_cast<std::streamsize>(inputBlock.size()));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead <= 0) {
            break;
        }
        int outputLength = 0;
        if (EVP_DecryptUpdate(context.get(), outputBlock.data(), &outputLength,
                              inputBlock.data(), static_cast<int>(bytesRead)) != 1) {
            ok = false;
            break;
        }
        plainOut.append(reinterpret_cast<const char*>(outputBlock.data()),
                        static_cast<std::size_t>(outputLength));
        OPENSSL_cleanse(outputBlock.data(), outputBlock.size());
    }

    if (ok) {
        unsigned char tail[EVP_MAX_BLOCK_LENGTH] = {};
        int tailLength = 0;
        if (EVP_DecryptFinal_ex(context.get(), tail, &tailLength) == 1) {
            plainOut.append(reinterpret_cast<const char*>(tail),
                            static_cast<std::size_t>(tailLength));
        } else {
            ok = false;
        }
        OPENSSL_cleanse(tail, sizeof(tail));
    }

    OPENSSL_cleanse(inputBlock.data(), inputBlock.size());
    OPENSSL_cleanse(outputBlock.data(), outputBlock.size());
    if (!ok) {
        wipe(plainOut);
    }
    return ok;
}

Bytes encryptGcm(const Bytes& key, const Bytes& plain) {
    const Bytes iv = randomBytes(kGcmIvSize);
    CipherContext context(EVP_CIPHER_CTX_new());
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
                                       nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kGcmIvSize), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        return Bytes();
    }

    Bytes cipher(plain.size());
    int cipherLength = 0;
    if (!plain.empty() && EVP_EncryptUpdate(context.get(), cipher.data(), &cipherLength,
                                            plain.data(), static_cast<int>(plain.size())) != 1) {
        return Bytes();
    }
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(context.get(), nullptr, &finalLength) != 1) {
        return Bytes();
    }
    Bytes tag(kGcmTagSize);
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(kGcmTagSize), tag.data()) != 1) {
        return Bytes();
    }

    Bytes sealed;
    sealed.reserve(iv.size() + tag.size() + cipher.size());
    sealed.insert(sealed.end(), iv.begin(), iv.end());
    sealed.insert(sealed.end(), tag.begin(), tag.end());
    sealed.insert(sealed.end(), cipher.begin(), cipher.begin() + cipherLength);
    return sealed;
}

bool decryptGcm(const Bytes& key, const Bytes& sealed, std::string& plainOut) {
    plainOut.clear();
    if (sealed.size() < kGcmIvSize + kGcmTagSize) {
        return false;
    }
    const unsigned char* iv = sealed.data();
    Bytes tag(sealed.begin() + kGcmIvSize, sealed.begin() + kGcmIvSize + kGcmTagSize);
    const unsigned char* cipher = sealed.data() + kGcmIvSize + kGcmTagSize;
    const std::size_t cipherSize = sealed.size() - kGcmIvSize - kGcmTagSize;

    CipherContext context(EVP_CIPHER_CTX_new());
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
                                       nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kGcmIvSize), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv) != 1) {
        return false;
    }

    Bytes buffer(cipherSize + EVP_MAX_BLOCK_LENGTH);
    int bufferLength = 0;
    if (cipherSize > 0 && EVP_DecryptUpdate(context.get(), buffer.data(), &bufferLength,
                                            cipher, static_cast<int>(cipherSize)) != 1) {
        wipe(buffer);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(kGcmTagSize), tag.data()) != 1) {
        wipe(buffer);
        return false;
    }
    unsigned char scratch[EVP_MAX_BLOCK_LENGTH] = {};
    int finalLength = 0;

    const bool authentic = EVP_DecryptFinal_ex(context.get(), scratch, &finalLength) == 1;
    OPENSSL_cleanse(scratch, sizeof(scratch));
    if (!authentic) {
        wipe(buffer);
        return false;
    }
    plainOut.assign(reinterpret_cast<const char*>(buffer.data()),
                    static_cast<std::size_t>(bufferLength));
    wipe(buffer);
    return true;
}

std::string base64Encode(const Bytes& data) {
    if (data.empty()) {
        return std::string();
    }
    std::string encoded(4 * ((data.size() + 2) / 3) + 1, '\0');
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&encoded[0]),
                                        data.data(), static_cast<int>(data.size()));
    encoded.resize(static_cast<std::size_t>(written));
    return encoded;
}

bool base64Decode(const std::string& text, Bytes& out) {
    out.clear();
    if (text.empty()) {
        return true;
    }
    if (text.size() % 4 != 0) {
        return false;
    }
    Bytes buffer(text.size() / 4 * 3 + 3);
    const int decoded = EVP_DecodeBlock(buffer.data(),
                                        reinterpret_cast<const unsigned char*>(text.data()),
                                        static_cast<int>(text.size()));
    if (decoded < 0) {
        return false;
    }

    std::size_t padding = 0;
    if (text.back() == '=') {
        ++padding;
    }
    if (text.size() > 1 && text[text.size() - 2] == '=') {
        ++padding;
    }
    buffer.resize(static_cast<std::size_t>(decoded) - padding);
    out = buffer;
    wipe(buffer);
    return true;
}

Bytes randomBytes(std::size_t size) {
    Bytes bytes(size);
    if (size > 0 && RAND_bytes(bytes.data(), static_cast<int>(size)) != 1) {
        bytes.clear();
    }
    return bytes;
}

std::string sha256Hex(const unsigned char* data, std::size_t size) {
    static const char kHexDigits[] = "0123456789abcdef";
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;
    if (EVP_Digest(data, size, digest, &digestLength, EVP_sha256(), nullptr) != 1) {
        return std::string();
    }
    std::string hex;
    hex.reserve(digestLength * 2);
    for (unsigned int index = 0; index < digestLength; ++index) {
        hex.push_back(kHexDigits[digest[index] >> 4]);
        hex.push_back(kHexDigits[digest[index] & 0x0F]);
    }
    return hex;
}

void wipe(std::string& text) {
    if (!text.empty()) {
        OPENSSL_cleanse(&text[0], text.size());
    }
    text.clear();
}

void wipe(Bytes& bytes) {
    if (!bytes.empty()) {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }
    bytes.clear();
}

}
