#ifndef LR1_CRYPTO_UTILS_HPP
#define LR1_CRYPTO_UTILS_HPP

#include <cstddef>
#include <istream>
#include <string>
#include <vector>

namespace lr1 {

using Bytes = std::vector<unsigned char>;

constexpr std::size_t kKeySize = 32;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kCbcIvSize = 16;
constexpr std::size_t kGcmIvSize = 12;
constexpr std::size_t kGcmTagSize = 16;
constexpr std::size_t kReadBlockSize = 4096;
constexpr int kPbkdf2Iterations = 100000;

Bytes deriveKey(const std::string& pin, const Bytes& salt);

Bytes encryptCbc(const Bytes& key, const Bytes& iv, const Bytes& plain);

bool decryptCbcStreaming(const Bytes& key, const Bytes& iv, std::istream& input,
                         std::string& plainOut);

Bytes encryptGcm(const Bytes& key, const Bytes& plain);

bool decryptGcm(const Bytes& key, const Bytes& sealed, std::string& plainOut);

std::string base64Encode(const Bytes& data);

bool base64Decode(const std::string& text, Bytes& out);

Bytes randomBytes(std::size_t size);

std::string sha256Hex(const unsigned char* data, std::size_t size);

void wipe(std::string& text);

void wipe(Bytes& bytes);

}

#endif
