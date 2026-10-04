// crypto_utils.hpp
// Криптографические примитивы ЛР1 на основе OpenSSL:
//   - PBKDF2-HMAC-SHA256: вывод ключа AES-256 из короткого пин-кода;
//   - AES-256-CBC: слой 1 - шифрование всего файла учётных данных;
//   - AES-256-GCM: слой 2 - шифрование логина и пароля отдельной записи;
//   - base64, SHA-256 и очистка секретов из памяти.
#ifndef LR1_CRYPTO_UTILS_HPP
#define LR1_CRYPTO_UTILS_HPP

#include <cstddef>
#include <istream>
#include <string>
#include <vector>

namespace lr1 {

using Bytes = std::vector<unsigned char>;

constexpr std::size_t kKeySize = 32;          // AES-256: ключ 32 байта
constexpr std::size_t kSaltSize = 16;         // соль PBKDF2
constexpr std::size_t kCbcIvSize = 16;        // вектор инициализации CBC (размер блока AES)
constexpr std::size_t kGcmIvSize = 12;        // nonce GCM (рекомендуемый размер)
constexpr std::size_t kGcmTagSize = 16;       // тег аутентификации GCM
constexpr std::size_t kReadBlockSize = 4096;  // размер блока, который читается из файла за раз
constexpr int kPbkdf2Iterations = 100000;     // число итераций PBKDF2

// Выводит ключ AES-256 из пин-кода функцией PBKDF2-HMAC-SHA256.
// pin  - пин-код (короткий мастер-пароль) пользователя;
// salt - соль длиной kSaltSize байт; хранится в файле и не является секретом.
// Возвращает ключ длиной kKeySize байт или пустой вектор при ошибке OpenSSL.
Bytes deriveKey(const std::string& pin, const Bytes& salt);

// Шифрует буфер AES-256-CBC с паддингом PKCS#7 (используется при создании файла).
// key   - ключ AES-256 (kKeySize байт);
// iv    - вектор инициализации (kCbcIvSize байт);
// plain - открытый текст.
// Возвращает шифртекст или пустой вектор при ошибке.
Bytes encryptCbc(const Bytes& key, const Bytes& iv, const Bytes& plain);

// Расшифровывает поток AES-256-CBC блоками: EVP_DecryptUpdate вызывается в цикле
// для каждого блока, прочитанного из входного потока, поэтому размер файла не ограничен.
// Открытый текст накапливается только в памяти и никогда не записывается на диск.
// key       - ключ AES-256;
// iv        - вектор инициализации;
// input     - поток с шифртекстом (после заголовка файла);
// plainOut  - сюда записывается открытый текст.
// Возвращает false, если паддинг некорректен (признак неверного ключа или повреждения).
bool decryptCbcStreaming(const Bytes& key, const Bytes& iv, std::istream& input,
                         std::string& plainOut);

// Шифрует строку AES-256-GCM (слой 2) со случайным nonce.
// key   - ключ AES-256;
// plain - открытый текст поля (логин или пароль).
// Возвращает блок вида iv|tag|шифртекст или пустой вектор при ошибке.
Bytes encryptGcm(const Bytes& key, const Bytes& plain);

// Расшифровывает блок iv|tag|шифртекст (слой 2) и проверяет тег аутентификации.
// key      - ключ AES-256;
// sealed   - блок, созданный encryptGcm();
// plainOut - сюда записывается открытый текст поля.
// Возвращает false, если тег не совпал (неверный пин-код или повреждение данных).
bool decryptGcm(const Bytes& key, const Bytes& sealed, std::string& plainOut);

// Кодирует данные в base64 (стандартный алфавит с дополнением '=').
std::string base64Encode(const Bytes& data);

// Декодирует base64 в байты. Возвращает false, если строка некорректна.
bool base64Decode(const std::string& text, Bytes& out);

// Возвращает size байт криптографически стойкой случайной последовательности (RAND_bytes).
Bytes randomBytes(std::size_t size);

// Вычисляет SHA-256 от буфера и возвращает результат в виде 64 шестнадцатеричных символов.
// data - буфер; size - его размер в байтах.
std::string sha256Hex(const unsigned char* data, std::size_t size);

// Затирает строку нулями (OPENSSL_cleanse), чтобы секрет не остался в памяти.
void wipe(std::string& text);

// Затирает байтовый буфер нулями (OPENSSL_cleanse).
void wipe(Bytes& bytes);

}  // namespace lr1

#endif  // LR1_CRYPTO_UTILS_HPP
