// credential_vault.hpp
// Хранилище учётных записей ЛР1: загрузка зашифрованного файла и выборочная расшифровка полей.
//
// Формат файла credentials.bin:
//   магическая строка "LR1CRED1" (8 байт) | соль слоя 1 (16) | IV слоя 1 (16) | шифртекст AES-256-CBC
// После расшифровки слоя 1 получается JSON:
//   {"format": "LR1-VAULT-1", "kdf2_salt": "<base64>", "entries": [
//       {"url": "https://...", "login": "<base64 iv|tag|ct>", "password": "<base64 iv|tag|ct>"}, ...]}
// URL хранится в открытом виде, логин и пароль зашифрованы слоем 2 (AES-256-GCM).
#ifndef LR1_CREDENTIAL_VAULT_HPP
#define LR1_CREDENTIAL_VAULT_HPP

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace lr1 {

constexpr char kFileMagic[] = "LR1CRED1";
constexpr std::size_t kFileMagicSize = 8;
constexpr char kVaultFormat[] = "LR1-VAULT-1";

// Одна учётная запись в памяти приложения.
struct VaultEntry {
    std::string url;       // адрес сайта в открытом виде
    Bytes loginSealed;     // логин в виде iv|tag|шифртекст (слой 2)
    Bytes passwordSealed;  // пароль в виде iv|tag|шифртекст (слой 2)
};

// Какое поле записи нужно расшифровать.
enum class Field { Login, Password };

class CredentialVault {
public:
    // Читает файл, выводит ключ слоя 1 из пин-кода, расшифровывает файл блоками
    // и разбирает JSON. Открытый текст файла не записывается на диск.
    // path  - путь к файлу credentials.bin (поддерживаются не-ASCII пути);
    // pin   - пин-код, введённый пользователем;
    // error - сюда записывается причина неудачи.
    // Возвращает true, если файл расшифрован и JSON корректен.
    bool load(const std::filesystem::path& path, const std::string& pin, std::string& error);

    // Расшифровывает логин или пароль записи index слоем 2.
    // index - номер записи; field - нужное поле; pin - пин-код для вывода ключа слоя 2;
    // value - сюда записывается открытое значение.
    // Возвращает false, если пин-код неверен или индекс вне диапазона.
    bool reveal(std::size_t index, Field field, const std::string& pin, std::string& value) const;

    // Возвращает все записи в открытом виде URL и зашифрованные поля.
    const std::vector<VaultEntry>& entries() const;

    // Очищает записи и соль из памяти.
    void clear();

private:
    std::vector<VaultEntry> entries_;
    Bytes layer2Salt_;
};

}  // namespace lr1

#endif  // LR1_CREDENTIAL_VAULT_HPP
