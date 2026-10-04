// credential_vault.cpp
// Реализация хранилища учётных записей: загрузка файла, слой 1 и слой 2 шифрования.
#include "credential_vault.hpp"

#include <cstring>
#include <fstream>

#include <nlohmann/json.hpp>

namespace lr1 {
namespace {

// Читает заголовок файла: магическая строка, соль слоя 1 и IV слоя 1.
// file   - открытый бинарный поток;
// salt   - сюда записывается соль PBKDF2;
// iv     - сюда записывается вектор инициализации CBC.
// Возвращает false, если заголовок неполный или магическая строка не совпадает.
bool readHeader(std::istream& file, Bytes& salt, Bytes& iv) {
    char magic[kFileMagicSize] = {};
    file.read(magic, static_cast<std::streamsize>(kFileMagicSize));
    if (file.gcount() != static_cast<std::streamsize>(kFileMagicSize) ||
        std::memcmp(magic, kFileMagic, kFileMagicSize) != 0) {
        return false;
    }
    salt.assign(kSaltSize, 0);
    iv.assign(kCbcIvSize, 0);
    file.read(reinterpret_cast<char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
    if (file.gcount() != static_cast<std::streamsize>(salt.size())) {
        return false;
    }
    file.read(reinterpret_cast<char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
    return file.gcount() == static_cast<std::streamsize>(iv.size());
}

// Возвращает строку из JSON-объекта или пустую строку, если поля нет или оно не строка.
std::string stringField(const nlohmann::json& object, const char* name) {
    const auto found = object.find(name);
    if (found == object.end() || !found->is_string()) {
        return std::string();
    }
    return found->get<std::string>();
}

}  // namespace

bool CredentialVault::load(const std::filesystem::path& path, const std::string& pin, std::string& error) {
    error.clear();
    clear();

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "не удалось открыть файл учётных данных";
        return false;
    }
    Bytes salt;
    Bytes iv;
    if (!readHeader(file, salt, iv)) {
        error = "файл учётных данных повреждён (неверный заголовок)";
        return false;
    }

    // Слой 1: ключ выводится из пин-кода, файл расшифровывается блоками в памяти.
    Bytes key = deriveKey(pin, salt);
    std::string plainJson;
    const bool decrypted = !key.empty() && decryptCbcStreaming(key, iv, file, plainJson);
    wipe(key);
    if (!decrypted) {
        error = "неверный пин-код";
        return false;
    }

    // Неверный пин-код даёт мусор после расшифровки, поэтому JSON служит проверкой пин-кода.
    nlohmann::json document = nlohmann::json::parse(plainJson, nullptr, false);
    wipe(plainJson);
    if (document.is_discarded() || !document.is_object() ||
        stringField(document, "format") != kVaultFormat) {
        error = "неверный пин-код или файл повреждён (JSON не разобран)";
        return false;
    }

    if (!base64Decode(stringField(document, "kdf2_salt"), layer2Salt_) ||
        layer2Salt_.size() != kSaltSize) {
        clear();
        error = "файл учётных данных повреждён (соль слоя 2)";
        return false;
    }

    const auto found = document.find("entries");
    if (found == document.end() || !found->is_array()) {
        clear();
        error = "файл учётных данных повреждён (нет списка записей)";
        return false;
    }
    for (const nlohmann::json& item : *found) {
        VaultEntry entry;
        entry.url = stringField(item, "url");
        if (!base64Decode(stringField(item, "login"), entry.loginSealed) ||
            !base64Decode(stringField(item, "password"), entry.passwordSealed) ||
            entry.url.empty()) {
            clear();
            error = "файл учётных данных повреждён (запись не разобрана)";
            return false;
        }
        entries_.push_back(entry);
    }
    return true;
}

bool CredentialVault::reveal(std::size_t index, Field field, const std::string& pin,
                             std::string& value) const {
    value.clear();
    if (index >= entries_.size()) {
        return false;
    }
    // Слой 2: ключ выводится из того же пин-кода, но с отдельной солью.
    Bytes key = deriveKey(pin, layer2Salt_);
    if (key.empty()) {
        return false;
    }
    const VaultEntry& entry = entries_[index];
    const Bytes& sealed = (field == Field::Login) ? entry.loginSealed : entry.passwordSealed;
    const bool ok = decryptGcm(key, sealed, value);
    wipe(key);
    return ok;
}

const std::vector<VaultEntry>& CredentialVault::entries() const {
    return entries_;
}

void CredentialVault::clear() {
    for (VaultEntry& entry : entries_) {
        wipe(entry.loginSealed);
        wipe(entry.passwordSealed);
    }
    entries_.clear();
    wipe(layer2Salt_);
}

}  // namespace lr1
