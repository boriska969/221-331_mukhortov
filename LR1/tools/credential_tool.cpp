#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

#include "credential_vault.hpp"
#include "crypto_utils.hpp"

namespace {

struct DemoRecord {
    const char* url;
    const char* login;
    const char* password;
};

const DemoRecord kDemoRecords[] = {
    {"https://mail.example.com", "alice.morgan", "Vq7#mLx2!tRp"},
    {"https://bank.example.org", "bkaramov", "Krt9$wYe4@Lzn"},
    {"https://forum.example.net", "night_owl_77", "Plm3&zQe8?Vna"},
    {"https://shop.example.com", "j.petrova", "Hd5*nRt2%Woq"},
    {"https://cloud.example.org", "dev-team-01", "Zx8!cVb4#Mkl"},
    {"https://news.example.net", "reader_42", "Tg6$pLo1^Sdf"},
    {"https://travel.example.com", "ivan.k", "Wq2@eRt7&Yuz"},
    {"https://game.example.org", "shadow_fox", "Mn4#bVc9*Xas"},
    {"https://school.example.edu", "student.nn", "Lk7%hGf3!Qwe"},
    {"https://music.example.com", "melody_lover", "Bv5^nMx8?Rty"},
    {"https://health.example.org", "patient.r", "Ds9&kJl2#Uio"},
    {"https://office.example.com", "admin.office", "Ty3*gHj6@Pxc"},
};

std::string toUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0],
                        length, nullptr, nullptr);
    return result;
}

bool createVaultFile(const std::string& pin, const std::filesystem::path& outputPath) {
    const lr1::Bytes layer2Salt = lr1::randomBytes(lr1::kSaltSize);
    lr1::Bytes layer2Key = lr1::deriveKey(pin, layer2Salt);
    if (layer2Key.empty()) {
        return false;
    }

    nlohmann::json entries = nlohmann::json::array();
    for (const DemoRecord& record : kDemoRecords) {
        const lr1::Bytes login(record.login, record.login + std::strlen(record.login));
        const lr1::Bytes password(record.password, record.password + std::strlen(record.password));
        const lr1::Bytes loginSealed = lr1::encryptGcm(layer2Key, login);
        const lr1::Bytes passwordSealed = lr1::encryptGcm(layer2Key, password);
        if (loginSealed.empty() || passwordSealed.empty()) {
            lr1::wipe(layer2Key);
            return false;
        }
        entries.push_back({{"url", record.url},
                           {"login", lr1::base64Encode(loginSealed)},
                           {"password", lr1::base64Encode(passwordSealed)}});
    }
    lr1::wipe(layer2Key);

    const nlohmann::json document = {{"format", lr1::kVaultFormat},
                                     {"kdf2_salt", lr1::base64Encode(layer2Salt)},
                                     {"entries", entries}};
    const std::string plainJson = document.dump();
    const lr1::Bytes plain(plainJson.begin(), plainJson.end());

    const lr1::Bytes salt1 = lr1::randomBytes(lr1::kSaltSize);
    const lr1::Bytes iv1 = lr1::randomBytes(lr1::kCbcIvSize);
    lr1::Bytes key1 = lr1::deriveKey(pin, salt1);
    if (key1.empty()) {
        return false;
    }
    const lr1::Bytes cipher = lr1::encryptCbc(key1, iv1, plain);
    lr1::wipe(key1);
    if (cipher.empty()) {
        return false;
    }

    std::ofstream output(outputPath, std::ios::binary);
    if (!output) {
        return false;
    }
    output.write(lr1::kFileMagic, static_cast<std::streamsize>(lr1::kFileMagicSize));
    output.write(reinterpret_cast<const char*>(salt1.data()), static_cast<std::streamsize>(salt1.size()));
    output.write(reinterpret_cast<const char*>(iv1.data()), static_cast<std::streamsize>(iv1.size()));
    output.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
    return output.good();
}

int checkVaultFile(const std::string& pin, const std::filesystem::path& inputPath) {
    lr1::CredentialVault vault;
    std::string error;
    if (!vault.load(inputPath, pin, error)) {
        std::printf("LOAD FAILED: %s\n", error.c_str());
        return 1;
    }
    std::string login;
    const bool revealed = !vault.entries().empty() &&
                          vault.reveal(0, lr1::Field::Login, pin, login);
    std::printf("LOAD OK: %zu records decrypted (layer 1)\n", vault.entries().size());
    if (revealed) {
        std::printf("first record: url=%s login=%s (layer 2 OK)\n",
                    vault.entries()[0].url.c_str(), login.c_str());
    }
    lr1::wipe(login);
    vault.clear();
    return 0;
}

}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 4) {
        std::printf("usage: CredentialTool create|check <pin> <file>\n");
        return 2;
    }
    const std::string command = toUtf8(argv[1]);
    const std::string pin = toUtf8(argv[2]);
    const std::filesystem::path path = std::filesystem::path(argv[3]);
    if (pin.size() < 4) {
        std::printf("pin must contain at least 4 characters\n");
        return 2;
    }
    if (command == "create") {
        if (!createVaultFile(pin, path)) {
            std::printf("CREATE FAILED\n");
            return 1;
        }
        std::printf("CREATE OK: %s, %ju bytes, %zu records\n", path.string().c_str(),
                    static_cast<std::uintmax_t>(std::filesystem::file_size(path)),
                    sizeof(kDemoRecords) / sizeof(kDemoRecords[0]));
        return 0;
    }
    if (command == "check") {
        return checkVaultFile(pin, path);
    }
    std::printf("unknown command: %s\n", command.c_str());
    return 2;
}
