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

struct VaultEntry {
    std::string url;
    Bytes loginSealed;
    Bytes passwordSealed;
};

enum class Field { Login, Password };

class CredentialVault {
public:

    bool load(const std::filesystem::path& path, const std::string& pin, std::string& error);

    bool reveal(std::size_t index, Field field, const std::string& pin, std::string& value) const;

    const std::vector<VaultEntry>& entries() const;

    void clear();

private:
    std::vector<VaultEntry> entries_;
    Bytes layer2Salt_;
};

}

#endif
