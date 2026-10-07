#ifndef CREDENTIAL_POLICY_HPP
#define CREDENTIAL_POLICY_HPP

#include <optional>
#include <string>

namespace credpolicy {

struct CredentialRecord {
    std::string site;
    std::string login;
    std::string password;
};

std::string validatePassword(const std::string& password);

std::optional<CredentialRecord> parseRecordLine(const std::string& line,
                                                std::string& error);

}

#endif
