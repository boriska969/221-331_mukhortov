#include "credential_policy.hpp"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace credpolicy {
namespace {

constexpr std::size_t kMinPasswordLength = 12;
constexpr std::size_t kMaxPasswordLength = 128;
constexpr std::size_t kMaxLoginLength = 64;

constexpr std::size_t kMaxRunLength = 3;
constexpr char kFieldSeparator = ';';
constexpr std::string_view kSpecialSymbols = "!@#$%^&*()-_=+[]{}:,.<>/?|~";
constexpr std::string_view kSitePrefix = "https://";
constexpr std::string_view kTrimSet = " \t\r\n";

bool isSpecialSymbol(char symbol) {
    return kSpecialSymbols.find(symbol) != std::string_view::npos;
}

std::string trimWhitespace(const std::string& text) {
    const std::size_t first = text.find_first_not_of(kTrimSet);
    if (first == std::string::npos) {
        return std::string();
    }
    const std::size_t last = text.find_last_not_of(kTrimSet);
    return text.substr(first, last - first + 1);
}

bool hasLongRun(const std::string& text) {
    std::size_t run = 0;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const bool continuesRun = index > 0 && text[index] == text[index - 1];
        run = continuesRun ? run + 1 : 1;
        if (run > kMaxRunLength) {
            return true;
        }
    }
    return false;
}

}

std::string validatePassword(const std::string& password) {
    if (password.size() < kMinPasswordLength) {
        return "password is shorter than " + std::to_string(kMinPasswordLength) +
               " characters";
    }
    if (password.size() > kMaxPasswordLength) {
        return "password is longer than " + std::to_string(kMaxPasswordLength) +
               " characters";
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    for (const char symbol : password) {
        const auto code = static_cast<unsigned char>(symbol);
        if (std::isspace(code) != 0) {
            return "password contains whitespace";
        }
        hasUpper = hasUpper || std::isupper(code) != 0;
        hasLower = hasLower || std::islower(code) != 0;
        hasDigit = hasDigit || std::isdigit(code) != 0;
        hasSpecial = hasSpecial || isSpecialSymbol(symbol);
    }

    if (!hasUpper) {
        return "password has no uppercase letter";
    }
    if (!hasLower) {
        return "password has no lowercase letter";
    }
    if (!hasDigit) {
        return "password has no digit";
    }
    if (!hasSpecial) {
        return "password has no special symbol";
    }
    if (hasLongRun(password)) {
        return "password has a run of identical characters";
    }
    return std::string();
}

std::optional<CredentialRecord> parseRecordLine(const std::string& line,
                                                std::string& error) {
    error.clear();
    const std::string content = trimWhitespace(line);
    if (content.empty()) {
        error = "line is empty";
        return std::nullopt;
    }

    const std::size_t firstSeparator = content.find(kFieldSeparator);
    const std::size_t secondSeparator =
        firstSeparator == std::string::npos
            ? std::string::npos
            : content.find(kFieldSeparator, firstSeparator + 1);
    if (secondSeparator == std::string::npos) {
        error = "expected three fields separated by ';'";
        return std::nullopt;
    }
    if (content.find(kFieldSeparator, secondSeparator + 1) != std::string::npos) {
        error = "too many fields: ';' is not allowed inside a value";
        return std::nullopt;
    }

    CredentialRecord record;
    record.site = trimWhitespace(content.substr(0, firstSeparator));
    record.login = trimWhitespace(
        content.substr(firstSeparator + 1, secondSeparator - firstSeparator - 1));
    record.password = trimWhitespace(content.substr(secondSeparator + 1));

    const bool hasPrefix = record.site.compare(0, kSitePrefix.size(), kSitePrefix) == 0;
    if (!hasPrefix || record.site.size() <= kSitePrefix.size()) {
        error = "site must start with https:// and contain a host";
        return std::nullopt;
    }
    if (record.login.empty() || record.login.size() > kMaxLoginLength) {
        error = "login must contain 1..64 characters";
        return std::nullopt;
    }
    if (record.login.find_first_of(" \t") != std::string::npos) {
        error = "login must not contain whitespace";
        return std::nullopt;
    }
    if (record.password.empty()) {
        error = "password is empty";
        return std::nullopt;
    }
    return record;
}

}
