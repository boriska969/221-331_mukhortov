#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>

#include "credential_policy.hpp"

namespace {

std::string maskPassword(const std::string& password) {
    return std::string(password.size(), '*');
}

std::size_t processStream(std::istream& input) {
    std::size_t problems = 0;
    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            continue;
        }

        std::string error;
        const auto record = credpolicy::parseRecordLine(line, error);
        if (!record) {
            ++problems;
            std::cout << "[line " << lineNumber << "] REJECTED: " << error << '\n';
            continue;
        }

        const std::string policyError = credpolicy::validatePassword(record->password);
        if (policyError.empty()) {
            std::cout << "[line " << lineNumber << "] OK site=" << record->site
                      << " login=" << record->login
                      << " password=" << maskPassword(record->password) << '\n';
        } else {
            ++problems;
            std::cout << "[line " << lineNumber << "] WEAK PASSWORD: " << policyError
                      << " (site=" << record->site << ")\n";
        }
    }
    return problems;
}

}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        processStream(std::cin);
        return 0;
    }
    std::ifstream file(argv[1]);
    if (!file) {
        std::cerr << "cannot open file: " << argv[1] << '\n';
        return 2;
    }
    const std::size_t problems = processStream(file);
    std::cout << "problems found: " << problems << '\n';
    return 0;
}
