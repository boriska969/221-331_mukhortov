#include <cstddef>
#include <iostream>
#include <iterator>
#include <string>

#include "credential_policy.hpp"

namespace {

constexpr std::size_t kMaxInputSize = 64 * 1024;

}

int main() {
    const std::string input((std::istreambuf_iterator<char>(std::cin)),
                            std::istreambuf_iterator<char>());
    if (input.size() > kMaxInputSize) {
        return 0;
    }

    std::string error;
    const auto record = credpolicy::parseRecordLine(input, error);
    if (record) {
        static_cast<void>(credpolicy::validatePassword(record->password));
    }
    return 0;
}
