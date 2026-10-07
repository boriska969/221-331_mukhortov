#include <cstddef>
#include <cstdio>
#include <cstring>

bool storeLogin(const char* login, std::size_t length) {
    char buffer[16];
    if (length <= sizeof(buffer)) {
        std::memcpy(buffer, login, length);
        buffer[length] = '\0';
        std::printf("stored: %s\n", buffer);
        return true;
    }
    return false;
}

int main() {

    storeLogin("abcdefghijklmnop", 16);
    return 0;
}
