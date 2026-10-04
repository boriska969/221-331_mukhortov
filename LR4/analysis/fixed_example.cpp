// fixed_example.cpp
// Исправленная версия файла unsafe_example.cpp: условие сделано строгим,
// поэтому завершающий нуль всегда помещается в буфер.
#include <cstddef>
#include <cstdio>
#include <cstring>

// Копирует логин во внутренний буфер фиксированного размера 16 байт.
// login  - исходная строка с логином;
// length - длина логина без завершающего нуля.
// Исправление: условие length < sizeof(buffer) гарантирует, что индекс
// buffer[length] не выходит за границы массива (максимум buffer[15]).
// Возвращает true, если логин сохранён.
bool storeLogin(const char* login, std::size_t length) {
    char buffer[16];
    if (length < sizeof(buffer)) {
        std::memcpy(buffer, login, length);
        buffer[length] = '\0';
        std::printf("stored: %s\n", buffer);
        return true;
    }
    return false;
}

int main() {
    // Граничный случай: логин из 16 символов теперь отклоняется.
    storeLogin("abcdefghijklmnop", 16);
    return 0;
}
