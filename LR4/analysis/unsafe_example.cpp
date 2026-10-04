// unsafe_example.cpp
// Демонстрационный файл с намеренно внесённой ошибкой (выход за границу буфера).
// Нужен только для проверки того, что статический анализатор (cppcheck) и
// динамический анализатор (AddressSanitizer) находят ошибку. В рабочий модуль
// credpolicy этот файл не входит.
#include <cstddef>
#include <cstdio>
#include <cstring>

// Копирует логин во внутренний буфер фиксированного размера 16 байт.
// login  - исходная строка с логином;
// length - длина логина без завершающего нуля.
// Ошибка: условие length <= sizeof(buffer) допускает length == 16, после чего
// завершающий нуль записывается в buffer[16], то есть за пределы массива.
// Возвращает true, если логин сохранён.
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
    // Граничный случай: логин ровно из 16 символов.
    storeLogin("abcdefghijklmnop", 16);
    return 0;
}
