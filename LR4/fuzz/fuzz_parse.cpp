// fuzz_parse.cpp
// Фаззинг-harness для AFL++: читает байты из стандартного ввода, ограничивает
// размер входа 64 КиБ и передаёт данные в parseRecordLine(). Если разбор успешен,
// дополнительно вызывается validatePassword(). Аварийное завершение процесса
// (сегментация, выход за границу буфера, неопределённое поведение) фиксирует AFL++.
#include <cstddef>
#include <iostream>
#include <iterator>
#include <string>

#include "credential_policy.hpp"

namespace {

// Максимальный размер входа, который передаётся в модуль.
constexpr std::size_t kMaxInputSize = 64 * 1024;

}  // namespace

// Точка входа harness-а. Читает весь стандартный ввод и запускает разбор.
// Возвращает 0 в любом штатном случае.
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
