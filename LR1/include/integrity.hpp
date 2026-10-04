// integrity.hpp
// Защита от отладки и модификации (ЛР1, этап 2):
//   - IsDebuggerPresent() - обнаружение отладчика (пункт 3 задания);
//   - самопроверка SHA-256 сегмента .text текущего исполняемого файла (пункт 5).
#ifndef LR1_INTEGRITY_HPP
#define LR1_INTEGRITY_HPP

#include <string>

namespace lr1 {

// Возвращает true, если к процессу подключён отладчик (WinAPI IsDebuggerPresent()).
bool isDebuggerAttached();

// Вычисляет SHA-256 от сегмента .text текущего образа в памяти.
// Начало и размер сегмента берутся из PE-заголовков (VirtualAddress и VirtualSize).
// hexOut - сюда записывается хеш в виде 64 шестнадцатеричных символов;
// error  - причина ошибки при неудаче.
// Возвращает false, если заголовки PE не удалось разобрать.
bool computeTextSegmentHash(std::string& hexOut, std::string& error);

// Сравнивает хеш сегмента .text с эталонным значением, записанным в образ
// скриптом tools/patch_text_hash.py после сборки.
// error - причина несовпадения (пусто при успехе).
// Возвращает true, если сегмент не изменён.
bool isTextSegmentIntact(std::string& error);

}  // namespace lr1

#endif  // LR1_INTEGRITY_HPP
