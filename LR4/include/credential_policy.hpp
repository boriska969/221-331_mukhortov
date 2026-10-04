// credential_policy.hpp
// Модуль проверки учётных записей: политика паролей и разбор строк записей.
// Модуль используется в ЛР4 (модульное тестирование, статический и динамический
// анализ, фаззинг, CI/CD) и рассчитан на работу из командной строки.
#ifndef CREDENTIAL_POLICY_HPP
#define CREDENTIAL_POLICY_HPP

#include <optional>
#include <string>

namespace credpolicy {

// Одна учётная запись: адрес сайта, логин и пароль.
struct CredentialRecord {
    std::string site;      // адрес вида https://host
    std::string login;     // логин без пробельных символов, длина 1..64
    std::string password;  // пароль, проверяется функцией validatePassword()
};

// Проверяет пароль по политике безопасности:
// длина 12..128 символов; есть строчная и заглавная буквы, цифра и спецсимвол;
// нет пробельных символов и цепочек из четырёх одинаковых символов подряд.
// password - проверяемый пароль.
// Возвращает пустую строку, если пароль соответствует политике,
// иначе - текст причины отказа.
std::string validatePassword(const std::string& password);

// Разбирает строку вида "https://host;login;password".
// Поля разделяются символом ';', пробелы по краям полей отбрасываются.
// line  - строка записи;
// error - при ошибке сюда записывается причина, при успехе очищается.
// Возвращает запись либо std::nullopt, если формат строки нарушен.
std::optional<CredentialRecord> parseRecordLine(const std::string& line,
                                                std::string& error);

}  // namespace credpolicy

#endif  // CREDENTIAL_POLICY_HPP
