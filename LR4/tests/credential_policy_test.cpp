// credential_policy_test.cpp
// Модульные тесты (GoogleTest) для функций validatePassword() и parseRecordLine().
// Для каждой функции написано по два позитивных и два негативных тестовых случая.
// Описание объекта проверки, входных данных и ожидаемого результата дано
// в комментарии перед каждым тестом.
#include <gtest/gtest.h>

#include <string>

#include "credential_policy.hpp"

namespace {

using credpolicy::parseRecordLine;
using credpolicy::validatePassword;

}  // namespace

// Объект проверки: validatePassword().
// Вход: "Correct-Horse-42!" (17 символов, есть все классы символов).
// Ожидаемый результат: пустая строка, пароль принят.
TEST(ValidatePasswordTest, AcceptsPasswordThatMeetsAllRules) {
    EXPECT_EQ(validatePassword("Correct-Horse-42!"), "");
}

// Объект проверки: validatePassword().
// Вход: "Tr0ub4dor&3xyz" (14 символов, спецсимвол '&', цифры, буквы разного регистра).
// Ожидаемый результат: пустая строка, пароль принят.
TEST(ValidatePasswordTest, AcceptsAnotherCompliantPassword) {
    EXPECT_EQ(validatePassword("Tr0ub4dor&3xyz"), "");
}

// Объект проверки: validatePassword().
// Вход: "Short1!" (7 символов, меньше минимальных 12).
// Ожидаемый результат: отказ, причина содержит фразу "shorter than".
TEST(ValidatePasswordTest, RejectsPasswordShorterThanMinimum) {
    EXPECT_NE(validatePassword("Short1!").find("shorter than"), std::string::npos);
}

// Объект проверки: validatePassword().
// Вход: "NoDigitsHere!!" (14 символов, но ни одной цифры).
// Ожидаемый результат: отказ с причиной "password has no digit".
TEST(ValidatePasswordTest, RejectsPasswordWithoutDigit) {
    EXPECT_EQ(validatePassword("NoDigitsHere!!"), "password has no digit");
}

// Объект проверки: parseRecordLine().
// Вход: "https://example.com;alice;Correct-Horse-42!" (корректная строка из трёх полей).
// Ожидаемый результат: запись разобрана, поля совпадают с исходными значениями, error пуст.
TEST(ParseRecordLineTest, ParsesWellFormedLine) {
    std::string error;
    const auto record = parseRecordLine("https://example.com;alice;Correct-Horse-42!", error);
    ASSERT_TRUE(record.has_value());
    EXPECT_TRUE(error.empty());
    EXPECT_EQ(record->site, "https://example.com");
    EXPECT_EQ(record->login, "alice");
    EXPECT_EQ(record->password, "Correct-Horse-42!");
}

// Объект проверки: parseRecordLine().
// Вход: "  https://bank.example.org ; bob ; Tr0ub4dor&3xyz  " (пробелы по краям полей).
// Ожидаемый результат: запись разобрана, пробелы по краям полей удалены.
TEST(ParseRecordLineTest, TrimsWhitespaceAroundFields) {
    std::string error;
    const auto record = parseRecordLine("  https://bank.example.org ; bob ; Tr0ub4dor&3xyz  ", error);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->site, "https://bank.example.org");
    EXPECT_EQ(record->login, "bob");
    EXPECT_EQ(record->password, "Tr0ub4dor&3xyz");
}

// Объект проверки: parseRecordLine().
// Вход: "https://example.com;alice" (два поля вместо трёх).
// Ожидаемый результат: отказ, причина "expected three fields separated by ';'".
TEST(ParseRecordLineTest, RejectsLineWithMissingField) {
    std::string error;
    EXPECT_FALSE(parseRecordLine("https://example.com;alice", error).has_value());
    EXPECT_EQ(error, "expected three fields separated by ';'");
}

// Объект проверки: parseRecordLine().
// Вход: "http://example.com;alice;Correct-Horse-42!" (протокол http вместо https).
// Ожидаемый результат: отказ, причина "site must start with https:// and contain a host".
TEST(ParseRecordLineTest, RejectsNonHttpsSite) {
    std::string error;
    EXPECT_FALSE(parseRecordLine("http://example.com;alice;Correct-Horse-42!", error).has_value());
    EXPECT_EQ(error, "site must start with https:// and contain a host");
}
