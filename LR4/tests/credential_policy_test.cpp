#include <gtest/gtest.h>

#include <string>

#include "credential_policy.hpp"

namespace {

using credpolicy::parseRecordLine;
using credpolicy::validatePassword;

}

TEST(ValidatePasswordTest, AcceptsPasswordThatMeetsAllRules) {
    EXPECT_EQ(validatePassword("Correct-Horse-42!"), "");
}

TEST(ValidatePasswordTest, AcceptsAnotherCompliantPassword) {
    EXPECT_EQ(validatePassword("Tr0ub4dor&3xyz"), "");
}

TEST(ValidatePasswordTest, RejectsPasswordShorterThanMinimum) {
    EXPECT_NE(validatePassword("Short1!").find("shorter than"), std::string::npos);
}

TEST(ValidatePasswordTest, RejectsPasswordWithoutDigit) {
    EXPECT_EQ(validatePassword("NoDigitsHere!!"), "password has no digit");
}

TEST(ParseRecordLineTest, ParsesWellFormedLine) {
    std::string error;
    const auto record = parseRecordLine("https://example.com;alice;Correct-Horse-42!", error);
    ASSERT_TRUE(record.has_value());
    EXPECT_TRUE(error.empty());
    EXPECT_EQ(record->site, "https://example.com");
    EXPECT_EQ(record->login, "alice");
    EXPECT_EQ(record->password, "Correct-Horse-42!");
}

TEST(ParseRecordLineTest, TrimsWhitespaceAroundFields) {
    std::string error;
    const auto record = parseRecordLine("  https://bank.example.org ; bob ; Tr0ub4dor&3xyz  ", error);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->site, "https://bank.example.org");
    EXPECT_EQ(record->login, "bob");
    EXPECT_EQ(record->password, "Tr0ub4dor&3xyz");
}

TEST(ParseRecordLineTest, RejectsLineWithMissingField) {
    std::string error;
    EXPECT_FALSE(parseRecordLine("https://example.com;alice", error).has_value());
    EXPECT_EQ(error, "expected three fields separated by ';'");
}

TEST(ParseRecordLineTest, RejectsNonHttpsSite) {
    std::string error;
    EXPECT_FALSE(parseRecordLine("http://example.com;alice;Correct-Horse-42!", error).has_value());
    EXPECT_EQ(error, "site must start with https:// and contain a host");
}
