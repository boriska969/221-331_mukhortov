cmake_minimum_required(VERSION 3.20)
project(credpolicy_lr4 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Опции сборки: санитайзеры (динамический анализ) и цель фаззинга AFL++.
option(LR4_SANITIZE "Собрать с AddressSanitizer и UndefinedBehaviorSanitizer" OFF)
option(LR4_FUZZ "Собрать фаззинг-harness для AFL++ (нужен afl-clang-fast++)" OFF)

if(LR4_SANITIZE)
    set(LR4_SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer
                            -fno-sanitize-recover=undefined)
    add_compile_options(${LR4_SANITIZER_FLAGS})
    add_link_options(${LR4_SANITIZER_FLAGS})
endif()

# Библиотека с модулем, который подвергается анализу.
add_library(credpolicy STATIC src/credential_policy.cpp)
target_include_directories(credpolicy PUBLIC include)
target_compile_options(credpolicy PRIVATE -Wall -Wextra -Wpedantic)

# Консольное приложение.
add_executable(credcheck app/main.cpp)
target_link_libraries(credcheck PRIVATE credpolicy)
target_compile_options(credcheck PRIVATE -Wall -Wextra -Wpedantic)

# Модульные тесты подключаются к сборке и запускаются через CTest.
enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(credpolicy_tests tests/credential_policy_test.cpp)
target_link_libraries(credpolicy_tests PRIVATE credpolicy GTest::gtest_main)

# CTest запускает набор тестов одним исполняемым файлом; подробный отчёт по
# каждому тесту печатает сам GoogleTest.
add_test(NAME credpolicy_unit_tests COMMAND credpolicy_tests)

# Фаззинг-harness (собирается только при -DLR4_FUZZ=ON).
if(LR4_FUZZ)
    add_executable(fuzz_parse fuzz/fuzz_parse.cpp)
    target_link_libraries(fuzz_parse PRIVATE credpolicy)
endif()
