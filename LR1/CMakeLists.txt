cmake_minimum_required(VERSION 3.20)
project(lr1_pass_manager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Пункт 3 задания: проверка IsDebuggerPresent() при запуске. Для самоотладки (пункт 4)
# проверку выключают: протектор сам подключён отладчиком, и IsDebuggerPresent() вернул бы true.
option(LR1_CHECK_IS_DEBUGGER_PRESENT "Проверять IsDebuggerPresent() при запуске PassManager" OFF)

# Каталог с OpenSSL (include, lib, bin) и nlohmann/json (include). Для MSYS2: C:/msys64/ucrt64.
set(LR1_DEPS_ROOT "" CACHE PATH "Каталог с OpenSSL и nlohmann/json (например, C:/msys64/ucrt64)")
if(NOT LR1_DEPS_ROOT)
    message(FATAL_ERROR "Укажите каталог зависимостей: -DLR1_DEPS_ROOT=<путь к OpenSSL и nlohmann/json>")
endif()

find_path(LR1_OPENSSL_INCLUDE openssl/evp.h PATHS "${LR1_DEPS_ROOT}/include" NO_DEFAULT_PATH REQUIRED)
find_path(LR1_JSON_INCLUDE nlohmann/json.hpp PATHS "${LR1_DEPS_ROOT}/include" NO_DEFAULT_PATH REQUIRED)
find_library(LR1_LIBCRYPTO NAMES libcrypto.dll.a libcrypto PATHS "${LR1_DEPS_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)
find_file(LR1_LIBCRYPTO_DLL NAMES libcrypto-3-x64.dll PATHS "${LR1_DEPS_ROOT}/bin" NO_DEFAULT_PATH REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

if(LR1_CHECK_IS_DEBUGGER_PRESENT)
    set(LR1_DEBUGGER_CHECK_VALUE 1)
else()
    set(LR1_DEBUGGER_CHECK_VALUE 0)
endif()

# Общая библиотека: криптография, хранилище записей и проверки целостности.
add_library(lr1core STATIC
    src/crypto_utils.cpp
    src/credential_vault.cpp
    src/integrity.cpp)
target_include_directories(lr1core PUBLIC include)
# Каталог зависимостей MSYS2 содержит и C-заголовки, которые не должны перекрывать
# заголовки стандартной библиотеки и Windows SDK, поэтому он подключается через -idirafter.
target_compile_options(lr1core PUBLIC
    "SHELL:-idirafter ${LR1_OPENSSL_INCLUDE}"
    "SHELL:-idirafter ${LR1_JSON_INCLUDE}")
target_compile_definitions(lr1core PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(lr1core PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(lr1core PUBLIC "${LR1_LIBCRYPTO}" crypt32 ws2_32)

# Главное приложение с графическим интерфейсом (окно Windows).
add_executable(PassManager WIN32 src/main.cpp)
target_compile_definitions(PassManager PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
                           LR1_CHECK_IS_DEBUGGER_PRESENT=${LR1_DEBUGGER_CHECK_VALUE})
target_compile_options(PassManager PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(PassManager PRIVATE lr1core comctl32)
target_link_options(PassManager PRIVATE -municode)

# Приложение-протектор: самоотладка менеджера паролей.
add_executable(Protector protector/protector.cpp)
target_compile_definitions(Protector PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(Protector PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(Protector PRIVATE -municode)

# Утилита создания и проверки файла учётных данных.
add_executable(CredentialTool tools/credential_tool.cpp)
target_compile_definitions(CredentialTool PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(CredentialTool PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(CredentialTool PRIVATE lr1core)
target_link_options(CredentialTool PRIVATE -municode)

# После линковки записываем эталонный SHA-256 сегмента .text в образ PassManager.exe.
add_custom_command(TARGET PassManager POST_BUILD
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/patch_text_hash.py"
            "$<TARGET_FILE:PassManager>"
    VERBATIM)

# DLL библиотеки OpenSSL и файл учётных данных копируются рядом с программой,
# поэтому PATH менять не нужно (требование методички).
add_custom_command(TARGET PassManager POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${LR1_LIBCRYPTO_DLL}" "$<TARGET_FILE_DIR:PassManager>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/data/credentials.bin"
            "$<TARGET_FILE_DIR:PassManager>"
    VERBATIM)
