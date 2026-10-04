cmake_minimum_required(VERSION 3.20)
project(lr2_transparent_encryption LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Пользовательские части ЛР2, которые собираются и запускаются без драйвера:
#   crypto_selftest - проверка криптографического ядра, общего с драйвером;
#   lab2_client     - клиентское приложение для чтения и записи файла фиксированного размера.
# Драйвер-фильтр (driver/) собирается в Visual Studio с WDK, см. README.md.
add_executable(crypto_selftest tests/crypto_selftest.c src/crypto_core.c)
target_include_directories(crypto_selftest PRIVATE src)

add_executable(lab2_client app/lab2_client.c)
