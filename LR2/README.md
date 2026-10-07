# ЛР2 - защита на уровне ядра ОС: прозрачное шифрование дискового ввода-вывода

Минифильтр-драйвер Windows (FltMgr) шифрует файлы с расширением `.lab2ext` при записи и
расшифровывает их при чтении. Шифрование - AES-256 (tiny-AES-c) в режиме «счётчик» на основе
ECB, поэтому работают любые размеры буферов и смещения.

## Состав

| Путь | Назначение | Статус |
|---|---|---|
| `src/crypto_core.c`, `src/crypto_core.h` | ядро шифрования (общее для драйвера и тестов) | собрано и проверено (`crypto_selftest`) |
| `third_party/tiny-aes-c/` | aes.c / aes.h (The Unlicense), в aes.h включён AES-256 | собрано и проверено |
| `tests/crypto_selftest.c` | 6 проверок: вектор FIPS-197, обратимость, согласованность частичных операций | 6 из 6 PASS |
| `app/lab2_client.c` | клиент: `show`, `write`, `demo` над файлом фиксированного размера (256 байт) | собрано и запущено без драйвера |
| `driver/` (`passThrough.vcxproj`, `passThrough.sln`, `passthrough.c`, `.h`, `.inf`, `.rc`) | минифильтр: PreOperation для WRITE, PostOperation для READ, высота 141050 | собран (Debug x64, WDK 10.0.26100.6584), **загружен и проверен в ВМ LR2-Win10** |
| `scripts/*.bat` | загрузка, выгрузка драйвера (`fltmc load/unload PassThrough`) | выполнены в ВМ от имени администратора, успешно |

## Сборка и проверка пользовательской части

```
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang
cmake --build build
build\bin\crypto_selftest.exe
```

## Драйвер (выполняется в тестовой виртуальной машине)

1. Установить Visual Studio 2022 с компонентами «Разработка классических приложений на C++», Spectre-библиотеками и «Комплект разработки драйверов для Windows». Установить Windows Driver Kit 10.0.26100.6584 и SDK 10.0.26100.6584 с тем же номером.
2. Открыть `driver\passThrough.sln` в Visual Studio 2022, выбрать Debug и x64, собрать решение. Та же сборка из командной строки: `MSBuild.exe driver\passThrough.vcxproj /p:Configuration=Debug /p:Platform=x64`.
3. Результат в `driver\x64\Debug\passThrough\`: `passThrough.sys`, `passThrough.inf`, `passthrough.cat`. Каталог `x64\` в git не попадает (см. `driver\.gitignore`).
4. Известное предупреждение сборки: проверка INF не находит `InfVerif.dll` в WDK 10.0.26100.6584, но код выхода сборки 0. Предупреждения C4005 и C4083 отключены в проекте: заголовки MSVC `<stdint.h>` и `<string.h>` конфликтуют с заголовками WDK для режима ядра.
5. В ВМ от имени администратора: установить INF, затем `scripts\load_driver.bat` и `lab2_client.exe demo <файл.lab2ext>`.

## Результаты проверки в ВМ (LR2-Win10)

- `sc query PassThrough` - служба зарегистрирована, `fltmc load PassThrough` - без ошибок,
  `fltmc filters` показывает `PassThrough` на высоте 141050 с 5 экземплярами (подключён ко всем томам).
- `lab2_client.exe demo test.lab2ext` при загруженном драйвере даёт тот же результат, что и
  эталонный запуск без драйвера (`analysis/logs/client_demo_no_driver.txt`) - фильтр прозрачен
  для приложения.
- Доказательство шифрования на диске: при `fltmc unload PassThrough` повторный `lab2_client.exe show`
  того же файла возвращает нечитаемые байты (AES-шифротекст), после `fltmc load PassThrough` -
  снова корректный текст. Подробности и точный вывод консоли:
  `analysis/logs/client_demo_with_driver.txt`, скриншот `screenshots/lr2_driver_unload_ciphertext.png`.

## Допущения

Ключ и nonce заданы константами (методичка это допускает). Драйвер меняет буфер на месте,
поэтому приложение не должно повторно использовать буфер записи. Для ввода-вывода без
буферизации и для двойных событий READ/WRITE нужны доработки (дополнительные задания).
