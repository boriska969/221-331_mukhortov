/* crypto_selftest.c
 * Самопроверка криптографического ядра ЛР2 в пользовательском режиме.
 * Драйвер использует то же ядро (src/crypto_core.c), поэтому проверка подтверждает
 * корректность гаммы AES-256 до установки драйвера в тестовую машину.
 */
#include <stdio.h>
#include <string.h>

#include "../src/crypto_core.h"
#include "../third_party/tiny-aes-c/aes.h"

static int failures = 0;

/* Выводит результат проверки и учитывает число неудач.
 * condition - истина, если проверка пройдена; name - описание проверки. */
static void check(int condition, const char* name)
{
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) {
        failures++;
    }
}

/* Учебный ключ и nonce; совпадают с константами драйвера (driver/passthrough.h). */
static const uint8_t kKey[LR2_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t kNonce[LR2_NONCE_SIZE] = { 0x4c, 0x52, 0x32, 0x2d, 0x6c, 0x61, 0x62, 0x21 };

/* Проверка по вектору FIPS-197, приложение C.3: AES-256, один блок. */
static void test_fips197_vector(void)
{
    static const uint8_t plain[AES_BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const uint8_t expected[AES_BLOCKLEN] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
    };
    struct AES_ctx context;
    uint8_t block[AES_BLOCKLEN];

    memcpy(block, plain, sizeof block);
    AES_init_ctx(&context, kKey);
    AES_ECB_encrypt(&context, block);
    check(memcmp(block, expected, sizeof block) == 0, "AES-256 matches FIPS-197 test vector C.3");
}

/* Шифрование и повторное шифрование с тем же смещением возвращают исходные данные. */
static void test_round_trip_at_offset(void)
{
    uint8_t original[300];
    uint8_t work[300];
    size_t index;

    for (index = 0; index < sizeof original; ++index) {
        original[index] = (uint8_t)(index * 7u + 3u);
    }
    memcpy(work, original, sizeof work);
    lr2_xcrypt_at_offset(kKey, kNonce, 5, work, sizeof work);
    check(memcmp(work, original, sizeof work) != 0, "ciphertext differs from plaintext");
    lr2_xcrypt_at_offset(kKey, kNonce, 5, work, sizeof work);
    check(memcmp(work, original, sizeof work) == 0, "round trip at offset 5 restores the data");
}

/* Обработка файла частями (как при нескольких операциях ReadFile/WriteFile) даёт тот же результат,
 * что и обработка целиком. Это условие корректности драйвера при частичных операциях ввода-вывода. */
static void test_split_io_is_consistent(void)
{
    uint8_t whole[100];
    uint8_t parts[100];
    size_t index;

    for (index = 0; index < sizeof whole; ++index) {
        whole[index] = parts[index] = (uint8_t)(0xa5u ^ index);
    }
    lr2_xcrypt_at_offset(kKey, kNonce, 0, whole, sizeof whole);
    lr2_xcrypt_at_offset(kKey, kNonce, 0, parts, 37);
    lr2_xcrypt_at_offset(kKey, kNonce, 37, parts + 37, sizeof parts - 37);
    check(memcmp(whole, parts, sizeof whole) == 0,
          "split I/O (0..36 and 37..99) gives the same ciphertext as one I/O");
}

/* Разные nonce и разные ключи дают разную гамму для одинаковых данных. */
static void test_keystream_depends_on_key_and_nonce(void)
{
    static const uint8_t otherNonce[LR2_NONCE_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t keyChanged[LR2_KEY_SIZE];
    uint8_t first[64];
    uint8_t second[64];
    uint8_t third[64];

    memset(first, 0x00, sizeof first);
    memset(second, 0x00, sizeof second);
    memset(third, 0x00, sizeof third);
    memcpy(keyChanged, kKey, sizeof keyChanged);
    keyChanged[0] ^= 0x01u;

    lr2_xcrypt_at_offset(kKey, kNonce, 0, first, sizeof first);
    lr2_xcrypt_at_offset(kKey, otherNonce, 0, second, sizeof second);
    lr2_xcrypt_at_offset(keyChanged, kNonce, 0, third, sizeof third);
    check(memcmp(first, second, sizeof first) != 0, "different nonce gives a different keystream");
    check(memcmp(first, third, sizeof first) != 0, "different key gives a different keystream");
}

/* Точка входа. Возвращает 0, если все проверки пройдены, иначе 1. */
int main(void)
{
    test_fips197_vector();
    test_round_trip_at_offset();
    test_split_io_is_consistent();
    test_keystream_depends_on_key_and_nonce();
    printf("%s (%d failure(s))\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures == 0 ? 0 : 1;
}
