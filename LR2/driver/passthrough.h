/* passthrough.h
 * Константы минифильтр-драйвера ЛР2 (прозрачное шифрование файлов с расширением .lab2ext).
 */
#ifndef LR2_PASSTHROUGH_H
#define LR2_PASSTHROUGH_H

#include "../src/crypto_core.h"

/* Расширение файлов, которые шифруются драйвером. Сравнение без учёта регистра. */
#define LR2_TARGET_EXTENSION L"lab2ext"

/* Учебные ключ и nonce. Они совпадают с константами в tests/crypto_selftest.c и с ключом,
 * который использует проверка ядра. В реальной системе ключ хранится в защищённом месте
 * и передаётся драйверу отдельно (см. раздел "Допущения" отчёта). */
static const uint8_t kLr2Key[LR2_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t kLr2Nonce[LR2_NONCE_SIZE] = { 0x4c, 0x52, 0x32, 0x2d, 0x6c, 0x61, 0x62, 0x21 };

#endif /* LR2_PASSTHROUGH_H */
