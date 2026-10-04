/* crypto_core.h
 * Криптографическое ядро ЛР2: шифрование AES-256 с учётом смещения в файле.
 * Один и тот же вызов шифрует и расшифровывает данные (режим "счётчик" на основе ECB),
 * поэтому драйвер может обрабатывать буферы любого размера и любого смещения:
 * фрагменты файла, прочитанные или записанные отдельными операциями, согласованы между собой.
 */
#ifndef LR2_CRYPTO_CORE_H
#define LR2_CRYPTO_CORE_H

#include <stddef.h>
#include <stdint.h>

#define LR2_KEY_SIZE 32u   /* AES-256: ключ 32 байта */
#define LR2_NONCE_SIZE 8u  /* начало блока-счётчика (первые 8 из 16 байт) */

/* Преобразует буфер на месте: XOR с гаммой AES-256, которая зависит от ключа,
 * nonce и абсолютной позиции байта в файле.
 * key        - ключ AES-256 (LR2_KEY_SIZE байт);
 * nonce      - постоянная часть блока-счётчика (LR2_NONCE_SIZE байт);
 * byteOffset - смещение первого байта буфера от начала файла;
 * buffer     - преобразуемые данные (изменяются на месте);
 * length     - число байт в буфере.
 */
void lr2_xcrypt_at_offset(const uint8_t key[LR2_KEY_SIZE],
                          const uint8_t nonce[LR2_NONCE_SIZE],
                          uint64_t byteOffset,
                          uint8_t* buffer,
                          size_t length);

#endif /* LR2_CRYPTO_CORE_H */
