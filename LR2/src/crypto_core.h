#ifndef LR2_CRYPTO_CORE_H
#define LR2_CRYPTO_CORE_H

#include <stddef.h>
#include <stdint.h>

#define LR2_KEY_SIZE 32u
#define LR2_NONCE_SIZE 8u

void lr2_xcrypt_at_offset(const uint8_t key[LR2_KEY_SIZE],
                          const uint8_t nonce[LR2_NONCE_SIZE],
                          uint64_t byteOffset,
                          uint8_t* buffer,
                          size_t length);

#endif
