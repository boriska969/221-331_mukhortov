#include "crypto_core.h"

#include <string.h>

#if defined(LR2_KERNEL_MODE)
#include <ntddk.h>
#define memcpy(destination, source, length) RtlCopyMemory((destination), (source), (length))
#define memset(destination, value, length) RtlFillMemory((destination), (length), (UCHAR)(value))
#endif

#include "../third_party/tiny-aes-c/aes.h"
#include "../third_party/tiny-aes-c/aes.c"

static void build_counter_block(const uint8_t nonce[LR2_NONCE_SIZE],
                                uint64_t blockIndex,
                                uint8_t block[AES_BLOCKLEN])
{
    size_t index;
    for (index = 0; index < LR2_NONCE_SIZE; ++index) {
        block[index] = nonce[index];
    }
    for (index = 0; index < 8u; ++index) {
        block[LR2_NONCE_SIZE + index] = (uint8_t)(blockIndex >> (8u * (7u - index)));
    }
}

void lr2_xcrypt_at_offset(const uint8_t key[LR2_KEY_SIZE],
                          const uint8_t nonce[LR2_NONCE_SIZE],
                          uint64_t byteOffset,
                          uint8_t* buffer,
                          size_t length)
{
    struct AES_ctx context;
    uint8_t keystream[AES_BLOCKLEN];
    uint64_t currentBlock = (uint64_t)-1;
    size_t index;

    AES_init_ctx(&context, key);
    for (index = 0; index < length; ++index) {
        uint64_t position = byteOffset + (uint64_t)index;
        uint64_t blockIndex = position / AES_BLOCKLEN;
        if (blockIndex != currentBlock) {

            build_counter_block(nonce, blockIndex, keystream);
            AES_ECB_encrypt(&context, keystream);
            currentBlock = blockIndex;
        }
        buffer[index] ^= keystream[position % AES_BLOCKLEN];
    }
}
