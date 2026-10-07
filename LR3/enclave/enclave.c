#include "Enclave_t.h"
#include <string.h>
#include <stddef.h>

static const char* const kEnclaveTable[] = {
    "alice.morgan;Vq7#mLx2!tRp",
    "bkaramov;Krt9$wYe4@Lzn",
    "night_owl_77;Plm3&zQe8?Vna",
    "j.petrova;Hd5*nRt2%Woq",
    "dev-team-01;Zx8!cVb4#Mkl",
};

#define ENCLAVE_TABLE_ROWS ((int)(sizeof kEnclaveTable / sizeof kEnclaveTable[0]))

int ecall_get_row(int row, char* buf, size_t buf_len)
{
    size_t length;

    if (buf == NULL || buf_len == 0) {
        return -1;
    }
    if (row < 0 || row >= ENCLAVE_TABLE_ROWS) {
        buf[0] = '\0';
        return -1;
    }
    length = strlen(kEnclaveTable[row]);
    if (length + 1 > buf_len) {
        buf[0] = '\0';
        return -1;
    }
    memcpy(buf, kEnclaveTable[row], length + 1);
    return 0;
}
