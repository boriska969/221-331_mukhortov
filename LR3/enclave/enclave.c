/* enclave.c
 * Доверенная часть ЛР3: таблица учётных записей и функция выдачи строки внутри анклава Intel SGX.
 *
 * Условность лабораторной работы: записи объявлены статически, поэтому они видны в
 * файле анклава при реверс-инжиниринге (см. theory_answers.md).
 */
#include "Enclave_t.h"
#include <string.h>
#include <stddef.h>

/* Таблица, которая хранится внутри анклава (та же, что в этапе 1). */
static const char* const kEnclaveTable[] = {
    "alice.morgan;Vq7#mLx2!tRp",
    "bkaramov;Krt9$wYe4@Lzn",
    "night_owl_77;Plm3&zQe8?Vna",
    "j.petrova;Hd5*nRt2%Woq",
    "dev-team-01;Zx8!cVb4#Mkl",
};

#define ENCLAVE_TABLE_ROWS ((int)(sizeof kEnclaveTable / sizeof kEnclaveTable[0]))

/* ECALL: копирует строку таблицы с номером row в буфер buf вызывающей стороны.
 * row     - номер строки (с нуля);
 * buf     - буфер для результата (выходной параметр, размер buf_len);
 * buf_len - размер буфера в байтах.
 * Возвращает 0, если строка найдена и скопирована; -1, если строки нет или буфер мал. */
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
