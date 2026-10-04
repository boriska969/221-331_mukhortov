/* app.c
 * Клиентское приложение ЛР3 (этап 3): неподготовленная (незащищённая) часть.
 * Создаёт анклав, запрашивает строку таблицы по номеру, печатает её и выгружает анклав.
 * Код не собирался в этой работе: требуется Intel SGX SDK (см. README.md).
 *
 * Использование: app <номер строки>
 */
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

#include "sgx_urts.h"
#include "Enclave_u.h" /* сгенерирован sgx_edger8r по Enclave.edl */

#define ENCLAVE_FILE _T("Enclave.signed.dll")
#define ROW_BUFFER_SIZE 128

/* Точка входа клиентского приложения.
 * argc, argv - аргументы командной строки; argv[1] - номер строки таблицы.
 * Возвращает 0 при успехе, 1 - при ошибке. */
int main(int argc, char* argv[])
{
    sgx_enclave_id_t enclaveId = 0;
    sgx_launch_token_t token = { 0 };
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t callStatus = SGX_SUCCESS;
    int updated = 0;
    int result = -1;
    char row[ROW_BUFFER_SIZE] = { 0 };
    long rowNumber;
    char* end = NULL;

    if (argc != 2) {
        printf("usage: app <row number>\n");
        return 1;
    }
    rowNumber = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0') {
        printf("WARNING: '%s' is not a row number\n", argv[1]);
        return 1;
    }

    /* Создание анклава; SGX_DEBUG_FLAG используется для учебной сборки Simulation. */
    status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &enclaveId, NULL);
    if (status != SGX_SUCCESS) {
        printf("App: error %#x, failed to create enclave.\n", status);
        return 1;
    }

    callStatus = ecall_get_row(enclaveId, &result, (int)rowNumber, row, sizeof row);
    if (callStatus != SGX_SUCCESS || result != 0) {
        printf("WARNING: row %ld does not exist or does not fit the buffer\n", rowNumber);
    } else {
        printf("row %ld: %s\n", rowNumber, row);
    }

    /* Выгрузка анклава перед завершением приложения. */
    if (SGX_SUCCESS != sgx_destroy_enclave(enclaveId)) {
        return 1;
    }
    return result == 0 ? 0 : 1;
}
