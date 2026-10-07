#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>

#include "sgx_urts.h"
#include "Enclave_u.h"

#define ENCLAVE_FILE _T("Enclave.signed.dll")
#define ROW_BUFFER_SIZE 128

int main(int argc, char* argv[])
{
    sgx_enclave_id_t enclaveId = 0;
    sgx_launch_token_t token = { 0 };
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t callStatus = SGX_SUCCESS;
    int updated = 0;
    int result = -1;
    char row[ROW_BUFFER_SIZE] = { 0 };
    char enclavePath[MAX_PATH];
    char* lastSlash;
    DWORD pathLength;
    long rowNumber;
    char* end = NULL;

    if (argc != 2) {
        printf("usage: app <row number>\n");
        return 1;
    }
    errno = 0;
    rowNumber = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || errno == ERANGE || rowNumber < INT_MIN || rowNumber > INT_MAX) {
        printf("WARNING: '%s' is not a row number\n", argv[1]);
        return 1;
    }

    pathLength = GetModuleFileNameA(NULL, enclavePath, sizeof enclavePath);
    if (!pathLength || pathLength >= sizeof enclavePath) {
        printf("ERROR: cannot locate executable directory\n");
        return 1;
    }
    lastSlash = strrchr(enclavePath, '\\');
    if (!lastSlash || (size_t)(lastSlash + 1 - enclavePath) + sizeof ENCLAVE_FILE > sizeof enclavePath) {
        printf("ERROR: enclave path is too long\n");
        return 1;
    }
    strcpy_s(lastSlash + 1, sizeof enclavePath - (lastSlash + 1 - enclavePath), ENCLAVE_FILE);
    status = sgx_create_enclave(enclavePath, SGX_DEBUG_FLAG, &token, &updated, &enclaveId, NULL);
    if (status != SGX_SUCCESS) {
        printf("App: error %#x, failed to create enclave.\n", status);
        return 1;
    }

    callStatus = ecall_get_row(enclaveId, &result, (int)rowNumber, row, sizeof row);
    if (callStatus != SGX_SUCCESS) {
        printf("ERROR: ECALL failed, SGX status %#x\n", callStatus);
    } else if (result != 0) {
        printf("WARNING: row %ld does not exist or does not fit the buffer\n", rowNumber);
    } else {
        printf("row %ld: %s\n", rowNumber, row);
    }

    if (SGX_SUCCESS != sgx_destroy_enclave(enclaveId)) {
        return 1;
    }
    return callStatus == SGX_SUCCESS && result == 0 ? 0 : 1;
}
