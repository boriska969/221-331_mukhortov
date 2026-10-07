#include <fltKernel.h>
#include <dontuse.h>

#include "passthrough.h"

#define LR2_POOL_TAG 'R2RL'

PFLT_FILTER gFilterHandle = NULL;

static BOOLEAN PtIsTargetFile(_In_ PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING targetExtension = RTL_CONSTANT_STRING(LR2_TARGET_EXTENSION);
    BOOLEAN isTarget = FALSE;
    NTSTATUS status;

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(FltParseFileNameInformation(nameInfo))) {
            isTarget = RtlEqualUnicodeString(&nameInfo->Extension, &targetExtension, TRUE);
        }
        FltReleaseFileNameInformation(nameInfo);
    }
    return isTarget;
}

static PVOID PtGetDataBuffer(_In_opt_ PVOID userBuffer, _In_opt_ PMDL mdl)
{
    if (userBuffer != NULL) {
        return userBuffer;
    }
    if (mdl != NULL) {
        return MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    }
    return NULL;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(_Inout_ PFLT_CALLBACK_DATA Data,
                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                          _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PVOID buffer;
    ULONG length;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!PtIsTargetFile(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    length = Data->Iopb->Parameters.Write.Length;
    buffer = PtGetDataBuffer(Data->Iopb->Parameters.Write.WriteBuffer,
                             Data->Iopb->Parameters.Write.MdlAddress);
    if (buffer != NULL && length != 0) {
        DbgPrint("*** Lab2: IRP_MJ_WRITE, encrypting %lu bytes at offset %I64d\n",
                 length, Data->Iopb->Parameters.Write.ByteOffset.QuadPart);
        lr2_xcrypt_at_offset(kLr2Key, kLr2Nonce,
                             (uint64_t)Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                             (uint8_t*)buffer, length);
        FltSetCallbackDataDirty(Data);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(_Inout_ PFLT_CALLBACK_DATA Data,
                           _In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _In_opt_ PVOID CompletionContext,
                           _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PVOID buffer;
    ULONG bytesRead;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!PtIsTargetFile(Data)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    bytesRead = (ULONG)Data->IoStatus.Information;
    buffer = PtGetDataBuffer(Data->Iopb->Parameters.Read.ReadBuffer,
                             Data->Iopb->Parameters.Read.MdlAddress);
    if (buffer != NULL) {
        DbgPrint("*** Lab2: IRP_MJ_READ, decrypting %lu bytes at offset %I64d\n",
                 bytesRead, Data->Iopb->Parameters.Read.ByteOffset.QuadPart);
        lr2_xcrypt_at_offset(kLr2Key, kLr2Nonce,
                             (uint64_t)Data->Iopb->Parameters.Read.ByteOffset.QuadPart,
                             (uint8_t*)buffer, bytesRead);
        FltSetCallbackDataDirty(Data);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS PtUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS PtInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                         _In_ DEVICE_TYPE VolumeDeviceType,
                         _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    if (VolumeFilesystemType == FLT_FSTYPE_RAW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

NTSTATUS PtInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                 _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      PtPreOperationPassThrough,
      NULL },
    { IRP_MJ_READ,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      NULL,
      PtPostOperationPassThrough },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    PtUnload,
    PtInstanceSetup,
    PtInstanceQueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(status)) {
            FltUnregisterFilter(gFilterHandle);
            gFilterHandle = NULL;
        }
    }
    return status;
}
