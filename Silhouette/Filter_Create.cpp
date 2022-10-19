#include "Silhouette.h"

FLT_PREOP_CALLBACK_STATUS
PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    FLT_PREOP_CALLBACK_STATUS cbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    // Ignore kernel mode callers
    if ((KernelMode == Data->RequestorMode) && !FlagOn(Data->Iopb->OperationFlags, SL_FORCE_ACCESS_CHECK))
    {
        goto Cleanup;
    }

    // We only care if they're requesting FILE_READ_DATA
    if (!FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_READ_DATA))
    {
        goto Cleanup;
    }

    cbStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

Cleanup:

    return cbStatus;
}

FLT_POSTOP_CALLBACK_STATUS
PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    FILE_ID_INFORMATION fileId = { 0, };
    ULONG resultSize = 0;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if ((STATUS_SUCCESS != Data->IoStatus.Status) ||
        !FltObjects->FileObject ||
        FlagOn(FltObjects->FileObject->Flags, FO_HANDLE_CREATED)
        )
    {
        goto Cleanup;
    }

    ntStatus = FsRtlQueryInformationFile(FltObjects->FileObject, &fileId, sizeof(fileId), FileIdInformation, &resultSize);
    if (!NT_SUCCESS(ntStatus) || (sizeof(fileId) != resultSize))
    {
        goto Cleanup;
    }

    for (ULONG i = 0; i < ARRAYSIZE(gProtectedFiles); i++)
    {
        if (0 == memcmp(&fileId, &gProtectedFiles[i], sizeof(fileId)))
        {
            FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Silhouette: DENY pagefile access.  PID: %u\n", FltGetRequestorProcessId(Data)
            );
        }
    }

Cleanup:
    return FLT_POSTOP_FINISHED_PROCESSING;
}