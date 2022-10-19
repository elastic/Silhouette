#include "Silhouette.h"

BOOLEAN ShouldBlockVolumeRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    BOOLEAN bShouldLog = FALSE;
    BOOLEAN bShouldBlock = FALSE;
    FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;

    // Ignore KernelMode requests
    // We're only interested in FO_VOLUME_OPEN reads
    // We're only interested in reads to the system boot partition
    if (((KernelMode == Data->RequestorMode) && !FlagOn(Data->Iopb->OperationFlags, SL_FORCE_ACCESS_CHECK)) ||
        (0 == FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) ||
        (0 == FlagOn(FltObjects->FileObject->DeviceObject->Flags, DO_SYSTEM_BOOT_PARTITION)))
    {
        goto Cleanup;
    }

    // The volume should be NTFS
    ntStatus = FltGetFileSystemType(FltObjects->Volume, &fsType);
    if (!NT_SUCCESS(ntStatus) || (FLT_FSTYPE_NTFS != fsType))
    {
        goto Cleanup;
    }

    bShouldLog = TRUE;

    // Allow small reads at offset 0
    if ((0 == Data->Iopb->Parameters.Read.ByteOffset.QuadPart) &&
        (Data->Iopb->Parameters.Read.Length <= 512))
    {
        goto Cleanup;
    }

#if 0
    {
        NTFS_VOLUME_DATA_BUFFER volumeData = { 0, };
        ULONG ulBytesReturned = 0;
        LONGLONG mftStartOffset = 0;
        LONGLONG mftEndOffset = 0;

        // Find MFT region
        ntStatus = FltFsControlFile(
            FltObjects->Instance, FltObjects->FileObject, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &volumeData, sizeof(volumeData), &ulBytesReturned);
        if (!NT_SUCCESS(ntStatus))
        {
            goto Cleanup;
        }

        mftStartOffset = volumeData.MftZoneStart.QuadPart * volumeData.BytesPerCluster;
        mftEndOffset = volumeData.MftZoneEnd.QuadPart * volumeData.BytesPerCluster;

        // Allow reads to the MFT region
        if ((Data->Iopb->Parameters.Read.ByteOffset.QuadPart >= mftStartOffset) &&
            (Data->Iopb->Parameters.Read.ByteOffset.QuadPart < mftEndOffset))
        {
            goto Cleanup;
        }
}
#endif

    bShouldBlock = TRUE;

Cleanup:

    if (bShouldLog)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Silhouette: %s FO_VOLUME_OPEN read at offset %llu Length %lu PID %u\n",
            bShouldBlock ? "DENY" : "ALLOW",
            Data->Iopb->Parameters.Read.ByteOffset.QuadPart,
            Data->Iopb->Parameters.Read.Length,
            FltGetRequestorProcessId(Data)
        );
    }

    return bShouldBlock;
}

FLT_PREOP_CALLBACK_STATUS
PreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    FLT_PREOP_CALLBACK_STATUS cbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Block direct volume reads
    // TODO: Block direct device reads (FLT_FSTYPE_RAW to \Device\Harddisk0\DR0) that fall within the bounds of the boot volume
    if (ShouldBlockVolumeRead(Data, FltObjects))
    {
        cbStatus = FLT_PREOP_COMPLETE;
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    // We're looking for paging I/O from LSASS
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
    {
        if ((gLsaPid == FltGetRequestorProcessId(Data)) ||
            (gLsaPid == HandleToULong(PsGetCurrentProcessId())) ||
            (gLsaPid == HandleToULong(PsGetProcessId(PsGetCurrentProcess()))))
        {
            // Wait for the page fault to complete, then re-empty the WS
            cbStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

Cleanup:

    return cbStatus;
}

FLT_POSTOP_CALLBACK_STATUS
PostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Page out LSA asynchronously
    EmptyWorkingSet(TRUE);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
