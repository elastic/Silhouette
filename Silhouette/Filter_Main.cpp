
#include "Silhouette.h"

PFLT_FILTER gpFilter = NULL;

// pagefile.sys
FILE_ID_INFORMATION gProtectedFiles[1] = { 0, };

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreateCallback,
      PostCreateCallback },

    { IRP_MJ_READ,
      0,
      PreReadCallback,
      PostReadCallback },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version   
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, //  Flags
    NULL,                                   //  Context
    Callbacks,                              //  Operation callbacks
    FilterUnload,                           //  FilterUnload
    InstanceSetupCallback,                  //  InstanceSetup
    QueryTeardown,                          //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete
    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

NTSTATUS GetFileIdByPath(PUNICODE_STRING pFilePath, PFILE_ID_INFORMATION pFileIdInfo)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr = { 0, };
    IO_STATUS_BLOCK iosb = { 0, };
    HANDLE hFile = NULL;

    InitializeObjectAttributes(&objAttr, pFilePath, OBJ_KERNEL_HANDLE, 0, NULL);

    // This fails with a sharing violation pagefile.sys, even with IO_IGNORE_SHARE_ACCESS_CHECK
    ntStatus = FltCreateFile(
        gpFilter, NULL, &hFile, 0, &objAttr, &iosb, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    ntStatus = ZwQueryInformationFile(hFile, &iosb, pFileIdInfo, sizeof(*pFileIdInfo), FileIdInformation);

Cleanup:
    HandleDelete(hFile);

    return ntStatus;
}

NTSTATUS FindPagefile()
{
    const ULONG systemProcessId = HandleToULong(PsGetProcessId(PsInitialSystemProcess)); // Always 4, but you never know?
    DECLARE_CONST_UNICODE_STRING(pagefile_sys, L"\\pagefile.sys");

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG handleInfoMem = 0;
    ULONG returnLength = 0;
    PFILE_OBJECT pFile = NULL;
    PFILE_NAME_INFORMATION pNameInfo = NULL;

    for (ULONG tries = 0; tries < 5; tries++)
    {
        ntStatus = ZwQuerySystemInformation(SystemHandleInformation, pHandleInfo, handleInfoMem, &returnLength);
        if (STATUS_INFO_LENGTH_MISMATCH != ntStatus)
        {
            break;
        }

        HandleDelete(pHandleInfo);
        handleInfoMem = returnLength * 2;
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(PagedPool, handleInfoMem, POOL_TAG);
        if (!pHandleInfo)
        {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        RtlZeroMemory(pHandleInfo, handleInfoMem);
    }
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        UNICODE_STRING nameInfoUni = { 0, };

        if (systemProcessId != pHandleInfo->Handles[i].UniqueProcessId)
        {
            continue;
        }

        ReferenceDelete(pFile);
        PoolDeleteWithTag(pNameInfo, POOL_TAG);

            // I'm not fond of temporarily referencing other handles in the System process, but the point here is to prove the concept
        ntStatus = ObReferenceObjectByHandle(
            MAKE_KERNEL_HANDLE(ULongToHandle(pHandleInfo->Handles[i].HandleValue)), FILE_READ_DATA|FILE_WRITE_DATA, *IoFileObjectType, KernelMode, (PVOID*)&pFile, NULL);
        if (!NT_SUCCESS(ntStatus))
        {
            continue;
        }

        // pagefile.sys is opened without buffering
        if (!FlagOn(pFile->Flags, FO_NO_INTERMEDIATE_BUFFERING))
        {
            continue;
        }

        // pagefile.sys is opened for RW- with -W- sharing
        if (!pFile->ReadAccess || !pFile->WriteAccess || pFile->DeleteAccess || pFile->SharedRead || pFile->SharedDelete)
        {
            continue;
        }

        pNameInfo = (PFILE_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, 4096, POOL_TAG);
        if (!pNameInfo)
        {
            continue;
        }
             
        RtlZeroMemory(pNameInfo, 4096);
        pNameInfo->FileNameLength = 4096 - sizeof(*pNameInfo); // Leave room for a NULL

        ntStatus = FsRtlQueryInformationFile(pFile, pNameInfo, 4096, FileNameInformation, &returnLength);
        if (!NT_SUCCESS(ntStatus) || (pNameInfo->FileNameLength > MAXUSHORT))
        {
            continue;
        }

        nameInfoUni.Buffer = pNameInfo->FileName;
        nameInfoUni.Length = (USHORT)pNameInfo->FileNameLength;
        nameInfoUni.MaximumLength = nameInfoUni.Length;

        if (!RtlEqualUnicodeString(&nameInfoUni, &pagefile_sys, FALSE))
        {
            continue;
        }

        ntStatus = FsRtlQueryInformationFile(pFile, &gProtectedFiles[0], sizeof(gProtectedFiles[0]), FileIdInformation, &returnLength);
        if (NT_SUCCESS(ntStatus) && (sizeof(gProtectedFiles[0]) == returnLength))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "Silhouette: Pagefile: %wZ\n",
                &nameInfoUni);

            goto Cleanup;
        }
    }

    ntStatus = STATUS_PAGEFILE_NOT_SUPPORTED;

Cleanup:
    PoolDeleteWithTag(pHandleInfo, POOL_TAG);
    PoolDeleteWithTag(pNameInfo, POOL_TAG);
    ReferenceDelete(pFile);

    return ntStatus;
}

NTSTATUS
RegisterFilter(_In_ PDRIVER_OBJECT pDriverObject)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = FltRegisterFilter(pDriverObject, &FilterRegistration, &gpFilter);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    ntStatus = FindPagefile();
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    ntStatus = FltStartFiltering(gpFilter);
    if (!NT_SUCCESS(ntStatus))
    {
        FltUnregisterFilter(gpFilter);
        gpFilter = NULL;
        goto Cleanup;
    }

Cleanup:
    return ntStatus;
}

VOID
UnregisterFilter()
{
    if (gpFilter)
    {
        FltUnregisterFilter(gpFilter);
        gpFilter = NULL;
    }
}

NTSTATUS
FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    FltUnregisterFilter(gpFilter);

    return STATUS_SUCCESS;
}

NTSTATUS InstanceSetupCallback(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING volumeName = { 0, };
    PWCHAR pBuffer = NULL;
    ULONG volumeNameLength = 0;

    ntStatus = FltGetVolumeName(FltObjects->Volume, NULL, &volumeNameLength);
    pBuffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, volumeNameLength, POOL_TAG);
    if (!pBuffer)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlInitEmptyUnicodeString(&volumeName, pBuffer, (USHORT)volumeNameLength);
    ntStatus = FltGetVolumeName(FltObjects->Volume, &volumeName, &volumeNameLength);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }
    
    // Volume Reads
    // Flags == FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT
    // VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM
    // VolumeFilesystemType == FLT_FSTYPE_NTFS

    // TODO: Raw disk reads

#if 0
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "Silhouette: InstanceSetupCallback for Flags: 0x%x DevType: %u FS: %u for %wZ\n",
        Flags, VolumeDeviceType, VolumeFilesystemType, &volumeName);
#endif

Cleanup:
    PoolDeleteWithTag(pBuffer, POOL_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS
QueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_ACCESS_DENIED;
}
