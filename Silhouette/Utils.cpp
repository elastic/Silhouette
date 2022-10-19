#include "Silhouette.h"
#include "Filter.h"


_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
GetRegistryValue(
    _In_ PCUNICODE_STRING pKeyPath,
    _In_ PCUNICODE_STRING pValueName,
    _In_ ULONG expectedType,
    _Inout_ PVOID pValue,
    _In_ ULONG valueSize
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hKey = NULL;

    ULONG returnLength = 0;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyInfo = NULL;
    ULONG keyInfoSize = 0;

    if (!pKeyPath || !pValueName || !pValue || (0 == valueSize) || (0 == expectedType))
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // We are intentionally casting pKeyPath here so all callers don't have to cast it.
    InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)pKeyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the key
    ntStatus = ZwOpenKey(&hKey, GENERIC_READ, &objAttr);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    keyInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + valueSize;
    pKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, keyInfoSize, POOL_TAG);
    if (!pKeyInfo)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(pKeyInfo, keyInfoSize);

    // Query the value
    // We are intentionally casting pValueName here so all callers don't have to cast it.
    ntStatus = ZwQueryValueKey(hKey, (PUNICODE_STRING)pValueName, KeyValuePartialInformation, pKeyInfo, keyInfoSize, &returnLength);
    if (!NT_SUCCESS(ntStatus))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "GetRegistryValue: Failed to query value with error 0x%08x\n", ntStatus));
        goto Cleanup;
    }

    // Validate that the data type and size matches what is expected
    if ((expectedType != pKeyInfo->Type) ||
        (pKeyInfo->DataLength != valueSize))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "GetRegistryValue: Value type or size is incorrect\n"));
        ntStatus = STATUS_REGISTRY_IO_FAILED;
        goto Cleanup;
    }

    RtlCopyMemory(pValue, &pKeyInfo->Data, pKeyInfo->DataLength);

Cleanup:
    HandleDelete(hKey);
    PoolDeleteWithTag(pKeyInfo, POOL_TAG);

    return ntStatus;
}

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
GetRegistryDword(
    _In_ PCUNICODE_STRING pKeyPath,
    _In_ PCUNICODE_STRING pValueName,
    _Out_ PULONG pValue
)
{
    return GetRegistryValue(pKeyPath, pValueName, REG_DWORD, pValue, sizeof(*pValue));
}

NTSTATUS EmptyWorkingSetAsync()
{
    KeSetEvent(&gWorkerThreadSignal, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS EmptyWorkingSet(BOOLEAN bAllowAsync)
{
    QUOTA_LIMITS_EX quotaLimits = { 0, };
    VM_COUNTERS_EX2 before = { 0, };
    VM_COUNTERS_EX2 after = { 0, };
    NTSTATUS ntStatus = STATUS_SUCCESS;;
    ULONG returnLength = 0;
    BOOLEAN bHaveInitialSnapshot = FALSE;
    BOOLEAN bShouldPurge = TRUE;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        if (bAllowAsync)
        {
            return EmptyWorkingSetAsync();
        }
        else
        {
            return STATUS_INVALID_STATE_TRANSITION;
        }
    }

    ntStatus = ZwQueryInformationProcess(ghLsass, ProcessVmCounters, &before, sizeof(before), &returnLength);
    if (NT_SUCCESS(ntStatus))
    {
        if (before.PrivateWorkingSetSize <= PAGE_SIZE)
        {
            // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Empty aborted: %zu\n", before.PrivateWorkingSetSize);
            goto Cleanup;
        }

        bHaveInitialSnapshot = TRUE;
    }

    // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Emptying working set\n");

    quotaLimits.MinimumWorkingSetSize = (SIZE_T)-1;
    quotaLimits.MaximumWorkingSetSize = (SIZE_T)-1;

    ntStatus = ZwSetInformationProcess( ghLsass, ProcessQuotaLimits, &quotaLimits, sizeof(quotaLimits) );
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    if (bHaveInitialSnapshot)
    {
        // If EmptyWorkingSet() didn't remove any pages, skip the MM list purge
        ntStatus = ZwQueryInformationProcess(ghLsass, ProcessVmCounters, &after, sizeof(after), &returnLength);
        if (NT_SUCCESS(ntStatus) && (after.PrivateWorkingSetSize == before.PrivateWorkingSetSize))
        {
            // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Purge ineffective\n");
            bShouldPurge = FALSE;
        }
    }

    if (bShouldPurge)
    {
        // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Purging.  Delta: %lld\n", before.PrivateWorkingSetSize - after.PrivateWorkingSetSize);
        ntStatus = PurgeModifiedAndStandbyLists();
    }

Cleanup:
    return ntStatus;
}

PVOID GetSystemProcAddress( PCWCHAR pFunctionName)
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, pFunctionName);

    return MmGetSystemRoutineAddress(&routineName);
}


NTSTATUS SetQuotaLimits(HANDLE hProcess)
{
    QUOTA_LIMITS_EX quotaLimits = { 0, };

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return STATUS_INVALID_STATE_TRANSITION;
    }

    // Cap LSASS working set
    quotaLimits.WorkingSetLimit = 5 * 1024 * 1024;
    quotaLimits.Flags = QUOTA_LIMITS_HARDWS_MAX_ENABLE;

    return ZwSetInformationProcess(hProcess, ProcessQuotaLimits, &quotaLimits, sizeof(quotaLimits));
}

NTSTATUS PurgeModifiedAndStandbyLists()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG command = 0;

    // Flush pages from modified list to the priority 0 standby list
    command = MemoryFlushModifiedList;
    ntStatus = ZwSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    // Flush the priority 0 standby list
    command = MemoryPurgeLowPriorityStandbyList;
    ntStatus = ZwSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Purged standby list\n");

Cleanup:
    return ntStatus;
}
