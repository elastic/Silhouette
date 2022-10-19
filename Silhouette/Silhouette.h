#pragma once

#pragma warning(disable: 4201) // warning C4201: nonstandard extension used: nameless struct/union

#include <ntifs.h>
#include <ntintsafe.h>
#include <ntimage.h>
#include <fltKernel.h>
#include "phnt_subset.h"

#include "Filter.h"

#define POOL_TAG 'PASL'

#define ONCE __pragma( warning(push) ) \
             __pragma( warning(disable:4127) ) \
             while( 0 ) \
             __pragma( warning(pop) )

#define ReferenceDelete(_x) \
        do{ \
            if( (_x) != NULL ) \
            { \
                ObDereferenceObject(_x); \
                (_x) = NULL; \
            } \
        } ONCE

#define HandleDelete(_x) \
        do{ \
            if( (_x) != NULL ) \
            { \
                ZwClose(_x); \
                (_x) = NULL; \
            } \
        } ONCE

#define PoolDeleteWithTag(_x, _tag)\
        do{ \
            if( (_x) != NULL ) \
            { \
                ExFreePoolWithTag( (_x), (_tag) ); \
                (_x) = NULL; \
            } \
        } ONCE

// NTQSI truncates high bits off the handle, hiding the fact that it's a kernel handle
#define MAKE_KERNEL_HANDLE(__h) (HANDLE)((ULONG_PTR)(__h) | 0xFFFFFFFF80000000)

extern HANDLE ghLsass;
extern ULONG gLsaPid;
extern PDRIVER_OBJECT gpDriverObject;
extern KEVENT gWorkerThreadSignal;

EXTERN_C
NTKERNELAPI
BOOLEAN
NTAPI 
PsIsProtectedProcessLight(
    _In_ PEPROCESS Process
);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
GetRegistryValue(
    _In_ PCUNICODE_STRING pKeyPath,
    _In_ PCUNICODE_STRING pValueName,
    _In_ ULONG expectedType,
    _Inout_ PVOID pValue,
    _In_ ULONG valueSize
);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
GetRegistryDword(
    _In_ PCUNICODE_STRING pKeyPath,
    _In_ PCUNICODE_STRING pValueName,
    _Out_ PULONG pValue
);

PVOID GetSystemProcAddress(PCWCHAR pFunctionName);

NTSTATUS EmptyWorkingSet(BOOLEAN bAllowAsync);

NTSTATUS EmptyWorkingSetAsync();

NTSTATUS SetQuotaLimits(HANDLE hProcess);

NTSTATUS PurgeModifiedAndStandbyLists();
