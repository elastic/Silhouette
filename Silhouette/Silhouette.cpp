#include "Silhouette.h"

HANDLE ghLsass = NULL;
ULONG gLsaPid = 0;
PDRIVER_OBJECT gpDriverObject = NULL;
KEVENT gWorkerThreadSignal = { 0, };
KEVENT gWorkerThreadShutdown = { 0, };
HANDLE ghWorkerThread = NULL;

static NTSTATUS OpenLSA(HANDLE* phLsass);
void WorkingSetThread(PVOID StartContext);

void
DriverUnload(
	PDRIVER_OBJECT DriverObject)
{
	UnregisterFilter();

	UNREFERENCED_PARAMETER(DriverObject);

	// Shut down and join worker thread
	if (ghWorkerThread)
	{
		KeSetEvent(&gWorkerThreadShutdown, 0, TRUE);
		ZwWaitForSingleObject(ghWorkerThread, FALSE, NULL);
		HandleDelete(ghWorkerThread);
	}

	HandleDelete(ghLsass);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Unloaded\n");
}

extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS ntStatus = 0;

	UNREFERENCED_PARAMETER(RegistryPath);

	gpDriverObject = DriverObject;

	ntStatus = OpenLSA(&ghLsass);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Start monitor thread
	KeInitializeEvent(&gWorkerThreadShutdown, NotificationEvent, FALSE);
	KeInitializeEvent(&gWorkerThreadSignal, SynchronizationEvent, FALSE);
	ntStatus = PsCreateSystemThread(&ghWorkerThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkingSetThread, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Do an initial shrink
	ntStatus = EmptyWorkingSet(FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Register minifilter
	ntStatus = RegisterFilter(DriverObject);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Setting this makes it trivial to unload this driver, but easier for development
	DriverObject->DriverUnload = DriverUnload;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Loaded\n");

Cleanup:
	if (!NT_SUCCESS(ntStatus))
	{
		DriverUnload(DriverObject);
	}
	return ntStatus;
}

static NTSTATUS OpenLSA(HANDLE* phLsass)
{
	const UNICODE_STRING szKeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
	const UNICODE_STRING szLsaPid = RTL_CONSTANT_STRING(L"LsaPid");

	NTSTATUS ntStatus = 0;
	CLIENT_ID cid = { 0, };
	OBJECT_ATTRIBUTES objAttr = { 0, };
	PEPROCESS pProcess = NULL;

	// Find LSA PID
	ntStatus = GetRegistryDword(&szKeyPath, &szLsaPid, &gLsaPid);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Get a handle
	cid = { ULongToHandle(gLsaPid), NULL };
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwOpenProcess(phLsass, 0, &objAttr, &cid);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	ntStatus = ObReferenceObjectByHandle(*phLsass, 0, *PsProcessType, KernelMode, (PVOID*)&pProcess, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}


	if (!PsIsProtectedProcessLight(pProcess))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"Silhouette: LSASS is not RunAsPPL!  Besides making it vulnerable to a variety of virtual memory-based attacks attacks, "
			"it greatly increases the chance of page faults due to benign VM accesses from APIs such as EnumProcessModules().\n");
	}

Cleanup:
	ReferenceDelete(pProcess);

	return ntStatus;
}

#define ONE_SECOND_IN_FILETIME 10000000
#define ONE_MS_IN_FILETIME 10000

void WorkingSetThread(PVOID StartContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	LARGE_INTEGER delay = { 0 };
	delay.QuadPart = -(ONE_MS_IN_FILETIME * 100); // 100ms
	PVOID waitEvents[2] = { &gWorkerThreadShutdown, &gWorkerThreadSignal };

	UNREFERENCED_PARAMETER(StartContext);

	do
	{
		ntStatus = KeWaitForMultipleObjects(2, waitEvents, WaitAny, Executive, KernelMode, FALSE, &delay, NULL);
		switch (ntStatus)
		{
		case STATUS_WAIT_0:
			break;
		case STATUS_WAIT_1:
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Silhouette: Performing async WS reduction\n");
			// fall through
		case STATUS_TIMEOUT:
			EmptyWorkingSet(FALSE);
			break;
		default:
			__debugbreak();
		}
	} while (ntStatus != STATUS_WAIT_0);

	PsTerminateSystemThread(ntStatus);
}
