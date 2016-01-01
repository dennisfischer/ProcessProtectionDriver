#include "stdafx.h"

// code by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt
// code by EasyHook @https://github.com/EasyHook/EasyHook
// heavily modified to fit purpose of this thesis

NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath);
VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath)
{
	UNREFERENCED_PARAMETER(InRegistryPath);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver start\n");

	BOOLEAN CreateProcessNotifyExSet = FALSE;
	BOOLEAN LoadImageNotifyRoutineSet = FALSE;
	BOOLEAN WriteProcessMemoryCallbackRoutineSet = FALSE;
	NTSTATUS Status;


	InDriverObject->DriverUnload = UnloadRoutine;

	//Initialize a mutex object so both callbacks don't create any weird race conditions and possibly bsods.
	GlobalMutex = AllocMemory(1, sizeof(KGUARDED_MUTEX));
	KeInitializeGuardedMutex(GlobalMutex);

	InitializePTree();

	if (!NT_SUCCESS(Status = PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, FALSE)))
	{
		goto ERROR_ABORT;
	}
	CreateProcessNotifyExSet = TRUE;

	if (!NT_SUCCESS(Status = PsSetLoadImageNotifyRoutine(OnImageLoadNotifyRoutine)))
	{
		goto ERROR_ABORT;
	}
	LoadImageNotifyRoutineSet = TRUE;


	if (!NT_SUCCESS(Status = RegisterOBCallback()))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Faild to RegisterCallbackFunction .status : 0x%X \n", Status);
		goto ERROR_ABORT;
	}
	WriteProcessMemoryCallbackRoutineSet = TRUE;


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Loaded\n");
	goto ERROR_ABORT;

ERROR_ABORT:

	if (CreateProcessNotifyExSet)
	{
		Status = PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, TRUE);
		TD_ASSERT(Status == STATUS_SUCCESS);
	}

	if (LoadImageNotifyRoutineSet)
	{
		Status = PsRemoveLoadImageNotifyRoutine(OnImageLoadNotifyRoutine);
		TD_ASSERT(Status == STATUS_SUCCESS);
	}

	if(WriteProcessMemoryCallbackRoutineSet)
	{
		FreeOBCallback();
	}

	DestroyPTree();
	FreeMemory(GlobalMutex);
	return Status;
}

//
// Unload routine
//
VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject)
{
	UNREFERENCED_PARAMETER(InDriverObject);

	FreeOBCallback();
	PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotifyRoutine);
	DestroyPTree();
	if (IsValidPointer(GlobalMutex)) {
		FreeMemory(GlobalMutex);
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloaded\n");
}
