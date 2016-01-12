#include "stdafx.h"

_Use_decl_annotations_ NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath);
_Use_decl_annotations_ VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject);

//Entry Point to the driver.
//Initializes all 3 parts
_Use_decl_annotations_ NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath)
{
	UNREFERENCED_PARAMETER(InRegistryPath);
	DEBUG("Driver start\n");

	BOOLEAN CreateProcessNotifyExSet = FALSE;
	BOOLEAN LoadImageNotifyRoutineSet = FALSE;
	BOOLEAN WriteProcessMemoryCallbackRoutineSet = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;

	//Set unload routine of driver
	InDriverObject->DriverUnload = UnloadRoutine;

	//Initialize a mutex object so both callbacks don't create any weird race conditions and possibly bsods.
	InitializePTree();

	//Register process creation callback
	if (!NT_SUCCESS(Status = PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, FALSE)))
	{
		DEBUG("Faild to OnCreateProcessNotifyRoutine .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	CreateProcessNotifyExSet = TRUE;

	//Register image (exe, dll) load callback
	if (!NT_SUCCESS(Status = PsSetLoadImageNotifyRoutine(OnImageLoadNotifyRoutine)))
	{
		DEBUG("Faild to OnImageLoadNotifyRoutine .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	LoadImageNotifyRoutineSet = TRUE;

	//Register OpenProcess(used for WriteProcessMemory) callback
	if (!NT_SUCCESS(Status = RegisterOBCallback()))
	{
		DEBUG("Faild to RegisterOBCallback .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	WriteProcessMemoryCallbackRoutineSet = TRUE;

	DEBUG("Driver Loaded\n");
	return STATUS_SUCCESS;

ERROR_ABORT:

	//Something went wrong, just unload the parts that were already loaded
	if (CreateProcessNotifyExSet)
	{
		PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, TRUE);
	}

	if (LoadImageNotifyRoutineSet)
	{
		PsRemoveLoadImageNotifyRoutine(OnImageLoadNotifyRoutine);
	}

	if (WriteProcessMemoryCallbackRoutineSet)
	{
		FreeOBCallback();
	}

	//Destroy the existing process tree and free memory
	DestroyPTree();
	return Status;
}

//Unload routine
_Use_decl_annotations_ VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject)
{
	UNREFERENCED_PARAMETER(InDriverObject);
	//Unload all registered callbacks and destroy process tree
	PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotifyRoutine);
	FreeOBCallback();
	DestroyPTree();
	DEBUG("Unloaded\n");
}