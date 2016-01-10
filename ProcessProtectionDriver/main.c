#include "stdafx.h"

// code by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt
// code by EasyHook @https://github.com/EasyHook/EasyHook
// heavily modified to fit purpose of this thesis

NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath);
VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject);

VOID Initalize();
VOID Shutdown();

_Use_decl_annotations_ NTSTATUS DriverEntry(IN PDRIVER_OBJECT InDriverObject, IN PUNICODE_STRING InRegistryPath)
{
	UNREFERENCED_PARAMETER(InRegistryPath);
	DEBUG("Driver start\n");

	BOOLEAN CreateProcessNotifyExSet = FALSE;
	BOOLEAN LoadImageNotifyRoutineSet = FALSE;
	BOOLEAN WriteProcessMemoryCallbackRoutineSet = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;

	InDriverObject->DriverUnload = UnloadRoutine;

	Initalize();

	if (!NT_SUCCESS(Status = PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, FALSE)))
	{
		DEBUG("Faild to OnCreateProcessNotifyRoutine .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	CreateProcessNotifyExSet = TRUE;


	if (!NT_SUCCESS(Status = PsSetLoadImageNotifyRoutine(OnImageLoadNotifyRoutine)))
	{
		DEBUG("Faild to OnImageLoadNotifyRoutine .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	LoadImageNotifyRoutineSet = TRUE;

	if (!NT_SUCCESS(Status = RegisterOBCallback()))
	{
		DEBUG("Faild to RegisterOBCallback .status : 0x%X \n" , Status);
		goto ERROR_ABORT;
	}
	WriteProcessMemoryCallbackRoutineSet = TRUE;

	DEBUG("Driver Loaded\n");

	return STATUS_SUCCESS ;

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

	if (WriteProcessMemoryCallbackRoutineSet)
	{
		FreeOBCallback();
	}

	Shutdown();
	return Status;
}

//
// Unload routine
//
_Use_decl_annotations_ VOID UnloadRoutine(IN PDRIVER_OBJECT InDriverObject)
{
	UNREFERENCED_PARAMETER(InDriverObject);
	PsSetCreateProcessNotifyRoutineEx(OnCreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotifyRoutine);
	FreeOBCallback();
	//causes BSODS
	//Shutdown();
	DEBUG("Unloaded\n");
}

VOID Initalize()
{
	//Initialize a mutex object so both callbacks don't create any weird race conditions and possibly bsods.
	InitializePTree();
}

VOID Shutdown()
{
	DestroyPTree();
}

