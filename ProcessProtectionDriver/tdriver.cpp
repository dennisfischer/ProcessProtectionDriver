#include "pch.h"

// coded by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt
// heavily modified to fit purpose of this thesis

const int MAX_ENTRIES = 10;
const int MAX_TREE_ENTRIES = 50;
int pos = 0;
long list[10] = {0};
long chromeTree[MAX_ENTRIES][MAX_TREE_ENTRIES] = {0};

ULONG_PTR GetParentProcessId(HANDLE child) // By Napalm @ NetCore2K
{
	PROCESS_BASIC_INFORMATION pbi = PROCESS_BASIC_INFORMATION();
	ULONG ulSize = 0;

	if (NtQueryInformationProcess(child, ProcessBasicInformation, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
		
		return pbi.UniqueProcessId;

	return (ULONG_PTR)-1;
}

void insertProcessToTree(long pid)
{
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (chromeTree[i] == 0)
		{
			list[i] = pid;

			DbgPrintEx(
				DPFLTR_IHVDRIVER_ID,
				DPFLTR_ERROR_LEVEL,
				"Entries: %d \n",
				(i + 1)
			);
			return;
		}
	}

	list[pos++] = pid;
	for (int i = 0; i < MAX_TREE_ENTRIES; i++)
	{
		chromeTree[pos][i] = 0;
	}
}

bool addChildProcessToTree(long parentPid, long pid)
{
	int position = -1;
	for (int i = 0; i < MAX_ENTRIES; i++)
	{
		if (list[i] == parentPid)
		{
			position = i;
			break;
		}
	}
	//Better expand the tree instead of returning
	if (position == -1)
		return false;

	for (int i = 0; i < MAX_TREE_ENTRIES; i++)
	{
		if (chromeTree[position][i] == 0)
		{
			chromeTree[position][i] = pid;


			DbgPrintEx(
				DPFLTR_IHVDRIVER_ID,
				DPFLTR_ERROR_LEVEL,
				"Children: %d \n",
				(i + 1)
			);
			return true;
		}
	}

	return false;
}

VOID CreateProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	//Process exiting
	if (CreateInfo == NULL)
	{
		return;
	}

	if (wcscmp(CreateInfo->ImageFileName->Buffer, L"chrome.exe"))
	{
		if (!_stricmp(GetProcessNameFromPid(CreateInfo->ParentProcessId), "chrome.exe"))
		{
			addChildProcessToTree(HandleToLong(CreateInfo->ParentProcessId), HandleToLong(ProcessId));
		}
		else
		{
			insertProcessToTree(HandleToLong(ProcessId));
		}

		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			"PID : %d (%d)  ImageName :%wZ CmdLine : %wZ \n",
			ProcessId, CreateInfo->ParentProcessId,
			CreateInfo->ImageFileName,
			CreateInfo->CommandLine
		);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver start\n");

	BOOLEAN CreateProcessNotifyExSet = FALSE;

	NTSTATUS Status = STATUS_SUCCESS;

	DriverObject->DriverUnload = UnloadRoutine;

	Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}
	else
	{
		CreateProcessNotifyExSet = TRUE;
	}

	NTSTATUS status = RegisterCallbackFunction();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Faild to RegisterCallbackFunction .status : 0x%X \n", status);
		goto Exit;
	}


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Loaded\n");
	goto Exit;

Exit:

	if (!NT_SUCCESS(Status))
	{
		if (CreateProcessNotifyExSet == TRUE)
		{
			Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
			TD_ASSERT(Status == STATUS_SUCCESS);
		}
	}

	return Status;
}

//
// Unload routine
//
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	FreeProcFilter();
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloaded\n");
}

//
// PRE OPERATION
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID RegistrationContext, IN  POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PreProcCreateRoutine. \n");


	//if (PreInfo->KernelHandle != 1)
	//{
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Kernel access requested - allow!\n");
	//	goto Exit;
	//}

	PEPROCESS OpenedProcess = (PEPROCESS)PreInfo->Object;
	PEPROCESS CurrentProcess = PsGetCurrentProcess();

	if (OpenedProcess == CurrentProcess)
	{
		goto Exit;
	}

	LPSTR OpenedProcName = GetProcessNameFromPid(PsGetProcessId(OpenedProcess));
	LPSTR TargetProcName = GetProcessNameFromPid(PsGetCurrentProcessId());

	//Names don't match
	if (_stricmp(OpenedProcName, "chrome.exe"))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Not requested onto chrome: %s?\n", OpenedProcName);
		goto Exit;
	}

	//Names match (chrome == chrome) or PIDs match
	if (!_stricmp(TargetProcName, OpenedProcName) || PsGetProcessId(OpenedProcess) == PsGetCurrentProcessId())
	{
		//Now do advanced costly check

		if(PsGetProcessId(OpenedProcess) == PsGetCurrentProcessId())
		{
			goto Exit;
		}

		ULONG_PTR parentHandle = GetParentProcessId(PsGetCurrentProcess());
		unsigned __int64 pid = parentHandle;
		if(parentHandle == (ULONG_PTR)-1)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Parent PID (%d): %d -> %d\n", pid, PsGetProcessId(OpenedProcess), PsGetCurrentProcessId());
			goto Exit;
		}

		for (int i = 0; i < MAX_ENTRIES; i++)
		{
			if (list[i] == pid)
			{
				for (int j = 0; j < MAX_TREE_ENTRIES; j++)
				{
					if (chromeTree[i][j] == HandleToLong(PsGetCurrentProcessId()))
					{
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Self access: %s -> %s\n", OpenedProcName, TargetProcName);
						goto Exit;
					}
				}
				break;
			}
		}

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UNALLOWED access: %s -> %s\n", OpenedProcName, TargetProcName);

	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Requested onto chrome from: %s!\n", GetProcessNameFromPid(PsGetCurrentProcessId()));

	switch (PreInfo->Operation)
	{
		case OB_OPERATION_HANDLE_CREATE:
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Requested access is: %x\n", PreInfo->Parameters->CreateHandleInformation.DesiredAccess);
			PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Access changed to: %x\n", PreInfo->Parameters->CreateHandleInformation.DesiredAccess);
			break;
		default:
			TD_ASSERT(FALSE);
			break;
	}

Exit:
	return OB_PREOP_SUCCESS;
}

//
//POST OPERATION
//

VOID ObjectPostCallback(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcCreateRoutine. \n");
}

//
// REGISTER CALLBACK FUNCTION
//

NTSTATUS RegisterCallbackFunction()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	USHORT filterVersion = ObGetFilterVersion();
	USHORT registrationCount = 1;
	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallBack;
	REG_CONTEXT RegistrationContext;
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;
	if (filterVersion == OB_FLT_REGISTRATION_VERSION)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Filter Version is correct.\n");

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = ObjectPreCallback;
		RegisterOperation.PostOperation = ObjectPostCallback;
		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&Altitude, L"1000");
		RegisterCallBack.Altitude = Altitude;
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Register Callback Function Entry.\n");


		ntStatus = ObRegisterCallbacks(&RegisterCallBack, &_CallBacks_Handle);
		if (ntStatus == STATUS_SUCCESS)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Register Callback Function Successful.\n");
		}
		else
		{
			if (ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Filter Instance Altitude Collision.\n");
			}
			if (ntStatus == STATUS_INVALID_PARAMETER)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Invalid Parameter.\n");
			}
			if (ntStatus == STATUS_ACCESS_DENIED)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "The callback routines do not reside in a signed kernel binary image.\n");
			}
			if (ntStatus == STATUS_INSUFFICIENT_RESOURCES)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Allocate Memory Failed.\n");
			}
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Register Callback Function Failed with 0x%08x\n", ntStatus);
		}
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Filter Version is not supported.\n");
	}
	return ntStatus;
}

//
// FREE PROC FILTER
//

NTSTATUS FreeProcFilter()
{
	// if the callbacks are active - remove them
	if (NULL != _CallBacks_Handle)
	{
		ObUnRegisterCallbacks(_CallBacks_Handle);
		_CallBacks_Handle = NULL;
	}
	return STATUS_SUCCESS ;
}

LPSTR GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;

	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (LPSTR)PsGetProcessImageFileName(Process);
}
