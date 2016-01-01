#include "stdafx.h"

PVOID OB_CALLBACK_HANDLE = NULL;

OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID InRegistrationContext, IN  POB_PRE_OPERATION_INFORMATION InPreInfo);
VOID ObjectPostCallback(IN  PVOID InRegistrationContext, IN  POB_POST_OPERATION_INFORMATION InPostInfo);

//
// PRE OPERATION
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID InRegistrationContext, IN  POB_PRE_OPERATION_INFORMATION InPreInfo)
{
	UNREFERENCED_PARAMETER(InRegistrationContext);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PreProcCreateRoutine. \n");


	//if (PreInfo->KernelHandle != 1)
	//{
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Kernel access requested - allow!\n");
	//	goto Exit;
	//}

	PEPROCESS OpenedProcess = (PEPROCESS)InPreInfo->Object;
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

		if (PsGetProcessId(OpenedProcess) == PsGetCurrentProcessId())
		{
			goto Exit;
		}


		//FIND / Compare operation here
		LockMutex(GlobalMutex);
		if (findPidInTree(HandleToLong(PsGetCurrentProcessId())) == findPidInTree(HandleToLong(PsGetProcessId(OpenedProcess)))) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Self access: %s -> %s\n", OpenedProcName, TargetProcName);
			UnlockMutex(GlobalMutex);
			goto Exit;
		}
		UnlockMutex(GlobalMutex);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "UNALLOWED access: %s -> %s\n", OpenedProcName, TargetProcName);

	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Requested onto chrome from: %s!\n", GetProcessNameFromPid(PsGetCurrentProcessId()));

	switch (InPreInfo->Operation)
	{
	case OB_OPERATION_HANDLE_CREATE:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Requested access is: %x\n", InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
		InPreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_WRITE);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Access changed to: %x\n", InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
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

VOID ObjectPostCallback(IN  PVOID InRegistrationContext, IN  POB_POST_OPERATION_INFORMATION InPostInfo)
{
	UNREFERENCED_PARAMETER(InRegistrationContext);
	UNREFERENCED_PARAMETER(InPostInfo);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcCreateRoutine. \n");
}

//
// REGISTER CALLBACK FUNCTION
//

NTSTATUS RegisterOBCallback()
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


		ntStatus = ObRegisterCallbacks(&RegisterCallBack, &OB_CALLBACK_HANDLE);
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

NTSTATUS FreeOBCallback()
{
	// if the callbacks are active - remove them
	if (NULL != OB_CALLBACK_HANDLE)
	{
		ObUnRegisterCallbacks(OB_CALLBACK_HANDLE);
		OB_CALLBACK_HANDLE = NULL;
	}
	return STATUS_SUCCESS;
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
