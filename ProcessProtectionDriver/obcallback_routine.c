#include "stdafx.h"

PVOID OB_CALLBACK_HANDLE = NULL;
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 },{ 0 } };
OB_CALLBACK_REGISTRATION CBCallbackRegistration = { 0 };
OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
REG_CONTEXT RegistrationContext = { 0 };

//
// PRE OPERATION
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID InRegistrationContext, IN  POB_PRE_OPERATION_INFORMATION InPreInfo)
{
	UNREFERENCED_PARAMETER(InRegistrationContext);
	DEBUG("PreProcCreateRoutine. \n");

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
		DEBUG("Not requested onto chrome: %s?\n", OpenedProcName);
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

		ULONG currentPid = FindPidInTree(HandleToLong(PsGetCurrentProcessId()));
		ULONG openedPid = FindPidInTree(HandleToLong(PsGetProcessId(OpenedProcess)));

		if (currentPid == openedPid) {
			DEBUG("Self access: %s -> %s\n", OpenedProcName, TargetProcName);
			UnlockMutex(GlobalMutex);
			goto Exit;
		}
		UnlockMutex(GlobalMutex);
		DEBUG("UNALLOWED access: %s -> %s\n", OpenedProcName, TargetProcName);

	}

	DEBUG("Requested onto chrome from: %s!\n", GetProcessNameFromPid(PsGetCurrentProcessId()));

	switch (InPreInfo->Operation)
	{
	case OB_OPERATION_HANDLE_CREATE:
		DEBUG("Requested access is: %x\n", InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
	//	InPreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_WRITE);
		DEBUG("Access changed to: %x\n", InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
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
	DEBUG("PostProcCreateRoutine. \n");
}

//
// REGISTER CALLBACK FUNCTION
//
NTSTATUS RegisterOBCallback()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;


		DEBUG("Filter Version is correct.\n");

		CBOperationRegistrations[0].ObjectType = PsProcessType;
		CBOperationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE;
		CBOperationRegistrations[0].PreOperation = ObjectPreCallback;
		CBOperationRegistrations[0].PostOperation = ObjectPostCallback;

		UNICODE_STRING Altitude;
		RtlInitUnicodeString(&Altitude, L"1000");
		CBObRegistration.Altitude = Altitude;
		CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		CBObRegistration.OperationRegistrationCount = 1;
		CBObRegistration.RegistrationContext = &CBCallbackRegistration;
		CBObRegistration.OperationRegistration = CBOperationRegistrations;
		DEBUG("Register Callback Function Entry.\n");


		ntStatus = ObRegisterCallbacks(&CBObRegistration, &OB_CALLBACK_HANDLE);
		if (ntStatus == STATUS_SUCCESS)
		{
			DEBUG("Register Callback Function Successful.\n");
		}
		else
		{
			DEBUG("Register Callback Function Failed with 0x%08x\n", ntStatus);
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
