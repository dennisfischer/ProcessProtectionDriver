#include "stdafx.h"

//Most of the following code or structure was taken from two sources
// code by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt
// code by Microsoft @https://github.com/Microsoft/Windows-driver-samples/tree/master/general/obcallback
//The executing logic was written by myself

PVOID OB_CALLBACK_HANDLE = NULL;
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = {{0},{0}};
OB_CALLBACK_REGISTRATION CBCallbackRegistration = {0};
OB_CALLBACK_REGISTRATION CBObRegistration = {0};
REG_CONTEXT RegistrationContext = {0};

//
// PRE OPERATION
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID InRegistrationContext, IN  POB_PRE_OPERATION_INFORMATION InPreInfo)
{
	UNREFERENCED_PARAMETER(InRegistrationContext);

	//Get both processes
	PEPROCESS OpenedProcess = (PEPROCESS)InPreInfo->Object;
	PEPROCESS CurrentProcess = PsGetCurrentProcess();

	//Do we have the same process?
	if (OpenedProcess == CurrentProcess)
	{
		//Process self access
		goto Exit;
	}

	//Get the names of the processes
	LPSTR OpenedProcName = GetProcessNameFromPid(PsGetProcessId(OpenedProcess));
	LPSTR TargetProcName = GetProcessNameFromPid(PsGetCurrentProcessId());

	//Is the opened process a chrome.exe?
	if (_stricmp(OpenedProcName, "chrome.exe"))
	{
		//No - we're not interested in other processes
		goto Exit;
	}

	//Names match (chrome == chrome) or PIDs match
	if (!_stricmp(TargetProcName, OpenedProcName) || PsGetProcessId(OpenedProcess) == PsGetCurrentProcessId())
	{
		//Now do advanced check
		//Are PIDs equal?
		if (PsGetProcessId(OpenedProcess) == PsGetCurrentProcessId())
		{
			//I'm not even sure this can occur, as we have already compared both PEPROCESS structs above.
			//But if - pids are equal -> self access
			goto Exit;
		}

		//Locate both processed inside the process tree
		ULONG currentPid = FindPidInTree(HandleToLong(PsGetCurrentProcessId()));
		ULONG openedPid = FindPidInTree(HandleToLong(PsGetProcessId(OpenedProcess)));

		//Do they match?
		if (currentPid == openedPid)
		{
			//Self access (possible cases: parent -> parent, parent -> child, child -> parent, child -> child)
			DEBUG("Self access: %s -> %s\n" , OpenedProcName , TargetProcName);
			goto Exit;
		}

		//Otherwise we have an unallowed access!
		DEBUG("UNALLOWED access: %s -> %s\n" , OpenedProcName , TargetProcName);
	}

	DEBUG("Requested onto chrome from: %s!\n" , GetProcessNameFromPid(PsGetCurrentProcessId()));
	switch (InPreInfo->Operation)
	{
	case OB_OPERATION_HANDLE_CREATE:
		//Remove permission to modify (write into) virtual memory
		DEBUG("Requested access is: %x\n" , InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
		InPreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_WRITE);
		DEBUG("Access changed to: %x\n" , InPreInfo->Parameters->CreateHandleInformation.DesiredAccess);
		break;
	default:
		//This should never get called. We only registered for OB_OPERATION_HANDLE_CREATE events
		TD_ASSERT(FALSE);
		break;
	}

Exit:
	return OB_PREOP_SUCCESS;
}

//
//POST OPERATION
//Required function "stub". Does nothing!
VOID ObjectPostCallback(IN  PVOID InRegistrationContext, IN  POB_POST_OPERATION_INFORMATION InPostInfo)
{
	UNREFERENCED_PARAMETER(InRegistrationContext);
	UNREFERENCED_PARAMETER(InPostInfo);
}

//
//REGISTER CALLBACK FUNCTION
//Registers both (pre and post) callback functions
//This code closely follows the given sources from Microsoft and Behrooz
NTSTATUS RegisterOBCallback()
{
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

	NTSTATUS Status = STATUS_SUCCESS;
	Status = ObRegisterCallbacks(&CBObRegistration, &OB_CALLBACK_HANDLE);
	if (Status == STATUS_SUCCESS)
	{
		DEBUG("Register Callback Function Successful.\n");
	}
	else
	{
		DEBUG("Register Callback Function Failed with 0x%08x\n" , Status);
	}

	return Status;
}

//
// FREE PROC FILTER
// This function removes the registered callbacks
NTSTATUS FreeOBCallback()
{
	// if the callbacks are active - remove them
	if (NULL != OB_CALLBACK_HANDLE)
	{
		ObUnRegisterCallbacks(OB_CALLBACK_HANDLE);
		OB_CALLBACK_HANDLE = NULL;
	}
	return STATUS_SUCCESS ;
}

//Returns the name of a process given a PID
LPSTR GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;

	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (LPSTR)PsGetProcessImageFileName(Process);
}

