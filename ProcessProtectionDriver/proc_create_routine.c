#include "stdafx.h"

VOID OnCreateProcessNotifyRoutine(PEPROCESS InProcess, HANDLE InProcessId, PPS_CREATE_NOTIFY_INFO InCreateInfo)
{
	UNREFERENCED_PARAMETER(InProcess);
	LockMutex(GlobalMutex);

	DEBUG("OnCreateProcessNotifyRoutine\n");
	//Process exiting
	if (InCreateInfo == NULL)
	{
		//Remove from process tree to prevent reassigned PID collisions
		RemovePidFromTree((ULONG)HandleToLong(InProcessId));
		DEBUG("Exit OnCreateProcessNotifyRoutine\n");
		goto Exit;
	}
	//Is this a chrome.exe process
	if (InCreateInfo->ImageFileName->Length > wcslen(L"chrome.exe") && wcscmp(&InCreateInfo->ImageFileName->Buffer[wcslen(InCreateInfo->ImageFileName->Buffer) - wcslen(L"chrome.exe")], L"chrome.exe") == 0)
	{
		RegisterProcessInTree(InCreateInfo->ParentProcessId, InProcessId);
	}
	DEBUG("PID : %d (%d)  ImageName :%wZ CmdLine : %wZ \n" ,
		HandleToLong(InProcessId) , HandleToLong(InCreateInfo->ParentProcessId) ,
		InCreateInfo->ImageFileName ,
		InCreateInfo->CommandLine
	);
	Exit:
	UnlockMutex(GlobalMutex);
	DEBUG("Exit OnCreateProcessNotifyRoutine\n");
}

VOID RegisterProcessInTree(HANDLE InParentProcessId, HANDLE InProcessId)
{
	//Is this a parent chrome.exe process
	if (!_stricmp(GetProcessNameFromPid(InParentProcessId), "chrome.exe"))
	{
		//No - add child to process tree
		AddChildPidToTree((ULONG)HandleToLong(InParentProcessId), HandleToLong(InProcessId));
	}
	else
	{
		//Yes - add parent to process tree
		InsertPidToTree((ULONG)HandleToLong(InProcessId));
	}
}