#include "stdafx.h"

VOID OnCreateProcessNotifyRoutine(PEPROCESS InProcess, HANDLE InProcessId, PPS_CREATE_NOTIFY_INFO InCreateInfo)
{
	UNREFERENCED_PARAMETER(InProcess);
	DEBUG("OnCreateProcessNotifyRoutine\n");

	//Process exiting
	if (InCreateInfo == NULL)
	{
		//Remove from process tree to prevent reassigned PID collisions
		LockMutex(GlobalMutex);
		RemovePidFromTree((ULONG)HandleToLong(InProcessId));
		UnlockMutex(GlobalMutex);
		DEBUG("Exit OnCreateProcessNotifyRoutine\n");
		return;
	}

	//Is this a chrome.exe process
	if (InCreateInfo->ImageFileName->Length > wcslen(L"chrome.exe") && wcscmp(&InCreateInfo->ImageFileName->Buffer[wcslen(InCreateInfo->ImageFileName->Buffer) - wcslen(L"chrome.exe")], L"chrome.exe") == 0)
	{
		//Is this a parent chrome.exe process
		if (!_stricmp(GetProcessNameFromPid(InCreateInfo->ParentProcessId), "chrome.exe"))
		{
			//No - add child to process tree
			LockMutex(GlobalMutex);
			AddChildPidToTree((ULONG)HandleToLong(InCreateInfo->ParentProcessId), HandleToLong(InProcessId));
			UnlockMutex(GlobalMutex);
		}
		else
		{
			//Yes - add parent to process tree
			LockMutex(GlobalMutex);
			InsertPidToTree((ULONG)HandleToLong(InProcessId));
			UnlockMutex(GlobalMutex);
		}

		DEBUG("PID : %d (%d)  ImageName :%wZ CmdLine : %wZ \n",
			HandleToLong(InProcessId), HandleToLong(InCreateInfo->ParentProcessId),
			InCreateInfo->ImageFileName,
			InCreateInfo->CommandLine
		);
	}
	DEBUG("Exit OnCreateProcessNotifyRoutine\n");
}

