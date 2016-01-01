#include "stdafx.h"

VOID OnCreateProcessNotifyRoutine(PEPROCESS InProcess, HANDLE InProcessId, PPS_CREATE_NOTIFY_INFO InCreateInfo)
{
	UNREFERENCED_PARAMETER(InProcess);

	//Process exiting
	if (InCreateInfo == NULL)
	{
		LockMutex(GlobalMutex);
		RemovePidFromTree((ULONG)HandleToLong(InProcessId));
		UnlockMutex(GlobalMutex);
		return;
	}

	if (wcscmp(InCreateInfo->ImageFileName->Buffer, L"chrome.exe"))
	{
		if (!_stricmp(GetProcessNameFromPid(InCreateInfo->ParentProcessId), "chrome.exe"))
		{
			LockMutex(GlobalMutex);
			AddChildPidToTree((ULONG)HandleToLong(InCreateInfo->ParentProcessId), HandleToLong(InProcessId));
			UnlockMutex(GlobalMutex);
		}
		else
		{
			LockMutex(GlobalMutex);
			InsertPidToTree((ULONG)HandleToLong(InProcessId));
			UnlockMutex(GlobalMutex);
		}

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PID : %d (%d)  ImageName :%wZ CmdLine : %wZ \n",
			InProcessId, InCreateInfo->ParentProcessId,
			InCreateInfo->ImageFileName,
			InCreateInfo->CommandLine
		);
	}
}

