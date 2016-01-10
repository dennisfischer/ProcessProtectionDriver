#include "stdafx.h"

VOID OnCreateProcessNotifyRoutine(PEPROCESS InProcess, HANDLE InProcessId, PPS_CREATE_NOTIFY_INFO InCreateInfo)
{
	UNREFERENCED_PARAMETER(InProcess);
	//Process exiting
	if (InCreateInfo == NULL)
	{
		//Remove from process tree to prevent reassigned PID collisions
		RemovePidFromTree((ULONG)HandleToLong(InProcessId));
		return;
	}
	//Is this a chrome.exe process
	if (InCreateInfo->ImageFileName->Length/2 > wcslen(L"chrome.exe") && wcsncmp(&InCreateInfo->ImageFileName->Buffer[InCreateInfo->ImageFileName->Length/2 - wcslen(L"chrome.exe")], L"chrome.exe", wcslen(L"chrome.exe")) == 0)
	{
		RegisterProcessInTree(InCreateInfo->ParentProcessId, InProcessId);
	}
	DEBUG("HAVE Length: %d\n", InCreateInfo->ImageFileName->Length);
	DEBUG("HAVE MaxLength: %d\n", InCreateInfo->ImageFileName->MaximumLength);
	DEBUG("HAVE CountedLength: %d\n", wcslen(InCreateInfo->ImageFileName->Buffer));
	DEBUG("HAVE: %S\n", &InCreateInfo->ImageFileName->Buffer[InCreateInfo->ImageFileName->Length/2 - wcslen(L"chrome.exe")]);
	DEBUG("PID : %d (%d)  ImageName :%wZ CmdLine : %wZ \n" ,
		HandleToLong(InProcessId) , HandleToLong(InCreateInfo->ParentProcessId) ,
		InCreateInfo->ImageFileName ,
		InCreateInfo->CommandLine
	);
}

VOID RegisterProcessInTree(HANDLE InParentProcessId, HANDLE InProcessId)
{
	//Is this a parent chrome.exe process
	if (InParentProcessId != NULL && !_stricmp(GetProcessNameFromPid(InParentProcessId), "chrome.exe"))
	{
		//No - add child to process tree
		AddChildPidToTree((ULONG)HandleToLong(InParentProcessId), HandleToLong(InProcessId));
		DEBUG("CHILD: %d\n", InProcessId);
	}
	else
	{
		//Yes - add parent to process tree
		InsertPidToTree((ULONG)HandleToLong(InProcessId));

		DEBUG("PARENT: %d\n", InProcessId);
	}
}