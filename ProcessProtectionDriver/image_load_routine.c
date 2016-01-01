#include "stdafx.h"
VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	NTSTATUS Status;
	LockMutex(GlobalMutex);

	if (InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"dll-injector-sample.dll")) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Malicious DLL Sample - PID : %d ImageName :%wZ\n", HandleToLong(InProcessId), InFullImageName);
		if(!NT_SUCCESS(Status = ZwUnmapViewOfSection(InProcessId, InImageInfo->ImageBase)))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "DLL Unmap failed (%d): %wZ\n", Status, InFullImageName);
		}
	}
	UnlockMutex(GlobalMutex);
}