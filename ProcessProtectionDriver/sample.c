#include "stdafx.h"

#define FORCES(expr)     {if(!NT_SUCCESS(NtStatus = (expr))) goto ERROR_ABORT;}


NTSTATUS NtMapViewOfSection_Hook(_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect)
{
	PVOID					CallStack[64];
	MODULE_INFORMATION		Mod;
	ULONG					MethodCount;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "HOOK CALLED!\n");


	LhBarrierPointerToModule(0, 0);

	LhBarrierCallStackTrace(CallStack, 64, &MethodCount);

	LhBarrierGetCallingModule(&Mod);

	return STATUS_SUCCESS;
}


NTSTATUS RunTestSuite()
{
	HOOK_TRACE_INFO			hHook = { NULL };
	NTSTATUS                NtStatus;
	ULONG                   ACLEntries[1] = { 0 };
	UNICODE_STRING			SymbolName;


	RtlInitUnicodeString(&SymbolName, L"NtMapViewOfSection");
	/*
	The following shows how to install and remove local hooks...
	*/
	LhSetGlobalExclusiveACL(0, 0);

#pragma warning(disable: 4152)
	FORCES(LhInstallHook(MmGetProcedureAddress(&SymbolName), NtMapViewOfSection_Hook, (PVOID)0x12345678,	&hHook));
#pragma warning(default: 4152)

	// activate the hook for the current thread
	FORCES(LhSetExclusiveACL(ACLEntries, 1, &hHook));

	// this will NOT unhook the entry point. But the associated handler is never called again...
	//LhUninstallHook(&hHook);

	// this will restore ALL entry points of currently rending removals issued by LhUninstallHook()
	//LhWaitForPendingRemovals();

	return STATUS_SUCCESS;

ERROR_ABORT:

	return NtStatus;
}