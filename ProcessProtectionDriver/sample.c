#include "stdafx.h"

#define FORCES(expr)     {if(!NT_SUCCESS(NtStatus = (expr))) goto ERROR_ABORT;}

BOOLEAN KeCancelTimer_Hook(PKTIMER InTimer)
{
	PVOID					CallStack[64];
	MODULE_INFORMATION		Mod;
	ULONG					MethodCount;

	LhBarrierPointerToModule(0, 0);

	LhBarrierCallStackTrace(CallStack, 64, &MethodCount);

	LhBarrierGetCallingModule(&Mod);

	return KeCancelTimer(InTimer);
}


NTSTATUS RunTestSuite()
{
	HOOK_TRACE_INFO			hHook = { NULL };
	NTSTATUS                NtStatus;
	ULONG                   ACLEntries[1] = { 0 };
	UNICODE_STRING			SymbolName;
	KTIMER					Timer;


	RtlInitUnicodeString(&SymbolName, L"KeCancelTimer");

	/*
	The following shows how to install and remove local hooks...
	*/
#pragma warning(disable: 4152)
	FORCES(LhInstallHook(MmGetSystemRoutineAddress(&SymbolName),	KeCancelTimer_Hook,	(PVOID)0x12345678,	&hHook));
#pragma warning(default: 4152)

	// won't invoke the hook handle because hooks are inactive after installation
	KeInitializeTimer(&Timer);

	KeCancelTimer(&Timer);

	// activate the hook for the current thread
	FORCES(LhSetInclusiveACL(ACLEntries, 1, &hHook));

	// will be redirected into the handler...
	KeCancelTimer(&Timer);

	// this will NOT unhook the entry point. But the associated handler is never called again...
	LhUninstallHook(&hHook);

	// this will restore ALL entry points of currently rending removals issued by LhUninstallHook()
	LhWaitForPendingRemovals();

	return STATUS_SUCCESS;

ERROR_ABORT:

	return NtStatus;
}