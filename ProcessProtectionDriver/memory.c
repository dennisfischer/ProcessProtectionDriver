#include "stdafx.h"

//Most of this functions are from EasyHook @https://github.com/EasyHook/EasyHook
//They copy runtime library behavior for better usage in a driver
#ifndef _DEBUG
#pragma optimize ("", off) // suppress _memset

#endif
VOID ZeroMemory(PVOID InTarget, ULONG InByteCount)
{
	ULONG Index;
	UCHAR* Target = (UCHAR*)InTarget;

	for (Index = 0; Index < InByteCount; Index++)
	{
		*Target = 0;
		Target++;
	}
}
#ifndef _DEBUG
#pragma optimize ("", on) 
#endif

PVOID AllocMemory(BOOLEAN InZeroMemory, ULONG InSize)
{
	PVOID Result = ExAllocatePoolWithTag(NonPagedPool, InSize, 'PROT');

	if (InZeroMemory && (Result != NULL))
		ZeroMemory(Result, InSize);

	return Result;
}

VOID FreeMemory(PVOID InPointer)
{
	if (InPointer != NULL)
	{
		ExFreePoolWithTag(InPointer, 'PROT');
	}
}

VOID CopyMemory(PVOID InDest, PVOID InSource, ULONG InByteCount)
{
	ULONG Index;
	UCHAR* Dest = (UCHAR*)InDest;
	UCHAR* Src = (UCHAR*)InSource;

	for (Index = 0; Index < InByteCount; Index++)
	{
		*Dest = *Src;

		Dest++;
		Src++;
	}
}

#if X64_DRIVER
// Write Protection Off
KIRQL RtlWPOff()
{
	// prevent rescheduling 
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	// disable memory protection (disable WP bit of CR0)   
	UINT64 cr0 = __readcr0();
	cr0 &= ~0x10000;
	__writecr0(cr0);
	// disable interrupts
	_disable();
	return irql;
}

//Write Protection On
void RtlWPOn(KIRQL irql)
{
	// re-enable memory protection (enable WP bit of CR0)   
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	// enable interrupts
	_enable();
	__writecr0(cr0);
	// lower irql again
	KeLowerIrql(irql);
}
#endif

