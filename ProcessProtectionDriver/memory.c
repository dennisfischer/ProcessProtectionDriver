#include "stdafx.h"

PVOID AllocMemory(BOOLEAN InZeroMemory, ULONG InSize)
{
	PVOID Result = ExAllocatePoolWithTag(NonPagedPool, InSize, 'PROT');

	if (InZeroMemory && (Result != NULL))
		RtlZeroMemory(Result, InSize);

	return Result;
}

VOID FreeMemory(PVOID InPointer)
{
	ExFreePool(InPointer);
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

BOOLEAN MoveMemory(PVOID InDest, PVOID InSource, ULONG InByteCount)
{
	PVOID Buffer = AllocMemory(FALSE, InByteCount);

	if (Buffer == NULL)
		return FALSE;

	RtlCopyMemory(Buffer, InSource, InByteCount);
	RtlCopyMemory(InDest, Buffer, InByteCount);

	FreeMemory(Buffer);

	return TRUE;
}


VOID LockMutex(PKGUARDED_MUTEX InMutex)
{
	KeEnterGuardedRegion();
	KeAcquireGuardedMutex(InMutex);
}

VOID UnlockMutex(PKGUARDED_MUTEX InMutex)
{
	KeReleaseGuardedMutex(InMutex);
	KeLeaveGuardedRegion();
}