#ifndef _MEMORY_H_
#define _MEMORY_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"

PVOID AllocMemory(BOOLEAN InZeroMemory, ULONG InSize);
VOID FreeMemory(PVOID InPointer);
VOID CopyMemory(PVOID InDest, PVOID InSource, ULONG InByteCount);
BOOLEAN IsValidPointer(PVOID InPtr);
VOID ZeroMemory(PVOID InTarget,	ULONG InByteCount);

VOID LockMutex(PKGUARDED_MUTEX InMutex);
VOID UnlockMutex(PKGUARDED_MUTEX InMutex);
#endif