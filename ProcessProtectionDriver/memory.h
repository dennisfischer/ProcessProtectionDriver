#ifndef _MEMORY_H_
#define _MEMORY_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"

PVOID AllocMemory(BOOLEAN InZeroMemory, ULONG InSize);
VOID FreeMemory(PVOID InPointer);
VOID CopyMemory(PVOID InDest, PVOID InSource, ULONG InByteCount);
VOID ZeroMemory(PVOID InTarget,	ULONG InByteCount);

#ifdef X64_DRIVER
	#include "intrin.h"
	KIRQL RtlWPOff();
	void RtlWPOn(KIRQL irql);
#endif
#endif