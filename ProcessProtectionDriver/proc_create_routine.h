#ifndef _PROC_CREATE_ROUTINE_H_
#define _PROC_CREATE_ROUTINE_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"
VOID RegisterProcessInTree(HANDLE InParentProcessId, HANDLE InProcessId);

#endif