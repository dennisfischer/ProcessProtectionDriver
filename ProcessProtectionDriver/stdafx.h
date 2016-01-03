#ifndef _STDAFX_H_
#define _STDAFX_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include <Ntifs.h>
#include <wdm.h>
#include "common.h"
#include "memory.h"
#include "ptree.h"
#include "sha2.h"
#include "image_load_routine.h"
#include <Ntstrsafe.h>

#define TD_ASSERT(_exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD UnloadRoutine;

PKGUARDED_MUTEX GlobalMutex;
NTSTATUS RegisterOBCallback();
NTSTATUS FreeOBCallback();
VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo);
VOID OnCreateProcessNotifyRoutine(PEPROCESS InProcess, HANDLE InProcessId, PPS_CREATE_NOTIFY_INFO InCreateInfo);
#endif