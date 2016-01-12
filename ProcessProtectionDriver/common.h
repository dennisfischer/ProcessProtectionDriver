#ifndef _COMMON_H_
#define _COMMON_H_
#if (_MSC_VER > 1000)
#pragma once
#endif
#include "stdafx.h"
//Some code of this file is from Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt

//-----------------------------------------------
//  Defines
//-----------------------------------------------

//Process Security and Access Rights
#define PROCESS_CREATE_THREAD  (0x0002)
#define PROCESS_CREATE_PROCESS (0x0080)
#define PROCESS_TERMINATE      (0x0001)
#define PROCESS_VM_WRITE       (0x0020)
#define PROCESS_VM_READ        (0x0010)
#define PROCESS_VM_OPERATION   (0x0008)
#define PROCESS_SUSPEND_RESUME (0x0800)


#define MAXIMUM_FILENAME_LENGTH 256
//-----------------------------------------------
// callback
//-----------------------------------------------

extern PVOID OB_CALLBACK_HANDLE;

typedef struct _OB_REG_CONTEXT
{
	__in USHORT Version;
	__in UNICODE_STRING Altitude;
	__in USHORT ulIndex;
	OB_OPERATION_REGISTRATION* OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;


//-----------------------------------------------
// PID2ProcName
//-----------------------------------------------
typedef PCHAR (*GET_PROCESS_IMAGE_NAME)(PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

LPSTR GetProcessNameFromPid(HANDLE pid);
//NTSTATUS PsLookupProcessByProcessId(IN HANDLE ulProcId, OUT PEPROCESS* pEProcess);
UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

//Define the Debug macro
#ifdef _DEBUG 
#define DEBUG DbgPrint
#else
#define DEBUG
#endif

#endif

