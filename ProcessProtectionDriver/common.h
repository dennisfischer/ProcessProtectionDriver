#ifndef COMMON_H
#define COMMON_H
#include "pch.h"
// coded by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt

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

PVOID _CallBacks_Handle = NULL;

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
extern "C" NTSTATUS PsLookupProcessByProcessId(IN HANDLE ulProcId, OUT PEPROCESS* pEProcess);
extern "C" UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
extern "C" LONG* NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS  ProcessInformationClass, PVOID             ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
#endif 