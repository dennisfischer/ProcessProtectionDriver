#ifndef TDRIVER_H
#define TDRIVER_H
#include "pch.h"
#define TD_ASSERT(_exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define TD_DRIVER_NAME             L"ProcessProtectionDriver"
#define TD_DRIVER_NAME_WITH_EXT    L"ProcessProtectionDriver.sys"

#define TD_NT_DEVICE_NAME          L"\\Device\\ProcessProtectionDriver"
#define TD_DOS_DEVICES_LINK_NAME   L"\\DosDevices\\ProcessProtectionDriver"
#define TD_WIN32_DEVICE_NAME       L"\\\\.\\ProcessProtectionDriver"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID RegistrationContext, IN  POB_PRE_OPERATION_INFORMATION PreInfo);
VOID ObjectPostCallback(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation);
NTSTATUS RegisterCallbackFunction();
NTSTATUS FreeProcFilter();
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH TdDeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH TdDeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH TdDeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH TdDeviceControl;
#endif