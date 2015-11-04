#include "pch.h"

// coded by Behrooz @http://stackoverflow.com/questions/20552300/hook-zwterminateprocess-in-x64-driver-without-ssdt
// heavily modified to fit purpose of this thesis

VOID CreateProcessNotifyEx(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	DbgPrintEx(
		DPFLTR_IHVDRIVER_ID,
		DPFLTR_INFO_LEVEL,
		"PID : 0x%X (%d)  ImageName :%wZ CmdLine : %wZ \n",
		ProcessId, ProcessId,
		CreateInfo->ImageFileName,
		CreateInfo->CommandLine
	);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	//
	// Create our device object.
	//
	UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING(TD_NT_DEVICE_NAME);
	UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(TD_DOS_DEVICES_LINK_NAME);
	PDEVICE_OBJECT Device = NULL;
	BOOLEAN SymLinkCreated = FALSE;
	BOOLEAN CreateProcessNotifiySet = FALSE;

	NTSTATUS Status;
	
	Status = IoCreateDevice(
		DriverObject, // pointer to driver object
		0, // device extension size
		&NtDeviceName, // device name
		FILE_DEVICE_UNKNOWN, // device type
		0, // device characteristics
		FALSE, // not exclusive
		&Device); // returned device object pointer

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	TD_ASSERT(Device == DriverObject->DeviceObject);
	DriverObject->MajorFunction[IRP_MJ_CREATE] = TdDeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = TdDeviceClose;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = TdDeviceCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdDeviceControl;
	DriverObject->DriverUnload = UnloadRoutine;
	Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	SymLinkCreated = TRUE;

	/*Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
	if(!NT_SUCCESS(Status))
	{
		goto Exit;
	} else
	{
		CreateProcessNotifyExSet = TRUE;
	}
	NTSTATUS status = RegisterCallbackFunction();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Faild to RegisterCallbackFunction .status : 0x%X \n", status);
		goto Exit;
	}
	*/

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Loaded\n");


Exit:

	if (!NT_SUCCESS(Status))
	{
		if (CreateProcessNotifyExSet == TRUE) {
			Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
			TD_ASSERT(Status == STATUS_SUCCESS);
		}

		if (SymLinkCreated == TRUE)
		{
			IoDeleteSymbolicLink(&DosDevicesLinkName);
		}

		if (Device != NULL)
		{
			IoDeleteDevice(Device);
		}
	}

	return Status;
}

//
// Unload routine
//
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	FreeProcFilter();
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloaded\n");
}

//
// PRE OPERATION
//
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(IN PVOID RegistrationContext, IN  POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PreProcCreateRoutine. \n");


	if (PreInfo->KernelHandle != 1)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Kernel access requested - allow!\n");
		goto Exit;
	}

	PEPROCESS OpenedProcess = (PEPROCESS)PreInfo->Object;
	PEPROCESS CurrentProcess = PsGetCurrentProcess();

	if (OpenedProcess == CurrentProcess)
	{
		goto Exit;
	}

	LPSTR ProcName = GetProcessNameFromPid(PsGetProcessId(OpenedProcess));
	if (!_stricmp(ProcName, "chrome.exe"))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Not requested onto chrome: %s?\n", ProcName);
		goto Exit;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Requested onto chrome!\n");


	switch (PreInfo->Operation)
	{
		case OB_OPERATION_HANDLE_CREATE:
		case OB_OPERATION_HANDLE_DUPLICATE:
			PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION);
			break;
		default: break;
	}

Exit:
	return OB_PREOP_SUCCESS;
}

//
//POST OPERATION
//

VOID ObjectPostCallback(IN  PVOID RegistrationContext, IN  POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcCreateRoutine. \n");
}

//
// REGISTER CALLBACK FUNCTION
//

NTSTATUS RegisterCallbackFunction()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	USHORT filterVersion = ObGetFilterVersion();
	USHORT registrationCount = 1;
	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallBack;
	REG_CONTEXT RegistrationContext;
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;
	if (filterVersion == OB_FLT_REGISTRATION_VERSION)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Filter Version is correct.\n");

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = ObjectPreCallback;
		RegisterOperation.PostOperation = ObjectPostCallback;
		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&Altitude, L"1000");
		RegisterCallBack.Altitude = Altitude;
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Register Callback Function Entry.\n");


		ntStatus = ObRegisterCallbacks(&RegisterCallBack, &_CallBacks_Handle);
		if (ntStatus == STATUS_SUCCESS)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Register Callback Function Successful.\n");
		}
		else
		{
			if (ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Filter Instance Altitude Collision.\n");
			}
			if (ntStatus == STATUS_INVALID_PARAMETER)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Invalid Parameter.\n");
			}
			if (ntStatus == STATUS_ACCESS_DENIED)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "The callback routines do not reside in a signed kernel binary image.\n");
			}
			if (ntStatus == STATUS_INSUFFICIENT_RESOURCES)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Allocate Memory Failed.\n");
			}
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Register Callback Function Failed with 0x%08x\n", ntStatus);
		}
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Filter Version is not supported.\n");
	}
	return ntStatus;
}

//
// FREE PROC FILTER
//

NTSTATUS FreeProcFilter()
{
	// if the callbacks are active - remove them
	if (NULL != _CallBacks_Handle)
	{
		ObUnRegisterCallbacks(_CallBacks_Handle);
		_CallBacks_Handle = NULL;
	}
	return STATUS_SUCCESS ;
}

LPSTR GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;

	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (LPSTR)PsGetProcessImageFileName(Process);
}


////////////////////////////////////////////////
VOID
TdDeviceUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(TD_DOS_DEVICES_LINK_NAME);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

	//
	// Unregister process notify routines.
	//
	Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
	TD_ASSERT(Status == STATUS_SUCCESS);

	//
	// Delete the link from our device name to a name in the Win32 namespace.
	//

	Status = IoDeleteSymbolicLink(&DosDevicesLinkName);
	if (Status != STATUS_INSUFFICIENT_RESOURCES)
	{
		//
		// IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
		//

		TD_ASSERT(NT_SUCCESS(Status));
	}


	//
	// Delete our device object.
	//

	IoDeleteDevice(DriverObject->DeviceObject);
}

//
// Function:
//
//     TdDeviceCreate
//
// Description:
//
//     This function handles the 'create' irp.
//


NTSTATUS
TdDeviceCreate(
	IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS ;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS ;
}

//
// Function:
//
//     TdDeviceClose
//
// Description:
//
//     This function handles the 'close' irp.
//

NTSTATUS
TdDeviceClose(
	IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS ;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS ;
}

//
// Function:
//
//     TdDeviceCleanup
//
// Description:
//
//     This function handles the 'cleanup' irp.
//

NTSTATUS
TdDeviceCleanup(
	IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS ;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS ;
}

NTSTATUS
TdDeviceControl(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp
	)
{
	PIO_STACK_LOCATION IrpStack;
	ULONG Ioctl;
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(DeviceObject);


	Status = STATUS_SUCCESS;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

	//
	// Complete the irp and return.
	//

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl leaving - status 0x%x\n", Status);
	return Status;
}