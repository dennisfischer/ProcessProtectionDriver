#include "stdafx.h"

typedef struct _SHA_WORK_ITEM
{
	WORK_QUEUE_ITEM WorkItem;
	PFILE_OBJECT FileObject;
	PUNICODE_STRING FullImageName;
	char* Result;
	BOOLEAN Done;
	BOOLEAN Allow;
} SHA_WORK_ITEM, *PSHA_WORK_ITEM;


typedef struct _PATCH_WORK_ITEM
{
	WORK_QUEUE_ITEM WorkItem;
	uint8* ImageBase;
	HANDLE ProcessId;
	BOOLEAN Done;
} PATCH_WORK_ITEM, *PPATCH_WORK_ITEM;


void PatchRoutine(PVOID Parameter)
{
	PPATCH_WORK_ITEM WorkItem = (PPATCH_WORK_ITEM)Parameter;
	NTSTATUS Status;

	PRKAPC_STATE apcState = AllocMemory(TRUE, sizeof(KAPC_STATE));
	PEPROCESS pEProcess;
	if (!NT_SUCCESS(Status = PsLookupProcessByProcessId(WorkItem->ProcessId, &pEProcess)))
	{
		DbgPrint("Process Lookup failed: %d\n", Status);
		goto Exit;
	}
	KeStackAttachProcess(pEProcess, apcState);

#ifdef X64_DRIVER
	KIRQL CurrentIRQL = RtlWPOff();
#endif
	DbgPrint("Attached\n");
	uint8* entryPointAbs = ReadPE(WorkItem->ImageBase);

	DbgPrint("DLL! %p\n", WorkItem->ImageBase);
	DbgPrint("Entry! %p\n", entryPointAbs);
	uint8 patch[] = {0xC3};
	CopyMemory(entryPointAbs, patch, sizeof(patch));
#ifdef X64_DRIVER
	RtlWPOn(CurrentIRQL);
#endif

	DbgPrint("Dettached\n");
	KeUnstackDetachProcess(apcState);
	FreeMemory(apcState);
	apcState = NULL;

Exit:
	WorkItem->Done = TRUE;
}

NTSTATUS TryGetFileHanlde(PUNICODE_STRING Path, PHANDLE fileHandle)
{
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStat;

	InitializeObjectAttributes(&objectAttributes, Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	return ZwOpenFile(fileHandle, FILE_READ_DATA, &objectAttributes, &ioStat, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT);
}

NTSTATUS ReadFile(HANDLE fileHandle, ULONG file_size, uint8* fileData)
{
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	IO_STATUS_BLOCK ioStat;

	return ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStat, fileData, file_size, &byteOffset, NULL);
}

NTSTATUS GetFileSize(PFILE_OBJECT fileObject, PLARGE_INTEGER file_size)
{
	return FsRtlGetFileSize(fileObject, file_size);
}

void HashRoutine(PVOID Parameter)
{
	PSHA_WORK_ITEM WorkItem = (PSHA_WORK_ITEM)Parameter;
	NTSTATUS Status;
	HANDLE fileHandle = NULL;
	try
	{
		uint8* fileData = NULL;
		PWCH resultString = NULL;

		//Check if we can open the file without path building
		if (NT_SUCCESS(Status = TryGetFileHanlde(WorkItem->FullImageName, &fileHandle)))
		{
			//Yes! system file?
			goto Checksum;
		}

		const wchar_t* SYS_ROOT_PREFIX = L"\\SystemRoot\\";
		wchar_t* FILE_NAME = WorkItem->FullImageName->Buffer;
		if (wcsncmp(SYS_ROOT_PREFIX, WorkItem->FullImageName->Buffer, wcslen(SYS_ROOT_PREFIX)) == 0)
		{
			WorkItem->Allow = TRUE;
			goto Done;
		}

		const wchar_t* HARDDISK_PREFIX = L"\\Device\\HarddiskVolume";
		if (wcsncmp(HARDDISK_PREFIX, WorkItem->FullImageName->Buffer, wcslen(HARDDISK_PREFIX)) == 0)
		{
			goto Done;
		}

		UNICODE_STRING deviceName;
		if (!NT_SUCCESS(Status = IoVolumeDeviceToDosName(WorkItem->FileObject->DeviceObject, &deviceName)) || deviceName.Buffer == NULL)
		{
			goto Fail;
		}
		const wchar_t* DOS_DEVICES_PREFIX = L"\\DosDevices\\";
		wchar_t* DEVICE_NAME = deviceName.Buffer;

		ULONG size = (USHORT)((wcslen(DOS_DEVICES_PREFIX) * sizeof(wchar_t)) + (deviceName.Length) + (WorkItem->FullImageName->Length) + sizeof(L'\0'));
		resultString = AllocMemory(TRUE, size);

		wcscpy(resultString, DOS_DEVICES_PREFIX);
		wcsncat(resultString, DEVICE_NAME, deviceName.Length / sizeof(wchar_t));
		wcsncat(resultString, FILE_NAME, WorkItem->FullImageName->Length / sizeof(wchar_t));

		DEBUG("Dos Name: %S\n" , DOS_DEVICES_PREFIX);
		DEBUG("Device Path: %wZ\n" , deviceName);
		DEBUG("File Path (L: %d, M:%d): %wZ\n" , WorkItem->FullImageName->Length , WorkItem->FullImageName->MaximumLength , WorkItem->FullImageName);
		DEBUG("Concated Path (%d): %S\n" , wcslen(FILE_NAME) , resultString);

		goto BuildPath;

	BuildPath:
		UNICODE_STRING Path;
		USHORT formattedSize = (USHORT)(wcslen(resultString) * sizeof(wchar_t) + sizeof(L'\0'));
		Path.Buffer = resultString;
		Path.Length = (USHORT)(wcslen(resultString) * sizeof(wchar_t));
		Path.MaximumLength = (USHORT)formattedSize;

		DEBUG("Full Path now is: %wZ\n" , &Path);
		if (!NT_SUCCESS(Status = TryGetFileHanlde(&Path, &fileHandle)))
		{
			DEBUG("ZwOpenFile failed: %d\n" , Status);
			goto Fail;
		}

	Checksum:
		LARGE_INTEGER file_size;
		if (!NT_SUCCESS(Status = GetFileSize(WorkItem->FileObject, &file_size)))
		{
			DEBUG("FsRtlGetFileSize failed: %d\n" , Status);
			goto Fail;
		}
		DEBUG("File size is: %lu\n" , file_size.LowPart);
		fileData = AllocMemory(TRUE, file_size.LowPart);
		if (!NT_SUCCESS(Status = ReadFile(fileHandle, file_size.LowPart, fileData)))
		{
			DEBUG("ZwReadFile failed %d\n" , Status);
			goto Fail;
		}

		WorkItem->Result = calc_sha256(fileData, file_size.LowPart);
		goto Done;
	Fail:
		WorkItem->Result = NULL;
	Done:
		FreeMemory(fileData);
		fileData = NULL;

		FreeMemory(resultString);
		resultString = NULL;
	}
	finally
	{
		if (fileHandle)
		{
			if (!NT_SUCCESS(Status = ZwClose(fileHandle)))
			{
				DEBUG("ZwClose failed %d\n" , Status);
			}
		}
		WorkItem->Done = TRUE;
	}
}

VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	//Should the dll get loaded into a chrome process?
	if (FindPidInTree(HandleToULong(InProcessId)) == 0)
	{
		//Maybe we're just coming early into this routine - check if we can insert initial parent
		//Is this a chrome.exe process
		if (InFullImageName->Length > wcslen(L"chrome.exe") && wcsncmp(&InFullImageName->Buffer[InFullImageName->Length - wcslen(L"chrome.exe")], L"chrome.exe", wcslen(L"chrome.exe")) == 0)
		{
			RegisterProcessInTree(NULL, InProcessId);
			goto Check;
		}

		//No - then do nothing
		DEBUG("Not tracked: PID: %d ImageName: %wZ\n" , HandleToLong(InProcessId) , InFullImageName);
		goto Allow;
	}
Check:
	//Is this a dll file?
	if (InFullImageName->Length / 2 < wcslen(L"dll") || wcsncmp(&InFullImageName->Buffer[InFullImageName->Length / 2 - wcslen(L"dll")], L"dll", wcslen(L"dll")) != 0)
	{
		DEBUG("Not a DLL ImageName: %wZ\n" , InFullImageName);
		//No - then do nothing
		goto Allow;
	}

	DEBUG("Malicious DLL Sample - PID: %d ImageName: %wZ\n" , HandleToLong(InProcessId) , InFullImageName);

	if (!InImageInfo->ExtendedInfoPresent)
	{
		goto Deny;
	}
	IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);

	DEBUG("Image Info Size: %llu\n" , InImageInfo->ImageSize);

	PSHA_WORK_ITEM sha_work_item = AllocMemory(TRUE, sizeof(SHA_WORK_ITEM));
	if (sha_work_item == NULL)
	{
		goto Deny;
	}
	sha_work_item->FileObject = ex->FileObject;
	sha_work_item->FullImageName = InFullImageName;
	sha_work_item->Result = NULL;
	sha_work_item->Allow = FALSE;
	sha_work_item->Done = FALSE;
	ExInitializeWorkItem(&sha_work_item->WorkItem, HashRoutine, sha_work_item);
	ExQueueWorkItem(&sha_work_item->WorkItem, CriticalWorkQueue);

	LARGE_INTEGER wait_large_integer;
	wait_large_integer.QuadPart = -100000;
	while (sha_work_item->Done == FALSE)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
	}

	if (sha_work_item->Allow == TRUE)
	{
		goto Allow;
	}
	if (sha_work_item->Result == NULL)
	{
		DEBUG("Something went wrong, deny load!");
		goto Deny;
	}

	int length = sizeof(WHITELIST) / sizeof(WHITELIST[0]);
	for (int i = 0; i < length; i++)
	{
		if (strcmp(sha_work_item->Result, WHITELIST[i]) == 0)
		{
			DEBUG("EQUAL!\n");
			goto Allow;
		}
	}

	DEBUG("NOT EQUAL!\n");
	DbgPrint("\"%s\", // %wZ\n", sha_work_item->Result, InFullImageName);

	FreeMemory(sha_work_item);
	sha_work_item = NULL;
	goto Deny;

Deny:

	PPATCH_WORK_ITEM patch_work_item = AllocMemory(TRUE, sizeof(PATCH_WORK_ITEM));
	if (patch_work_item == NULL)
	{
		goto Deny;
	}
	patch_work_item->ImageBase = InImageInfo->ImageBase;
	patch_work_item->ProcessId = InProcessId;
	patch_work_item->Done = FALSE;
	ExInitializeWorkItem(&patch_work_item->WorkItem, PatchRoutine, patch_work_item);
	ExQueueWorkItem(&patch_work_item->WorkItem, CriticalWorkQueue);

	LARGE_INTEGER wait_large_integer;
	wait_large_integer.QuadPart = -100000;
	while (patch_work_item->Done == FALSE)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
	}
	FreeMemory(patch_work_item);


	DEBUG("Deny!\n");
Allow:
	return;
	//DEBUG("Allow!\n");
}

char* sha256_hash_string(char hash[SHA256_DIGEST_LENGTH])
{
	char* sha256string = AllocMemory(TRUE, sizeof(char) * SHA256_DIGEST_STRING_LENGTH);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(&sha256string[i * 2], "%02x", (uint8)hash[i]);
	}

	return sha256string;
}


char* calc_sha256(uint8* base, ULONG size)
{
	char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	uint8* buffer = AllocMemory(TRUE, size);
	CopyMemory(buffer, base, size);
	SHA256_Update(&sha256, buffer, size);
	SHA256_Final((uint8_t*)hash, &sha256);
	char* finalHash = sha256_hash_string(hash);
	FreeMemory(buffer);
	buffer = NULL;
	return finalHash;
}


uint8* ReadPE(uint8* base)
{
	uint32 entryPoint;
	struct MzHeader* mz = AllocMemory(TRUE, sizeof(struct MzHeader));
	CopyMemory(mz, base, sizeof(struct MzHeader));

	struct PeHeader* pe = AllocMemory(TRUE, sizeof(struct PeHeader));
	CopyMemory(pe, base + mz->lfaNew, sizeof(struct PeHeader));

	struct Pe32OptionalHeader* peOpt = AllocMemory(TRUE, sizeof(struct Pe32OptionalHeader));
	CopyMemory(peOpt, base + mz->lfaNew + sizeof(struct PeHeader), sizeof(struct Pe32OptionalHeader));
	entryPoint = peOpt->addressOfEntryPoint;

	peOpt->addressOfEntryPoint = 0;
	CopyMemory(base + mz->lfaNew + sizeof(struct PeHeader), peOpt, sizeof(struct Pe32OptionalHeader));

	FreeMemory(peOpt);
	peOpt = NULL;
	FreeMemory(pe);
	pe = NULL;
	FreeMemory(mz);
	mz = NULL;

	return base + entryPoint;
}

