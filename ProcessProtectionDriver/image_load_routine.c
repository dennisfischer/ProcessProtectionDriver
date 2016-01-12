#include "stdafx.h"

//Callback routine whenever an image file (dll, exe, ...) is mapped into memory
//This function is called before execution starts
//LdrLoadLoaderLock is held, so memory modifications should only occur in a work-item
VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	//Should the dll get loaded into a chrome process?
	if (FindPidInTree(HandleToULong(InProcessId)) == 0)
	{
		//Maybe we're just coming early into this routine - check if this is a chrome.exe process
		LPSTR OpenedProcName = GetProcessNameFromPid(InProcessId);

		if (strcmp(OpenedProcName, "chrome.exe") == 0)
		{
			//This is a chrome process, check if the dlls are okay.
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

	//Was this DLL loaded from a file?
	if (!InImageInfo->ExtendedInfoPresent)
	{
		//No, then we can't check its hash -> deny
		goto Deny;
	}

	//Get the extended information
	IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);
	DEBUG("Image Info Size: %llu\n" , InImageInfo->ImageSize);

	//Create first work item
	//This work item creates the sha256 file hash
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

	//Work item was queued - wait for its end
	LARGE_INTEGER wait_large_integer;
	wait_large_integer.QuadPart = -100000;
	while (sha_work_item->Done == FALSE)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
	}

	//Was file a system root file?
	//Note - this checked can be removed to increase security, by also checking system root files
	if (sha_work_item->Allow == TRUE)
	{
		//They cannot be modified without admin privileges -> allow
		goto Allow;
	}
	//Did we even get a result?
	if (sha_work_item->Result == NULL)
	{
		//Something went wrong inside hash routine.
		//This could be an indication of a driver bug and if it occurs often
		//the driver should be checked for a bug
		//In all cases, deny the load as we don't know the reason for failing
		DEBUG("Something went wrong, deny load!");
		goto Deny;
	}

	//Check if the given hash is in the whitelist
	int length = sizeof(WHITELIST) / sizeof(WHITELIST[0]);
	for (int i = 0; i < length; i++)
	{
		if (strcmp(sha_work_item->Result, WHITELIST[i]) == 0)
		{
			//There's a match found -> allow
			DEBUG("EQUAL!\n");
			goto Allow;
		}
	}

	//No match found -> deny
	DEBUG("NOT EQUAL!\n");
	//This statement is purposly not marked with the DEBUG macro
	//In case the driver is running under release mode, the output of
	//Dbgview.exe can be used to fill in a whitelist after observing a process start
	//Most entries of the whitelist have been generated this way
	DbgPrint("\"%s\", // %wZ\n", sha_work_item->Result, InFullImageName);

	FreeMemory(sha_work_item);
	sha_work_item = NULL;
	goto Deny;

Deny:
	//So now we know that the DLL was NOT on the whitelist
	//Start the patch work item
	PPATCH_WORK_ITEM patch_work_item = AllocMemory(TRUE, sizeof(PATCH_WORK_ITEM));
	if (patch_work_item == NULL)
	{
		goto Deny;
	}
	patch_work_item->ImageBase = InImageInfo->ImageBase;
	patch_work_item->ImageSize = InImageInfo->ImageSize;
	patch_work_item->ProcessId = InProcessId;
	patch_work_item->Done = FALSE;
	ExInitializeWorkItem(&patch_work_item->WorkItem, PatchRoutine, patch_work_item);
	ExQueueWorkItem(&patch_work_item->WorkItem, CriticalWorkQueue);
	
	//Wait until patching is done
	while (patch_work_item->Done == FALSE)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
	}
	FreeMemory(patch_work_item);

	DEBUG("Deny!\n");
Allow:
	//Independent of deny / allow -> resume suspended process now
	return;
}

//This is the patch routine which will break the DLL file
#pragma alloc_text(PAGE, PatchRoutine)
void PatchRoutine(PVOID Parameter)
{
	PPATCH_WORK_ITEM WorkItem = (PPATCH_WORK_ITEM)Parameter;
	NTSTATUS Status;

	//To access the dll in memory, we have to reach into the process virtual memory
	PRKAPC_STATE apcState = AllocMemory(TRUE, sizeof(KAPC_STATE));
	PEPROCESS pEProcess;
	if (!NT_SUCCESS(Status = PsLookupProcessByProcessId(WorkItem->ProcessId, &pEProcess)))
	{
		DEBUG("Process Lookup failed: %d\n" , Status);
		goto Exit;
	}
	//We attach to it here
	KeStackAttachProcess(pEProcess, apcState);

	//First of all Write protection is disabled
#ifdef X64_DRIVER
	KIRQL CurrentIRQL = RtlWPOff();
#endif
	DEBUG("Attached\n");
	//The IRQL needs to be lowered to <=APC_LEVEL, so that PAGE faults don't lead to a BugCheck
	KeLowerIrql(APC_LEVEL);
	//Get the entryPoint of the dll
	uint8* entryPointAbs = ReadPE(WorkItem->ImageBase);

	DEBUG("DLL! %p\n", WorkItem->ImageBase);
	DEBUG("Entry! %p\n", entryPointAbs);
	//Patch the entry point function by writing a ret instruction
	uint8 patch[] = {0xC3}; //ret
	CopyMemory(entryPointAbs, patch, sizeof(patch));
	
	//Undo KeLowerIRQL to previous IRQL level from RtlWpOff
	KeRaiseIrqlToDpcLevel();
	//And enabled again
#ifdef X64_DRIVER
	RtlWPOn(CurrentIRQL);
#endif

	DEBUG("Dettached\n");
	//And after patching is done, we detach from it
	KeUnstackDetachProcess(apcState);
	FreeMemory(apcState);
	apcState = NULL;

Exit:
	WorkItem->Done = TRUE;
}

//This is the hash routine which generates the sha256 hash
void HashRoutine(PVOID Parameter)
{
	PSHA_WORK_ITEM WorkItem = (PSHA_WORK_ITEM)Parameter;
	NTSTATUS Status;

	//We will need to get a fileHandle
	HANDLE fileHandle = NULL;
	try
	{
		uint8* fileData = NULL;
		PWCH resultString = NULL;

		//The following part tries to build a path
		//Sometimes this is necessary as FullImageName cannot be opened without further modifications
		//Check if we can open the file without path building
		if (NT_SUCCESS(Status = TryGetFileHanlde(WorkItem->FullImageName, &fileHandle)))
		{
			//Yes! system file?
			goto Checksum;
		}

		//Check if the file has SystemRoot prefix
		const wchar_t* SYS_ROOT_PREFIX = L"\\SystemRoot\\";
		wchar_t* FILE_NAME = WorkItem->FullImageName->Buffer;
		if (wcsncmp(SYS_ROOT_PREFIX, WorkItem->FullImageName->Buffer, wcslen(SYS_ROOT_PREFIX)) == 0)
		{
			//This is the case described in the image callback routine.
			//Set goto Done, to goto Checksum for more security
			WorkItem->Allow = TRUE;
			goto Done;
		}

		//Check if there's a harddisk prefix present
		const wchar_t* HARDDISK_PREFIX = L"\\Device\\HarddiskVolume";
		if (wcsncmp(HARDDISK_PREFIX, WorkItem->FullImageName->Buffer, wcslen(HARDDISK_PREFIX)) == 0)
		{
			goto Done;
		}

		//If we reach this point, the DLL probably wasn't a system file, or the path was so far invalid
		//The following part constructs the full path by using tree parts
		//\DosDevices\{DriverLetter}\{FullImageName}

		//Get the drive letter
		UNICODE_STRING deviceName;
		if (!NT_SUCCESS(Status = IoVolumeDeviceToDosName(WorkItem->FileObject->DeviceObject, &deviceName)) || deviceName.Buffer == NULL)
		{
			goto Fail;
		}

		const wchar_t* DOS_DEVICES_PREFIX = L"\\DosDevices\\";
		wchar_t* DEVICE_NAME = deviceName.Buffer;

		//Calculate target buffer size
		ULONG size = (USHORT)((wcslen(DOS_DEVICES_PREFIX) * sizeof(wchar_t)) + (deviceName.Length) + (WorkItem->FullImageName->Length) + sizeof(L'\0'));
		resultString = AllocMemory(TRUE, size);

		//Copy each part into the resulting String
		wcscpy(resultString, DOS_DEVICES_PREFIX);
		wcsncat(resultString, DEVICE_NAME, deviceName.Length / sizeof(wchar_t));
		wcsncat(resultString, FILE_NAME, WorkItem->FullImageName->Length / sizeof(wchar_t));

		DEBUG("Dos Name: %S\n" , DOS_DEVICES_PREFIX);
		DEBUG("Device Path: %wZ\n" , deviceName);
		DEBUG("File Path (L: %d, M:%d): %wZ\n" , WorkItem->FullImageName->Length , WorkItem->FullImageName->MaximumLength , WorkItem->FullImageName);
		DEBUG("Concated Path (%d): %S\n" , wcslen(FILE_NAME) , resultString);

		goto BuildPath;

	BuildPath:
		//This part builds a unicode string given the resultString
		UNICODE_STRING Path;
		USHORT formattedSize = (USHORT)(wcslen(resultString) * sizeof(wchar_t) + sizeof(L'\0'));
		Path.Buffer = resultString;
		Path.Length = (USHORT)(wcslen(resultString) * sizeof(wchar_t));
		Path.MaximumLength = (USHORT)formattedSize;

		//Let's see if we can open the file now
		DEBUG("Full Path now is: %wZ\n" , &Path);
		if (!NT_SUCCESS(Status = TryGetFileHanlde(&Path, &fileHandle)))
		{
			//We still can't open it -> deny
			DEBUG("ZwOpenFile failed: %d\n" , Status);
			goto Fail;
		}

	Checksum:
		//Finally build the checksum

		//Get the file size
		LARGE_INTEGER file_size;
		if (!NT_SUCCESS(Status = GetFileSize(WorkItem->FileObject, &file_size)))
		{
			DEBUG("FsRtlGetFileSize failed: %d\n" , Status);
			goto Fail;
		}
		DEBUG("File size is: %lu\n" , file_size.LowPart);
		
		//Allocate data buffer and read file into buffer
		fileData = AllocMemory(TRUE, file_size.LowPart);
		if (!NT_SUCCESS(Status = ReadFile(fileHandle, file_size.LowPart, fileData)))
		{
			DEBUG("ZwReadFile failed %d\n" , Status);
			goto Fail;
		}

		//Finally hash the data contained inside fileData
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
		//If an exception occurs we need to clean up and close handles
		if (fileHandle)
		{
			if (!NT_SUCCESS(Status = ZwClose(fileHandle)))
			{
				DEBUG("ZwClose failed %d\n" , Status);
			}
		}
		//And of course stop blocking the calling thread
		WorkItem->Done = TRUE;
	}
}

//This function wraps ZwOpenFile
NTSTATUS TryGetFileHanlde(PUNICODE_STRING Path, PHANDLE fileHandle)
{
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStat;

	InitializeObjectAttributes(&objectAttributes, Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	return ZwOpenFile(fileHandle, FILE_READ_DATA, &objectAttributes, &ioStat, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT);
}

//This function wraps ZwReadFile
NTSTATUS ReadFile(HANDLE fileHandle, ULONG file_size, uint8* fileData)
{
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	IO_STATUS_BLOCK ioStat;

	return ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStat, fileData, file_size, &byteOffset, NULL);
}

//This function wraps FsRtlGetFileSize
NTSTATUS GetFileSize(PFILE_OBJECT fileObject, PLARGE_INTEGER file_size)
{
	return FsRtlGetFileSize(fileObject, file_size);
}

//This function converts the given hash (32 characters) to 64 characters hex representation
char* sha256_hash_string(char hash[SHA256_DIGEST_LENGTH])
{
	char* sha256string = AllocMemory(TRUE, sizeof(char) * SHA256_DIGEST_STRING_LENGTH);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(&sha256string[i * 2], "%02x", (uint8)hash[i]);
	}

	return sha256string;
}

//This function calls the required sha2.c functions to generate the hash
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

//This function with structs is taken from kallisti5 @https://github.com/kallisti5/readpe/blob/master/readpe.c
//Given a base address, the PE Header is read and destroyed
uint8* ReadPE(uint8* base)
{
	//First read the whole data into header structs
	uint32 entryPoint;
	struct MzHeader* mz = AllocMemory(TRUE, sizeof(struct MzHeader));
	CopyMemory(mz, base, sizeof(struct MzHeader));

	struct PeHeader* pe = AllocMemory(TRUE, sizeof(struct PeHeader));
	CopyMemory(pe, base + mz->lfaNew, sizeof(struct PeHeader));

	struct Pe32OptionalHeader* peOpt = AllocMemory(TRUE, sizeof(struct Pe32OptionalHeader));
	CopyMemory(peOpt, base + mz->lfaNew + sizeof(struct PeHeader), sizeof(struct Pe32OptionalHeader));

	//Save the entrypoint
	entryPoint = peOpt->addressOfEntryPoint;

	//Start destroying the header
	//Unset the entry point so nothing will execute after we're finished
	peOpt->addressOfEntryPoint = 0;
	CopyMemory(base + mz->lfaNew + sizeof(struct PeHeader), peOpt, sizeof(struct Pe32OptionalHeader));

	//Zero the MzHeader, so injections with SetWindowsHookEx aren't functional
	RtlZeroMemory(base, sizeof(struct MzHeader));

	FreeMemory(peOpt);
	peOpt = NULL;
	FreeMemory(pe);
	pe = NULL;
	FreeMemory(mz);
	mz = NULL;

	return base + entryPoint;
}

