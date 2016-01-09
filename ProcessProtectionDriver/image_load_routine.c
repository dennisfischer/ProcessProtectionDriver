#include "stdafx.h"

typedef struct _SHA_WORK_ITEM
{
	WORK_QUEUE_ITEM WorkItem;
	PFILE_OBJECT FileObject;
	PUNICODE_STRING FullImageName;
	char* Result;
	BOOLEAN Done;
} SHA_WORK_ITEM, *PSHA_WORK_ITEM;

void HashRoutine(PVOID Parameter)
{
	PSHA_WORK_ITEM WorkItem = (PSHA_WORK_ITEM)Parameter;
	NTSTATUS Status;
	HANDLE fileHandle = NULL;
	try
	{
		LARGE_INTEGER file_size;
		uint8* fileData = NULL;
		PWCH resultString = NULL;

		if (!NT_SUCCESS(Status = FsRtlGetFileSize(WorkItem->FileObject, &file_size)))
		{
			DbgPrint("FsRtlGetFileSize failed: %d\n", Status);
			goto Fail;
		}

		DbgPrint("File size is: %lu\n", file_size.LowPart);

		const wchar_t* SYS_ROOT_PREFIX = L"\\SystemRoot\\";
		wchar_t* FILE_NAME = WorkItem->FullImageName->Buffer;
		if(wcsncmp(SYS_ROOT_PREFIX, WorkItem->FullImageName->Buffer, wcslen(SYS_ROOT_PREFIX)) == 0)
		{
			SIZE_T size = (wcslen(FILE_NAME) * sizeof(wchar_t)) + sizeof(L'\0');
			resultString = AllocMemory(TRUE, size);
			wcscpy(resultString, FILE_NAME);
			DbgPrint("File Path: %S\n", resultString);
			goto BuildPath;
		}

		UNICODE_STRING deviceName;
		if (!NT_SUCCESS(Status = IoVolumeDeviceToDosName(WorkItem->FileObject->DeviceObject, &deviceName)) || deviceName.Buffer == NULL)
		{
			goto Fail;
		}
		const wchar_t* DOS_DEVICES_PREFIX = L"\\DosDevices\\";
		wchar_t* DEVICE_NAME = deviceName.Buffer;
		DbgPrint("Dos Name: %S\n", DOS_DEVICES_PREFIX);
		DbgPrint("Device Path: %wZ\n", deviceName);
		DbgPrint("File Path: %wZ\n", WorkItem->FullImageName);

		SIZE_T size = (wcslen(DOS_DEVICES_PREFIX) * sizeof(wchar_t)) + (wcslen(DEVICE_NAME) * sizeof(wchar_t)) + (wcslen(FILE_NAME) * sizeof(wchar_t)) + sizeof(L'\0');
		resultString = AllocMemory(TRUE, size);

		wcscpy(resultString, DOS_DEVICES_PREFIX);
		wcscat(resultString, DEVICE_NAME);
		wcscat(resultString, FILE_NAME);

	BuildPath:
		UNICODE_STRING Path;
		SIZE_T formattedSize = wcslen(resultString) * sizeof(wchar_t) + sizeof(L'\0');
		Path.Buffer = resultString;
		Path.Length = wcslen(resultString) * sizeof(wchar_t);
		Path.MaximumLength = formattedSize;

		DbgPrint("Full Path now is: %wZ\n", &Path);

		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK ioStat;

		InitializeObjectAttributes(&objectAttributes, &Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		if (!NT_SUCCESS(Status = ZwOpenFile(&fileHandle, FILE_READ_DATA, &objectAttributes, &ioStat, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT)))
		{
			DbgPrint("ZwOpenFile failed: %d\n", Status);
			goto Fail;
		}

		fileData = AllocMemory(TRUE, file_size.LowPart);
		LARGE_INTEGER byteOffset;
		byteOffset.LowPart = byteOffset.HighPart = 0;

		if (!NT_SUCCESS(Status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStat, fileData, file_size.LowPart, &byteOffset, NULL)))
		{
			DbgPrint("ZwReadFile failed %d\n", Status);
			goto Fail;
		}

		WorkItem->Result = calc_sha256(fileData, file_size.LowPart);
		goto Done;
	Fail:
		WorkItem->Result = NULL;
	Done:
		if (fileData)
		{
			FreeMemory(fileData);
		}
		if (resultString)
		{
			FreeMemory(resultString);
		}
	}
	finally
	{
		if (fileHandle) {
			if (!NT_SUCCESS(Status = ZwClose(fileHandle)))
			{
				DbgPrint("ZwClose failed %d\n", Status);
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
		//No - then do nothing
		return;
	}
	//Is this a dll file?
	if(InFullImageName->Length < 3 || wcscmp(&InFullImageName->Buffer[wcslen(InFullImageName->Buffer)-wcslen(L"dll")], L"dll") != 0)
	{
		//No - then do nothing
		return;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Malicious DLL Sample - PID: %d ImageName: %wZ\n", HandleToLong(InProcessId), InFullImageName);

	if (!InImageInfo->ExtendedInfoPresent)
	{
		goto Deny;
	}
	IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);


	uint8* allowed[12] = {"17783e487bb67f613e825b8daee576e9f78e5df37b80b61be46f9ada4285d3bd", "d0fc863e2541002688cf76400cf317d510e969a812ca4470dde2022f439c8c3f",
		"0f5a0f576d4589e2a40d84d555b3cec8b05e491d6bb686f79451a368578bdd35", "b383bd69a8f1301128a43373fbd5f6f3cb8c70bf3807c0b8db4cfcdc4ac3c3f8",
		"3a78579fd2e8ed905374df3cfa380db3a253494c6247638fc1d52ad12c8007c9", "8d540d484ea41e374fd0107d55d253f87ded4ce780d515d8fd59bbe8c98970a7",
		"efbdbbcd0d954f8fdc53467de5d89ad525e4e4a9cfff8a15d07c6fdb350c407f", "66f5c66dc1d4ad06f18ae9c5c711626ff900bbc51bd2351da3282c2768951251",
		"9d74ce6b8702920009c53b421269c381ef4fd4a6dae075a4575fac6a1163ee57", "a031631de878d945bceb2273978e82a4918ae57996c894eaaf6acf69f4162387",
		"d27490ecb39c6c17adc99a16de091f6c0e144865af487a68c3e988f057195a6c", "1595887fa72397b5070699eecdd1a0dcc5dedf1d46e25f000a9c4d6ba18634e6"};
	try
	{
		DbgPrint("Image Info Size: %llu\n", InImageInfo->ImageSize);

		PSHA_WORK_ITEM sha_work_item = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHA_WORK_ITEM), 'PROT');
		if (sha_work_item == NULL)
		{
			goto Deny;
		}
		sha_work_item->FileObject = ex->FileObject;
		sha_work_item->FullImageName = InFullImageName;
		sha_work_item->Result = NULL;
		ExInitializeWorkItem(&sha_work_item->WorkItem, HashRoutine, sha_work_item);
		ExQueueWorkItem(&sha_work_item->WorkItem, DelayedWorkQueue);


		LARGE_INTEGER wait_large_integer;
		wait_large_integer.LowPart = -100000000;
		while (sha_work_item->Done == FALSE)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
		//	DbgPrint("Waiting %d\n", 0);
		}

		if (sha_work_item->Result == NULL)
		{
			DbgPrint("Something went wrong, deny load!");
			goto Deny;
		}

		BOOLEAN match = FALSE;
		int length = sizeof(allowed) / sizeof(allowed[0]);
		for (int i = 0; i < length; i++)
		{
			if (strcmp(sha_work_item->Result, allowed) == 0)
			{
				//equal
				DbgPrint("EQUAL!");
				goto Allow;
			}
		}

		if (!match)
		{
			DbgPrint("NOT EQUAL!");
			DbgPrint("HAVE: %s", sha_work_item->Result);
		}

		ExFreePool(sha_work_item);
		goto Deny;
	} except (SYSTEM_SERVICE_EXCEPTION)
	{
	}

Deny:
	/*try
	{
		PRKAPC_STATE apcState = AllocMemory(TRUE, sizeof(KAPC_STATE));
		PEPROCESS pEProcess;
		PsLookupProcessByProcessId(InProcessId, &pEProcess);
		KeStackAttachProcess(pEProcess, apcState);

#ifdef X64_DRIVER
		KIRQL CurrentIRQL = KeGetCurrentIrql();
		RtlWPOff();
#endif
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Attached");
		uint8* entryPointAbs = ReadPE(InImageInfo->ImageBase);

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "DLL! %p\n", InImageInfo->ImageBase);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Entry! %p\n", entryPointAbs);
		uint8 patch[] = {0xC3};
		CopyMemory(entryPointAbs, patch, sizeof(patch));
#ifdef X64_DRIVER
		RtlWPOn(CurrentIRQL);
#endif

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Dettached");
		KeUnstackDetachProcess(apcState);
		FreeMemory(apcState);
	}
	except (SYSTEM_SERVICE_EXCEPTION)//will crash without this.
	{
		DbgPrint("error:%x");
	}
	*/
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Deny!\n");
Allow:
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Allow!\n");
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


char* calc_sha256(uint8* base, SIZE_T size)
{
	char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	uint8* buffer = AllocMemory(TRUE, size);
	CopyMemory(buffer, base, size);
	SHA256_Update(&sha256, buffer, size);
	SHA256_Final(hash, &sha256);
	char* finalHash = sha256_hash_string(hash);
	FreeMemory(buffer);
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
	FreeMemory(pe);
	FreeMemory(mz);

	return base + entryPoint;
}

