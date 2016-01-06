#include "stdafx.h"

typedef struct _SHA_WORK_ITEM {

	WORK_QUEUE_ITEM WorkItem;
	PFILE_OBJECT FileObject;
	PUNICODE_STRING FullImageName;
	char* Result;
} SHA_WORK_ITEM, *PSHA_WORK_ITEM;

void HashRoutine(PVOID Parameter)
{
	PSHA_WORK_ITEM WorkItem = (PSHA_WORK_ITEM)Parameter;

	NTSTATUS Status;
	HANDLE fileHandle;
	LARGE_INTEGER file_size;
	uint8* fileData = NULL;
	PWCH resultString = NULL;

	if (!NT_SUCCESS(Status = FsRtlGetFileSize(WorkItem->FileObject, &file_size)))
	{
		DbgPrint("FsRtlGetFileSize failed: %d\n", Status);
		goto Fail;
	}

	DbgPrint("File size is: %lu\n", file_size.LowPart);


	UNICODE_STRING deviceName;
	IoVolumeDeviceToDosName(WorkItem->FileObject->DeviceObject, &deviceName);

	PWCH DOS_DEVICES_PREFIX = L"\\DosDevices\\";
	PWCH DEVICE_NAME = deviceName.Buffer;
	PWCH FILE_NAME = WorkItem->FullImageName->Buffer;
	DbgPrint("Dos Name: %wZ\n", DOS_DEVICES_PREFIX);
	DbgPrint("Device Path: %wZ\n", deviceName);
	DbgPrint("File Path: %wZ\n", WorkItem->FullImageName);

	SIZE_T size = (wcslen(DOS_DEVICES_PREFIX) * sizeof(wchar_t)) + (wcslen(DEVICE_NAME) * sizeof(wchar_t)) + (wcslen(FILE_NAME) * sizeof(wchar_t)) + sizeof(L'\0');
	resultString = AllocMemory(TRUE, size);

	wcscpy(resultString, DOS_DEVICES_PREFIX);
	wcscat(resultString, DEVICE_NAME);
	wcscat(resultString, FILE_NAME);

	UNICODE_STRING Path;
	SIZE_T formattedSize = wcslen(resultString) * sizeof(wchar_t) + sizeof(L'\0');
	Path.Buffer = resultString;
	Path.Length = formattedSize - sizeof(L'\0');
	Path.MaximumLength = formattedSize;

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
	
	char* sha256string = calc_sha256(fileData, file_size.LowPart);
	DbgPrint("SHA2 String: %s\n", sha256string);
	WorkItem->Result = sha256string;

	if (!NT_SUCCESS(Status = ZwClose(fileHandle)))
	{
		DbgPrint("ZwClose failed %d\n", Status);
		goto Fail;
	}

Fail:
	WorkItem->Result = "FAILED!";
	if(fileData)
	{
		FreeMemory(fileData);
	}
	if(resultString)
	{
		FreeMemory(resultString);
	}
}


VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	if (InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"dll-injector-sample.dll")) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Malicious DLL Sample - PID: %d ImageName: %wZ\n", HandleToLong(InProcessId), InFullImageName);

		if (InImageInfo->ExtendedInfoPresent) {

			uint8* allowed[1] = { "2fb2b49c959b389318650df2380dd29f74fe327f58921eeff845fd8445215805" };
			try
			{

				NTSTATUS Status;
				IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);

				DbgPrint("Image Info Size: %llu\n", InImageInfo->ImageSize);

				PSHA_WORK_ITEM sha_work_item;
				sha_work_item = ExAllocatePool(NonPagedPool, sizeof(SHA_WORK_ITEM));
				sha_work_item->FileObject = ex->FileObject;
				sha_work_item->FullImageName = InFullImageName;
				sha_work_item->Result = NULL;
				ExInitializeWorkItem(&sha_work_item->WorkItem, HashRoutine, sha_work_item);
				ExQueueWorkItem(&sha_work_item->WorkItem, DelayedWorkQueue);


				LARGE_INTEGER wait_large_integer;
				wait_large_integer.LowPart = -10000;
				while(sha_work_item->Result == NULL)
				{
					KeDelayExecutionThread(KernelMode, FALSE, &wait_large_integer);
					DbgPrint("Waiting %d\n", 0);
				}
				DbgPrint("Result: %d\n", sha_work_item->Result);
				ExFreePool(sha_work_item);
				/*
				
			
	/*			uint8* sha256string = calc_sha256((uint8*)InImageInfo->ImageBase, (uint8*)InImageInfo->ImageSize);
				DbgPrint("SHA2 String: %s", sha256string);
				DbgPrint("File Name: %wZ", InFullImageName);


				BOOLEAN match = FALSE;
				int length = sizeof(allowed) / sizeof(allowed[0]);
				for (int i = 0; i < length; i++) {
					if (strcmp(sha256string, allowed) == 0)
					{
						//equal
						DbgPrint("EQUAL!");
						match = TRUE;
					}
				}

				if (!match)
				{
					DbgPrint("NOT EQUAL!");
					DbgPrint("ALLOWED: %s", allowed[0]);
					DbgPrint("HAVE: %s", sha256string);
				}

				*/
			} except (SYSTEM_SERVICE_EXCEPTION) {
			}

		}

/*		uint8* entryPointAbs = NULL;
		try
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
			entryPointAbs = ReadPE(InImageInfo->ImageBase);
			uint8 patch[] = { 0xC3 };
			CopyMemory(entryPointAbs, patch, sizeof(patch));
#ifdef X64_DRIVER
			RtlWPOn(CurrentIRQL);
#endif

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Dettached");
			KeUnstackDetachProcess(apcState);

			FreeMemory(apcState);
		}
		except(SYSTEM_SERVICE_EXCEPTION)//will crash without this.
		{
			DbgPrint("error:%x");
		}

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "DLL! %p, %x\n", InImageInfo->ImageBase, InImageInfo->ImageBase);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Entry! %p, %x\n", entryPointAbs, entryPointAbs);

		*/
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Done!\n");
	}
}
char* sha256_hash_string(char hash[SHA256_DIGEST_LENGTH])
{
	char* sha256string = AllocMemory(TRUE, sizeof(char) * SHA256_DIGEST_STRING_LENGTH);

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(&sha256string[i * 2], "%02x", (uint8)hash[i]);
	}

	DbgPrint("sha first try: %s", sha256string);

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


uint8* ReadPE(uint8* base) {
	uint32 entryPoint;
	struct MzHeader* mz = AllocMemory(TRUE, sizeof(struct MzHeader));
	CopyMemory(mz, base, sizeof(struct MzHeader));

	struct PeHeader* pe = AllocMemory(TRUE, sizeof(struct PeHeader));
	CopyMemory(pe, base + mz->lfaNew, sizeof(struct PeHeader));

	struct Pe32OptionalHeader* peOpt = AllocMemory(TRUE, sizeof(struct Pe32OptionalHeader));
	CopyMemory(peOpt, base + mz->lfaNew + sizeof(struct PeHeader), sizeof(struct Pe32OptionalHeader));
	entryPoint = peOpt->addressOfEntryPoint;

	//	peOpt->addressOfEntryPoint = 0;
	//	CopyMemory(base + mz->lfaNew + sizeof(struct PeHeader), peOpt, sizeof(struct Pe32OptionalHeader));

	FreeMemory(peOpt);
	FreeMemory(pe);
	FreeMemory(mz);

	return base + entryPoint;
}