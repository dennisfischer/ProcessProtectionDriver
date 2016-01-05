#include "stdafx.h"

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

				DbgPrint("Image Info Size: %llu", InImageInfo->ImageSize);

				LARGE_INTEGER largeInt;
				if (!NT_SUCCESS(Status = FsRtlGetFileSize(ex->FileObject, &largeInt)))
				{
					DbgPrint("FsRtlGetFileSize failed: %d", Status);
				}

				
				DbgPrint("Current IRQL: %d", KeGetCurrentIrql());

				if ((ex->FileObject->Flags & FO_HANDLE_CREATED) == FO_HANDLE_CREATED)
				{
					DbgPrint("FO_HANDLE_CREATED");
				}

				KeLeaveGuardedRegion();
				HANDLE fileHandle;

				if (!NT_SUCCESS(Status = ObOpenObjectByPointer(ex->FileObject, OBJ_KERNEL_HANDLE, NULL, NULL, NULL, KernelMode, &fileHandle)))
				{
					DbgPrint("ObOpenObjectByPointer failed: %d", Status);
					
				} else
				{
					DbgPrint("Current IRQL: %d", KeGetCurrentIrql());

					IO_STATUS_BLOCK ioStat;
					uint8* fileData = AllocMemory(TRUE, largeInt.LowPart);
					LARGE_INTEGER byteOffset;
					byteOffset.LowPart = byteOffset.HighPart = 0;

					if(!NT_SUCCESS(Status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStat, fileData, largeInt.LowPart, &byteOffset, NULL)))
					{
						DbgPrint("ZwReadFile failed %d", Status);
					} else
					{
						DbgPrint("ZwReadFile done");

						uint8* sha256string = calc_sha256(fileData, largeInt.LowPart);
						DbgPrint("SHA2 String: %s", sha256string);
					}
					FreeMemory(fileData);
					
				}
				if (!NT_SUCCESS(Status = ZwClose(fileHandle)))
				{
					DbgPrint("ZwClose failed %d", Status);
				}
				KeEnterGuardedRegion();
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
			} except(SYSTEM_SERVICE_EXCEPTION) {
				DbgPrint("error:%x");
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
uint8* sha256_hash_string(char hash[SHA256_DIGEST_LENGTH])
{
	uint8 sha256string[SHA256_DIGEST_STRING_LENGTH];

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf_s(&sha256string[i * 2], 2, "%02x", (uint8)hash[i]);
	}

	return sha256string;
}


uint8* calc_sha256(char* base, SIZE_T size)
{
	char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	char* buffer = AllocMemory(TRUE, size);
	CopyMemory(buffer, base, size);
	SHA256_Update(&sha256, buffer, size);
	SHA256_Final(hash, &sha256);
	uint8* finalHash =  sha256_hash_string(hash);
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