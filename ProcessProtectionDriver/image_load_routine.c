#include "stdafx.h"

VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	if (InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"dll-injector-sample.dll")) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Malicious DLL Sample - PID : %d ImageName :%wZ\n", HandleToLong(InProcessId), InFullImageName);

		if (InImageInfo->ExtendedInfoPresent) {

			uint8* allowed[2] = { "5ecd6f1a3b5aeef3d541aa0645f344bd7ef1a2a2b672ece6bce20c28044bedd4", "396f0d16561e13774d04f22f3439f7ae99c41d90aea0a6a7e974e67142d7c619" };
			try
				{
					//IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);
					uint8 offset = 4000;
					uint8* sha256string = calc_sha256((uint8*)InImageInfo->ImageBase+offset, (uint8*)InImageInfo->ImageSize-offset);
					DbgPrint("SHA2 String: %s", sha256string);

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

					if(!match)
					{
						DbgPrint("NOT EQUAL!");
						DbgPrint("ALLOWED: %s", allowed[0]);
						DbgPrint("HAVE: %s", sha256string);
					}

				} except(SYSTEM_SERVICE_EXCEPTION) {
					DbgPrint("error:%x");
				}
		}

		uint8* entryPointAbs = NULL;
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


		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Done!\n");
	}
}
uint8* sha256_hash_string(char hash[SHA256_DIGEST_LENGTH])
{
	uint8 sha256string[SHA256_DIGEST_STRING_LENGTH];

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(&sha256string[i * 2], "%02x", (uint8)hash[i]);
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
	FreeMemory(buffer);
	SHA256_Final(hash, &sha256);
	return sha256_hash_string(hash);
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
