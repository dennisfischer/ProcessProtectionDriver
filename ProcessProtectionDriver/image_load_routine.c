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
	DbgPrint("Attached");
	uint8* entryPointAbs = ReadPE(WorkItem->ImageBase);

	DbgPrint("DLL! %p\n", WorkItem->ImageBase);
	DbgPrint("Entry! %p\n", entryPointAbs);
	uint8 patch[] = {0xC3};
	CopyMemory(entryPointAbs, patch, sizeof(patch));
#ifdef X64_DRIVER
	RtlWPOn(CurrentIRQL);
#endif

	DbgPrint("Dettached");
	KeUnstackDetachProcess(apcState);
	FreeMemory(apcState);

Exit:
	WorkItem->Done = TRUE;
}

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
			DEBUG("FsRtlGetFileSize failed: %d\n" , Status);
			goto Fail;
		}

		DEBUG("File size is: %lu\n" , file_size.LowPart);

		const wchar_t* SYS_ROOT_PREFIX = L"\\SystemRoot\\";
		wchar_t* FILE_NAME = WorkItem->FullImageName->Buffer;
		if (wcsncmp(SYS_ROOT_PREFIX, WorkItem->FullImageName->Buffer, wcslen(SYS_ROOT_PREFIX)) == 0)
		{
			WorkItem->Allow = TRUE;
			goto Done;
			// System root file - speed up
			/*
			SIZE_T size = (wcslen(FILE_NAME) * sizeof(wchar_t)) + sizeof(L'\0');
			resultString = AllocMemory(TRUE, size);
			wcscpy(resultString, FILE_NAME);
			DEBUG("File Path: %S\n", resultString);
			goto BuildPath;*/
		}

		UNICODE_STRING deviceName;
		if (!NT_SUCCESS(Status = IoVolumeDeviceToDosName(WorkItem->FileObject->DeviceObject, &deviceName)) || deviceName.Buffer == NULL)
		{
			goto Fail;
		}
		const wchar_t* DOS_DEVICES_PREFIX = L"\\DosDevices\\";
		wchar_t* DEVICE_NAME = deviceName.Buffer;
		DEBUG("Dos Name: %S\n" , DOS_DEVICES_PREFIX);
		DEBUG("Device Path: %wZ\n" , deviceName);
		DEBUG("File Path: %wZ\n" , WorkItem->FullImageName);

		ULONG size = (USHORT)((wcslen(DOS_DEVICES_PREFIX) * sizeof(wchar_t)) + (wcslen(DEVICE_NAME) * sizeof(wchar_t)) + (wcslen(FILE_NAME) * sizeof(wchar_t)) + sizeof(L'\0'));
		resultString = AllocMemory(TRUE, size);

		wcscpy(resultString, DOS_DEVICES_PREFIX);
		wcscat(resultString, DEVICE_NAME);
		wcscat(resultString, FILE_NAME);
		goto BuildPath;

	BuildPath:
		UNICODE_STRING Path;
		USHORT formattedSize = (USHORT)(wcslen(resultString) * sizeof(wchar_t) + sizeof(L'\0'));
		Path.Buffer = resultString;
		Path.Length = (USHORT)(wcslen(resultString) * sizeof(wchar_t));
		Path.MaximumLength = (USHORT)formattedSize;

		DEBUG("Full Path now is: %wZ\n" , &Path);

		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK ioStat;

		InitializeObjectAttributes(&objectAttributes, &Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		if (!NT_SUCCESS(Status = ZwOpenFile(&fileHandle, FILE_READ_DATA, &objectAttributes, &ioStat, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_ALERT)))
		{
			DEBUG("ZwOpenFile failed: %d\n" , Status);
			goto Fail;
		}

		fileData = AllocMemory(TRUE, file_size.LowPart);
		LARGE_INTEGER byteOffset;
		byteOffset.LowPart = byteOffset.HighPart = 0;

		if (!NT_SUCCESS(Status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStat, fileData, file_size.LowPart, &byteOffset, NULL)))
		{
			DEBUG("ZwReadFile failed %d\n" , Status);
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
	LockMutex(GlobalMutex);
	//Should the dll get loaded into a chrome process?
	if (FindPidInTree(HandleToULong(InProcessId)) == 0)
	{
		//No - then do nothing
		UnlockMutex(GlobalMutex);
		goto Allow;
	}
	UnlockMutex(GlobalMutex);

	//Is this a dll file?
	if (InFullImageName->Length < 3 || wcscmp(&InFullImageName->Buffer[wcslen(InFullImageName->Buffer) - wcslen(L"dll")], L"dll") != 0)
	{
		//No - then do nothing
		goto Allow;
	}

	DEBUG("Malicious DLL Sample - PID: %d ImageName: %wZ\n" , HandleToLong(InProcessId) , InFullImageName);

	if (!InImageInfo->ExtendedInfoPresent)
	{
		goto Deny;
	}
	IMAGE_INFO_EX* ex = CONTAINING_RECORD(InImageInfo, IMAGE_INFO_EX, ImageInfo);


	char* allowed[] = {"5d88697613ba650495e9ea4f9142bbd09d46dd51512109e0f4ea07f054f6359f",
		"694cf94e8e102216d227ae39edc5f0724c9b1d0b4ad586d41040b0ba453223c4",
		"824202b392e9467f024067006b08258ba2f87b9367af3a95b756a99cbd5bc198",
		"8494f7b1b241a9c4121b78a01d756ca5e93417261e5e6e109728093b980c7b99",
		"0f5a0f576d4589e2a40d84d555b3cec8b05e491d6bb686f79451a368578bdd35",
		"085210d7806731d21ab5a81675f71cb93cf08425adc8fe774915cad9221c80ac",
		"645ca9e88da21c63710a04a0f54421018df415a3d612112c71a255c49325c082",
		"c36a45bc2448df30cd17bd2f8a17fc196fafb685612cacceb22dc7b58515c201",
		"16113812257d31c1eb2932649331f6699868d3ea634dffde303c19425ef432da",
		"add81ea1d208907d67802f0e96ec0327ba89021f870ba22b9c7e3a19013a6ae7",
		"e2e231f1c2e2ce19583483acc53318651fa7ca2de46bcb89b4cbf97ca0525122",
		"3a78579fd2e8ed905374df3cfa380db3a253494c6247638fc1d52ad12c8007c9",
		"849a82e9bea587e8221935f5132443f298412cf4d983c23c396510c7776ced41",
		"ed9d26f539065d62fccedeec8e509b30f4d15f8da586c1f657acefe9dabaacd0",
		"492eac5c51472b43de11825358aec4b9e3a081dacfd7513c696d6fe40f302ee5",
		"66f4da105bd72e41250cd59e2b3cd931b47ac9fdb6c784b9e33c5ee1ac29841f",
		"dcb76016f9ac47e631540874da208a089f9d529da9628705a2869b954526bfe0",
		"cdd734279c8f9f24ea2538bad8e91eb8c3dd74c33032db6b2d85c19576b42707",
		"b8f96336bf87f1153c245d19606cbd10fbe7cf2795bcc762f2a1b57cb7c39116",
		"a4ad1d2fd3ec2f26949dbbc388f9fff3713ad7eb4e9220af817ebb5223e467c6",
		"d8cfbe70d97f5bd880a46e797fdc3d33141d3c7413aedd3c64287e335e4330ca",
		"005be9ec30390e88c429622eeee4e2d2840cc3c75992c4a7f0e8a69756b0a2fd",
		"ff5e2f04f1fd56fdd19368150b5750275f0a44e9ea9820c8087e84ecbbf45286",
		"b02c99850940588d52b3e6db30db64582f294e0bd62101067becfea1483010c6",
		"b7faed8543095429567f16e3c1c46ddb11758ed711dc8267461b09219481236e",
		"2a47ff52d1d6480aad1919382e783ea184bf926311f8c7e466febe9f6fb88fd6",
		"1b594e6d057c632abb3a8cf838157369024bd6b9f515ca8e774b22fe71a11627",
		"b47a8d9985d9b71eb870816a0ab2b6403d394ccbdf7de5378d5721d58d68d28d",
		"10e3b89a5470e1bb6f73382135dd2352f5073c1ee8485d7476cfb5122d4aaa2f",
		"802a67247a04faff37ecc4df3dbd3f3783e180829e05e0aea7afa9afc6c9624a",
		"ac01fe84504b863dfa19d38be854f518521072ab697df51c888545cfbc839f4f",
		"1837275202628d3320867a3bf8cfda15491730c4b74215f7c0d7e140bf01ac3c",
		"3409ea885c9c332a997c81b3ca60352aeea30950304cdd128f29043d2cf7d194",
		"f38e9fe868d769ca59e899f0adae4112396cd06ab44f13306cd175670859a4c3",
		"755fa67f7bf10e3c6336788d297fbaa70f28f630852a43a78d3f7d7e3a7eced0",
		"9dfd9c58b90257c34d52b7156c1d2566be32ee7bd4699dde164a5f190ec4d44a",
		"e22408b4d2ede2f89e686a4fdcd4057be27b86d050e9cb489f0ffb39c72aec1d",
		"2a610beb16610fe2f2e9a50477a62a05481e8a5843a814955a0edff45d0304b3",
		"c69781683ca963a1335780dabbbc60e2c3cef0888738d3425d358d12e8d0af58",
		"cbcd032d679ade3a9942a1d116648d6a9ecc71f66f8630629e724e5ee23f9f73",
		"e5f3378ac40aee6114eeaf3bf11dc1059466891cae353e80c08622a60485c954",
		"c79db405d588c77e4acae3bc26080213beeb604c0a109afdf88031fc46b4cbc0",
		"2f3bb32ee2c0673058a74deeb2d405e5e79f833f33c4d289a93eb3c618a86e75",
		"80939a7b5354032256706c6ca0c3ccc7e67cd1c1c81eaea2cbc74997c0863662",
		"201313175bea013de47b00f9f563614641959fcad937fb873b587b7f8c87166c",
		"d00c7e0d665e467b712c68a446cc5be14fda743a2301878b3ceb72cdd0a8b8e7",
		"5d88697613ba650495e9ea4f9142bbd09d46dd51512109e0f4ea07f054f6359f",
		"68d66c36d1f293d10adcc6a33c870f989a29743537592cf172f02e794beafd1c",
		"0d3c73b45bc708d7b1e26dfb6d4f64031a998548fea0fb5ce198ed716f7dc9a0",
		"57f3353f89724147d8ac8b69b12c1303df26978309776f5f8ccf074526a915d3",
		"ff0db8bf0c68da0d09272e8181d2b5409c8850bb2f31aea3ac4cd14c5a420a59",
		"f82592908d038c44d9f2e5c5b7bc663a2d370fc565f40420e1138a9e55f0e7eb",
		"4bb7c956ea8d2ce63f5bf80fae652f98416a7635202aee04fc8d81000e6363df",
		"b383bd69a8f1301128a43373fbd5f6f3cb8c70bf3807c0b8db4cfcdc4ac3c3f8",
		"76f17d4df440d6734dc8157092d94eb18c2a73a0a49beea289e7b3ede30e86a2",
		"4bb2f43322093f02b2fbcc4b2456437356555da48dc6da67fc55a1b457d32149",
		"73f591c8f75822ffff27030f9ae629778e79d74eee3eac8ef20ca674cead08f7",
		"b861360d0a014265a0beb4cc2fe31ea05ae95120e8b07820c13a044d64c00e2b",
		"417205797cc9f6c986a863a61179784d9adcaf1961ef8a4d9042d73c5a86509a",
		"d0e46802d90afce8390cd377fcce98e8ee06c146a21e5cc2c397b6e5e7605ee4",
		"efbdbbcd0d954f8fdc53467de5d89ad525e4e4a9cfff8a15d07c6fdb350c407f",
		"d27490ecb39c6c17adc99a16de091f6c0e144865af487a68c3e988f057195a6c",
		"75633011cd28dcbd4834211a9d415f17de15bfcd80fb9ff6ce25cbbd4e9899af",
		"0e25ca984c0eeb629184423faa9bc6d4356df9a93f281e06dc83b4ac638aec4a",
		"6f8b87fb4d67f9e76a51ef759b58a95d903c4aac9c789a65a3fa1fc4f253d978",
		"e1edce6216b24037b243ac68ceebd510646b2efd70bc118e68303f9ed85d1973",
		"a650c3a244306f8e605bda8e74bfe438356ba4403b0cb61e980d3183e3f0a7c7",
		"17783e487bb67f613e825b8daee576e9f78e5df37b80b61be46f9ada4285d3bd",
		"72eaf30265a0cc88dec0fca7869734d8c93572457c61a2bf1bdffb20c061dbcd",
		"7e8980a3751762180d795eac38458303beaf8d1f85ab5f2d10d9ce7013090cbe",
		"38130b5f42fcb2c46ecf0c06f3d05a6f8e9d5e7d47cd9ec0e852de1c10ffe67e",
		"d9310c5bbfe089b8c81e259c462ec1e6d7a7a87fa59fc1f174ed5c58d409ae7a",
		"647587c396c941f2d0d23ce4189f1d053b2def47e6d9f32c2bd2bdecb03873c9",
		"54ba429753c27b15f313feba952ac5b2deaac548e31c4bb4f62796cc38b4f6dc",
		"0b28499594a53fda839c17356f258b0141e82e36e34fb6437d6dfcc55fd7d76b",
		"d926530c659ddaf80770663f46f1efd94ffb4aab475c4e3367cb531af4a734e1", //\Windows\SysWOW64\powrprof.dll
		"5a5d205e16e6afdcc965e4144fe6e104157de7541d31727520363f2670513940", //\Windows\SysWOW64\avrt.dll
		"59e2df91f8da9e33de65fa67a6a49a7c3f524618a87eaefc8a28c5304e7fab85", //\Windows\SysWOW64\linkinfo.dll
		"77373919dca647f09851e7e460ae78fbd89f21516b961f84ac4446304e51e09c", //\Windows\SysWOW64\ntshrui.dll
		"7f1b3ca09ab045f805da5765be7dd270f5ddace3073017f7386ff1e2fa82d6fb", //\Windows\SysWOW64\cscapi.dll
		"8721edb4c51bf6020002fa5ddb1987c68590f9f433a2f18d9756b2dac7542cb6", //\Windows\SysWOW64\slc.dll
		"9b4d262b10cb09543aca9a78482f4edd905791d2c8c518b574eba440a71a85b7", //\Windows\SysWOW64\mscms.dll
		"3f9d4ee64e4210340c6fee0de81bfe3c613ddbe608ec09d63817d24ce24bfc5e", //\Windows\SysWOW64\SensApi.dll
		"8ba490c65cb6978b4aaa8565a6e1f5277d90ecd3f08669712a26a3edda668e3d", //\Windows\SysWOW64\Speech\Common\sapi.dll
		"d68d9f525d31c1843b6ec8fa950166fa1f34db71222716e7b22dd33981c152b6", //\Windows\SysWOW64\msacm32.dll
		"04b7fb6c64bfa3b80549f35cef36d5dae5d19a40e42444b3665b6befdf98eb5f", //\Windows\SysWOW64\msdmo.dll
	};
	try
	{
		DEBUG("Image Info Size: %llu\n" , InImageInfo->ImageSize);

		PSHA_WORK_ITEM sha_work_item = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHA_WORK_ITEM), 'PROT');
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

		int length = sizeof(allowed) / sizeof(allowed[0]);
		for (int i = 0; i < length; i++)
		{
			if (strcmp(sha_work_item->Result, allowed[i]) == 0)
			{
				DEBUG("EQUAL!");
				goto Allow;
			}
		}

		DEBUG("NOT EQUAL!");
		DbgPrint("\"%s\", //%wZ", sha_work_item->Result, InFullImageName);

		ExFreePool(sha_work_item);
		goto Deny;
	} except (SYSTEM_SERVICE_EXCEPTION)
	{
	}

Deny:

	PPATCH_WORK_ITEM patch_work_item = ExAllocatePoolWithTag(NonPagedPool, sizeof(PATCH_WORK_ITEM), 'PROT');
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
	ExFreePool(patch_work_item);


	DEBUG("Deny!\n");
Allow:
	DEBUG("Allow!\n");
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

