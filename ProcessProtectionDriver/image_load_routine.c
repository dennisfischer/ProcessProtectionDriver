#include "stdafx.h"

#include <stdint.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;

struct MzHeader {
	uint16 magic; /* == 0x5a4D */
	uint16 bytesInLastBlock;
	uint16 blocksInFile;
	uint16 numRelocations;
	uint16 headerParagraphs;
	uint16 minExtraParagraphs;
	uint16 maxExtraParagraphs;
	uint16 ss;
	uint16 sp;
	uint16 checksum;
	uint16 ip;
	uint16 cs;
	uint16 relocationTableOffset;
	uint16 overlayNumber;
	uint16 reserved[4];
	uint16 oemID;
	uint16 oemInfo;
	uint16 reserved2[10];
	uint32 lfaNew;	// PE Address
};

struct PeHeader {
	uint32 magic; // 0x4550
	uint16 machine;
	uint16 numberOfSections;
	uint32 timeDateStamp;
	uint32 pointerToSymbolTable;
	uint32 numberOfSymbols;
	uint16 sizeOfOptionalHeader;
	uint16 characteristics;
};

struct Pe32OptionalHeader {
	uint16 magic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	uint8  majorLinkerVersion;
	uint8  minorLinkerVersion;
	uint32 sizeOfCode;
	uint32 sizeOfInitializedData;
	uint32 sizeOfUninitializedData;
	uint32 addressOfEntryPoint;
	uint32 baseOfCode;
	uint32 baseOfData;
	uint32 imageBase;
	uint32 sectionAlignment;
	uint32 fileAlignment;
	uint16 majorOperatingSystemVersion;
	uint16 minorOperatingSystemVersion;
	uint16 majorImageVersion;
	uint16 minorImageVersion;
	uint16 majorSubsystemVersion;
	uint16 minorSubsystemVersion;
	uint32 win32VersionValue;
	uint32 sizeOfImage;
	uint32 sizeOfHeaders;
	uint32 checksum;
	uint16 subsystem;
	uint16 llCharacteristics;
	uint32 sizeOfStackReserve;
	uint32 sizeOfStackCommit;
	uint32 sizeOfHeapReserve;
	uint32 sizeOfHeapCommit;
	uint32 loaderFlags;
	uint32 numberOfRvaAndSizes;
};

unsigned char*  ReadPE(unsigned char* base) {
	uint32 entryPoint;
	struct MzHeader* mz = AllocMemory(TRUE, sizeof(struct MzHeader));
	CopyMemory(mz, base, sizeof(struct MzHeader));
	
	struct PeHeader* pe = AllocMemory(TRUE, sizeof(struct PeHeader));
	CopyMemory(pe, base + mz->lfaNew, sizeof(struct PeHeader));

	struct Pe32OptionalHeader* peOpt = AllocMemory(TRUE, sizeof(struct Pe32OptionalHeader));
	CopyMemory(peOpt, base + mz->lfaNew + sizeof(struct PeHeader), sizeof(struct Pe32OptionalHeader));
	entryPoint = peOpt->addressOfEntryPoint;
	
	FreeMemory(peOpt);
	FreeMemory(pe);
	FreeMemory(mz);

	return base + entryPoint;
}


VOID OnImageLoadNotifyRoutine(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO InImageInfo)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE ProcessHandle = NULL;

	if (InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"dll-injector-sample.dll")) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "Malicious DLL Sample - PID : %d ImageName :%wZ\n", HandleToLong(InProcessId), InFullImageName);
		unsigned char* entryPointAbs = ReadPE(InImageInfo->ImageBase);
		unsigned char patch[] = { 0xC3 };

		CopyMemory(entryPointAbs, patch, sizeof(patch));
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "Done!\n");
	}

ERROR_ABORT:

	if (ProcessHandle != NULL) {
		ZwClose(&ProcessHandle);
	}
}