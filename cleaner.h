#pragma once
#include "imports.h"

PVOID ntoskrnlBase = NULL;
ULONG ntoskrnlSize = 0;

NTSTATUS ScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL) return STATUS_INVALID_PARAMETER;

	PVOID base = (PVOID)ntoskrnlBase;
	if (!base) return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = PatternScan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
			return status;
		}
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
	UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

	PVOID PiDDBLockPtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (&PiDDBLockPtr)))) return FALSE;
	RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

	PVOID PiDTablePtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (&PiDTablePtr)))) return FALSE;
	RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);

	UINT64 RealPtrPIDLock = NULL;
	RealPtrPIDLock = (UINT64)ntoskrnlBase + (UINT64)PiDDBLockPtr;
	*lock = (PERESOURCE)ResolveRelativeAddress((PVOID)RealPtrPIDLock, 3, 7);

	UINT64 RealPtrPIDTable = NULL;
	RealPtrPIDTable = (UINT64)ntoskrnlBase + (UINT64)PiDTablePtr;
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress((PVOID)RealPtrPIDTable, 3, 7));

	return TRUE;
}

BOOLEAN clean_PiDDBCacheTable()
{
	PERESOURCE PiDDBLock = NULL; 
	PRTL_AVL_TABLE PiDDBCacheTable = NULL;


	if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) return FALSE;

	PIDCacheobj iqvw64e;

	UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	iqvw64e.DriverName = DriverName;
	iqvw64e.TimeDateStamp = 0x5284F8FA; // intel_driver TimeStamp.

	// aquire the ddb lock
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &iqvw64e);
	if (pFoundEntry == NULL)
	{
		// release the ddb resource lock
		ExReleaseResourceLite(PiDDBLock);
		return FALSE;
	}
	else
	{
		// unlink from the list
		RemoveEntryList(&pFoundEntry->List);
		// delete the element from the avl table
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
		// release the ddb resource lock
		ExReleaseResourceLite(PiDDBLock);
	}
	DbgPrintEx(0, 0, "Cleaned piddb\n");
	return TRUE;
}
