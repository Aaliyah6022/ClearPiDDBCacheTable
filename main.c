#include <ntifs.h>
#include "cleaner.h"

void real_entry()
{
	DbgPrintEx(0, 0, "Real Entry Called.\n");


	DbgPrintEx(0, 0, "Cleaning....!");
	clean_PiDDBCacheTable();
	DbgPrintEx(0, 0, "Cleaning...DONE");

	// hook

	DbgPrintEx(0, 0, "Hooks applied!");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(0, 0, "Driver Created.\n");

	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObj);

	real_entry();

	return STATUS_SUCCESS;
}