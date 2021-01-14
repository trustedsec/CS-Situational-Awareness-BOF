#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#define DIV 1048576

void getResources() {

	// Get dat memory
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);

	if (KERNEL32$GlobalMemoryStatusEx(&statex) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Error fetching memory");
		return;
	}

	internal_printf("Memory Used:\t%I64dMB/%I64dMB\n", (statex.ullTotalPhys - statex.ullAvailPhys) / DIV,
		statex.ullTotalPhys / DIV);


	// And now the primary disk
	ULARGE_INTEGER totalBytes;
	ULARGE_INTEGER freeBytes;

	int a = KERNEL32$GetDiskFreeSpaceExA(NULL, NULL, &totalBytes, &freeBytes);
	if (a == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Error fetching disk space");
		return;
	} else {
		internal_printf("Free Space:\t%lu MB\n", freeBytes.QuadPart / DIV);
		internal_printf("Total Space:\t%lu MB\n", totalBytes.QuadPart / DIV);
	}
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	getResources();
	printoutput(TRUE);
	bofstop();
};
