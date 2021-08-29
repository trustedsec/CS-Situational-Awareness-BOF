#include <windows.h>
#include "bofdefs.h"
#include "base.c"


BOOL ListModules(DWORD PID, const char * modSearchString)
{
	MODULEENTRY32 modinfo = {0};
	modinfo.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	BOOL retVal = FALSE;
	hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
	BOOL more = KERNEL32$Module32First(hSnap, &modinfo);
	while(more)
	{
		if(SHLWAPI$StrStrIA(modinfo.szExePath, modSearchString))
		{
			//May be beneficial to print off all hits even within a single process
			internal_printf("%s\n", modinfo.szExePath);
			retVal = TRUE;
			//break;
		}
		more = KERNEL32$Module32Next(hSnap, &modinfo);
	}

	if(hSnap != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(hSnap); }
	return retVal;

}

void ListProcesses(const char * procSearchString, const char * modSearchString)
{
	//Get snapshop of all procs
	PROCESSENTRY32 procinfo = {0};
	procinfo.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	DWORD count = 0;
	hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnap == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to list processes: %lu", KERNEL32$GetLastError());
		goto end;
	}
	//And now we Enumerate procs and Call up to List Modules with them
	BOOL more = KERNEL32$Process32First(hSnap, &procinfo);
	//internal_printf("First call returned : %d\n", more);
	while(more)
	{
		if(!procSearchString || SHLWAPI$StrStrIA(procinfo.szExeFile, procSearchString))
		{
			if(ListModules(procinfo.th32ProcessID, modSearchString))
			{
				internal_printf("%-10lu : %s\n", procinfo.th32ProcessID, procinfo.szExeFile);
				count++;
			}
		}
		more = KERNEL32$Process32Next(hSnap, &procinfo);
	}
	//Check that we exited because we were done and not an error
	DWORD exitStatus = KERNEL32$GetLastError();
	if(exitStatus != ERROR_NO_MORE_FILES)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to enumerate all processes: %lu", exitStatus);
		goto end;
	}

	if(!count)
	{
		internal_printf("Successfully enumerated all processes, but didn't find the requested module");
	}
	end:
	if(hSnap != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(hSnap); }
	return;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	const char * modSearchString = BeaconDataExtract(&parser, NULL); //Must Be set
	const char * procSearchString = BeaconDataExtract(&parser, NULL);
	procSearchString = (procSearchString[0]) ? procSearchString : NULL;

	ListProcesses(procSearchString, modSearchString);
	printoutput(TRUE);
};

#else

int main()
{
ListProcesses("explorer", "ntdll");
ListProcesses(NULL, "Kernel32.dll");
ListProcesses(NULL, "asdfasdfadsf");
}

#endif
