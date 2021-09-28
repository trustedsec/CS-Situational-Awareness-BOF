#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#define FSCTL_SRV_ENUMERATE_SNAPSHOTS  0x00144064

void EnumSnapshots(wchar_t * hostname, wchar_t * sharename)
{
	HANDLE hFile = NULL;
	wchar_t path[MAX_PATH] = {0};
	wchar_t * targetPath = NULL;
	IO_STATUS_BLOCK io = {0};
	char * snapshots = NULL;
	ULONG snapshotsLen = 0;
	wchar_t * entry = NULL;
	DWORD Volumes, VolumesReturned, VolumeBytes;
	Volumes = VolumeBytes = VolumesReturned = 0;
	NTSTATUS ret = 0;


	MSVCRT$_snwprintf(path, MAX_PATH, L"\\\\%ls\\%ls", hostname, sharename);
	targetPath = path;
	internal_printf("Target = %ls\n", targetPath);

	hFile = KERNEL32$CreateFileW(targetPath, 
	GENERIC_READ,
	FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	NULL,
	OPEN_EXISTING,
	FILE_FLAG_BACKUP_SEMANTICS,
	NULL);

	if(hFile == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR, "Could not open root folder to query, Error: %lu", KERNEL32$GetLastError());
		return;
	}
	snapshotsLen = 16;
	snapshots = intAlloc(snapshotsLen);
	if (NULL == snapshots)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to allocate memory for snapshots");
		goto end;
	}	
	//Get sizes required
	ret = NTDLL$NtFsControlFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&io,
		FSCTL_SRV_ENUMERATE_SNAPSHOTS,
		NULL,
		0,
		snapshots,
		snapshotsLen);
	
	if(ret != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to get snapshots: %X", ret);
		goto end;
	}
	memcpy(&Volumes, snapshots, 4);
	memcpy(&VolumesReturned, snapshots +4, 4);
	memcpy(&VolumeBytes, snapshots + 8, 4);
	intFree(snapshots); snapshots = NULL;
	snapshotsLen = 12 + VolumeBytes;
	snapshots = intAlloc(snapshotsLen);
	if (NULL == snapshots)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to allocate memory for snapshots");
		goto end;
	}
	ret = NTDLL$NtFsControlFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&io,
		FSCTL_SRV_ENUMERATE_SNAPSHOTS,
		NULL,
		0,
		snapshots,
		snapshotsLen);
	
	if(ret != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to get snapshots: %X", ret);
		goto end;
	}
	memcpy(&VolumesReturned, snapshots +4, 4);
	entry = (wchar_t *)((char *)snapshots + 12);
	for(int i = 0; i < VolumesReturned; i++)
	{
		internal_printf("%ls\n", entry);
		entry += MSVCRT$wcslen(entry) + 1;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "Found and enumerated %lu snapshots", VolumesReturned);

end:
	if(snapshots)
	{
		intFree(snapshots);
	}
	if(hFile)
	{
		KERNEL32$CloseHandle(hFile);
	}

}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	wchar_t * hostname = (wchar_t *)BeaconDataExtract(&parser, NULL);
	wchar_t * sharename = (wchar_t *)BeaconDataExtract(&parser, NULL);
	if(!bofstart())
	{
		return;
	}
	EnumSnapshots(hostname, sharename);
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
