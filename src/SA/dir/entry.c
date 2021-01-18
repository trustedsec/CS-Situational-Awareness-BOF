#include <windows.h>
#include "bofdefs.h"
#include "base.c"

void listDir(wchar_t *path) {

	WIN32_FIND_DATAW fd = {0};
	HANDLE hand = NULL;
	LARGE_INTEGER fileSize;
	LONGLONG totalFileSize = 0;
	int nFiles = 0;
	int nDirs = 0;
	
	// If the file ends in \ or is a drive (C:), throw a * on there
	int a = MSVCRT$wcslen(path);
	if (MSVCRT$_wcsicmp(path + a - 1, L"\\") == 0) {
		MSVCRT$wcscat(path, L"*");
	} else if (MSVCRT$_wcsicmp(path + a - 1, L":") == 0) {
		MSVCRT$wcscat(path, L"\\*");
	}
	
	// Query the first file
	(hand = KERNEL32$FindFirstFileW(path, &fd));
	if (hand == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "File not found: %ls", path);
		return;
	}

	// If it's a single directory without a wildcard, re-run it with a \*
	if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && MSVCRT$wcsstr(path, L"\\*") == NULL) {
		MSVCRT$wcscat(path, L"\\*");
		listDir(path);
		return;
	}

	internal_printf("Contents of %ls:\n", path);
	do {
		// Get file write time
		SYSTEMTIME stUTC, stLocal;
		KERNEL32$FileTimeToSystemTime(&(fd.ftLastWriteTime), &stUTC);
		KERNEL32$SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

		internal_printf("\t%02d/%02d/%02d %02d:%02d", 
				stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute);

		// File size (or ujust print dir)
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				internal_printf("%16s %ls\n", "<junction", fd.cFileName);
			} else {
				internal_printf("%16s %ls\n", "<dir>", fd.cFileName);
			}
			nDirs++;
		} else {
			fileSize.LowPart = fd.nFileSizeLow;
			fileSize.HighPart = fd.nFileSizeHigh;
			internal_printf("%16lld %ls\n", fileSize.QuadPart, fd.cFileName);

			nFiles++;
			totalFileSize += fileSize.QuadPart;
		}
	} while(KERNEL32$FindNextFileW(hand, &fd));
	internal_printf("\t%32lld Total File Size for %d File(s)\n", totalFileSize, nFiles);
	internal_printf("\t%55d Dir(s)\n", nDirs);

	// A single error (ERROR_NO_MORE_FILES) is normal
	DWORD err = KERNEL32$GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		BeaconPrintf(CALLBACK_ERROR, "Error fetching files: %s\n", err);
		KERNEL32$FindClose(hand);
		return;
	}

	KERNEL32$FindClose(hand);
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	wchar_t * path = (wchar_t *)BeaconDataExtract(&parser, NULL);

	if(!bofstart())
	{
		return;
	}

	listDir(path);
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
