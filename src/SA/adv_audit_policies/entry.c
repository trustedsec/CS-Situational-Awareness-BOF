#include <windows.h>
#include "bofdefs.h"
#include "base.c"

DWORD RecursiveFindFile(LPWSTR swzDirectory, LPWSTR swzFileName, LPWSTR* lpswzResults, PDWORD lpdwResultsCount)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	WIN32_FIND_DATAW findFileData = {0};
	HANDLE hFindFile = NULL;

	intZeroMemory(&findFileData, sizeof(findFileData));
	
	// If the file ends in \ or is a drive (C:), throw a * on there
	nFileNameLength = MSVCRT$wcslen(lpFileName);
	if (MSVCRT$_wcsicmp(lpFileName + nFileNameLength - 1, L"\\") == 0) {
		MSVCRT$wcscat(lpFileName, L"*");
	} else if (MSVCRT$_wcsicmp(lpFileName + nFileNameLength - 1, L":") == 0) {
		MSVCRT$wcscat(lpFileName, L"\\*");
	}

	// Query the first file
	hFindFile = KERNEL32$FindFirstFileW(lpFileName, &findFileData);
	if (hFindFile == INVALID_HANDLE_VALUE)
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "FindFirstFileW(%ls) failed. (%lu)", lpFileName, dwErrorCode);
		goto END;
	}

	// If it's a single directory without a wildcard, re-run it with a \*
	if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && MSVCRT$wcsstr(lpFileName, L"\\*") == NULL) {
		MSVCRT$wcscat(lpFileName, L"\\*");
		listDir(lpFileName);
		return;
	}

	internal_printf("Contents of %ls:\n", lpFileName);
	do {
		// Get file write time
		SYSTEMTIME stUTC, stLocal;
		KERNEL32$FileTimeToSystemTime(&(findFileData.ftLastWriteTime), &stUTC);
		KERNEL32$SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

		internal_printf("\t%02d/%02d/%02d %02d:%02d",
				stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute);

		// File size (or ujust print dir)
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				internal_printf("%16s %ls\n", "<junction>", findFileData.cFileName);
			} else {
				internal_printf("%16s %ls\n", "<dir>", findFileData.cFileName);
			}
			nDirs++;
			// ignore . and ..
			if (MSVCRT$wcscmp(findFileData.cFileName, L".") == 0 || MSVCRT$wcscmp(findFileData.cFileName, L"..") == 0) {
				continue;
			}
			// Queue subdirectory for recursion
			if (subdirs) {
				nextPath = (WCHAR *)intAlloc((MSVCRT$wcslen(lpFileName) + MSVCRT$wcslen(findFileData.cFileName) + 3) * 2);
				MSVCRT$wcsncat(nextPath, lpFileName, MSVCRT$wcslen(lpFileName)-1);
				MSVCRT$wcscat(nextPath, findFileData.cFileName);
				dirQueue->push(dirQueue, nextPath);
			}
		} else {
			fileSize.LowPart = findFileData.nFileSizeLow;
			fileSize.HighPart = findFileData.nFileSizeHigh;
			internal_printf("%16lld %ls\n", fileSize.QuadPart, findFileData.cFileName);

			nFiles++;
			totalFileSize += fileSize.QuadPart;
		}
	} while(KERNEL32$FindNextFileW(hFindFile, &findFileData));
	internal_printf("\t%32lld Total File Size for %d File(s)\n", totalFileSize, nFiles);
	internal_printf("\t%55d Dir(s)\n", nDirs);

	// A single error (ERROR_NO_MORE_FILES) is normal
	DWORD err = KERNEL32$GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		BeaconPrintf(CALLBACK_ERROR, "Error fetching files: %s\n", err);
		KERNEL32$FindClose(hFindFile);
		return;
	}

	KERNEL32$FindClose(hFindFile);
	while((curitem = dirQueue->pop(dirQueue)) != NULL) {
		listDir((wchar_t *)curitem, subdirs);
		intFree(curitem);
	}
	dirQueue->free(dirQueue);

END:

}

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	wchar_t * lpFileName = (wchar_t *)BeaconDataExtract(&parser, NULL);
	unsigned short subdirs = BeaconDataShort(&parser);

    // Not positive how long lpFileName is, let's be safe
    // At worst, we will append \* so give it four bytes (= 2 wchar_t)
    wchar_t * realPath = intAlloc(1024);
    MSVCRT$wcsncat(realPath, lpFileName, 1020);

	if(!bofstart())
	{
		return;
	}

	listDir(realPath, subdirs);
    intFree(realPath);
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
