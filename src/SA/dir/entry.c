#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "queue.c"

void listDir(wchar_t *path, unsigned short subdirs) {

	WIN32_FIND_DATAW fd = {0};
	HANDLE hand = NULL;
	LARGE_INTEGER fileSize;
	LONGLONG totalFileSize = 0;
	int nFiles = 0;
	int nDirs = 0;
	Pqueue dirQueue = queueInit();
	char * curitem;
	WCHAR * nextPath;

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
		BeaconPrintf(CALLBACK_ERROR, "Couldn't open %ls: Error %lu", path, KERNEL32$GetLastError());
		return;
	}

	// If it's a single directory without a wildcard, re-run it with a \*
	if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && MSVCRT$wcsstr(path, L"\\*") == NULL) {
		MSVCRT$wcscat(path, L"\\*");
		listDir(path, subdirs);
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
				internal_printf("%16s %ls\n", "<junction>", fd.cFileName);
			} else {
				internal_printf("%16s %ls\n", "<dir>", fd.cFileName);
			}
			nDirs++;
			// ignore . and ..
			if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 || MSVCRT$wcscmp(fd.cFileName, L"..") == 0) {
				continue;
			}
			// Queue subdirectory for recursion
			if (subdirs) {
				nextPath = (WCHAR *)intAlloc((MSVCRT$wcslen(path) + MSVCRT$wcslen(fd.cFileName) + 3) * 2);
				MSVCRT$wcsncat(nextPath, path, MSVCRT$wcslen(path)-1);
				MSVCRT$wcscat(nextPath, fd.cFileName);
				dirQueue->push(dirQueue, nextPath);
			}
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
	while((curitem = dirQueue->pop(dirQueue)) != NULL) {
		listDir((wchar_t *)curitem, subdirs);
		intFree(curitem);
	}
	dirQueue->free(dirQueue);

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
	unsigned short subdirs = BeaconDataShort(&parser);

    // Not positive how long path is, let's be safe
    // At worst, we will append \* so give it four bytes (= 2 wchar_t)
    wchar_t * realPath = intAlloc(1024);
    MSVCRT$wcsncat(realPath, path, 1020);

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
