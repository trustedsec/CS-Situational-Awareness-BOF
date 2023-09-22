#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "queue.c"

void listDir(char *path, unsigned short subdirs) {

	WIN32_FIND_DATA fd = {0};
	HANDLE hand = NULL;
	LARGE_INTEGER fileSize;
	LONGLONG totalFileSize = 0;
	int nFiles = 0;
	int nDirs = 0;
	Pqueue dirQueue = queueInit();
	char * uncIndex;
	char * curitem;
	char * nextPath;
	int pathlen = MSVCRT$strlen(path);

	// Per MSDN: "On network shares ... you cannot use an lpFileName that points to the share itself; for example, "\\Server\Share" is not valid."
	// Workaround: If we're using a UNC Path, there'd better be at least 4 backslashes
	// This breaks the convention, but a `cmd /c dir \\hostname\admin$` will work, so let's replicate that functionality.
	if (MSVCRT$_strnicmp(path, "\\\\", 2) == 0) {
		uncIndex = MSVCRT$strstr(path + 2, "\\");
		if (uncIndex != NULL && MSVCRT$strstr(uncIndex + 1, "\\") == NULL) {
			MSVCRT$strcat(path, "\\");
			pathlen = pathlen + 1;
		}
	}

	// If the file ends in \ or is a drive (C:), throw a * on there
	if (MSVCRT$strcmp(path + pathlen - 1, "\\") == 0) {
		MSVCRT$strcat(path, "*");
	} else if (MSVCRT$strcmp(path + pathlen - 1, ":") == 0) {
		MSVCRT$strcat(path, "\\*");
	}

	// Query the first file
	(hand = KERNEL32$FindFirstFileA(path, &fd));
	if (hand == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "Couldn't open %s: Error %u", path, KERNEL32$GetLastError());
		KERNEL32$FindClose(hand);
		return;
	}
	// If it's a single directory without a wildcard, re-run it with a \*
	if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && MSVCRT$strstr(path, "*") == NULL) {
		MSVCRT$strcat(path, "\\*");
		listDir(path, subdirs);
		KERNEL32$FindClose(hand);
		return;
	}

	internal_printf("Contents of %s:\n", path);
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
				internal_printf("%16s %s\n", "<junction>", fd.cFileName);
			} else {
				internal_printf("%16s %s\n", "<dir>", fd.cFileName);
			}
			nDirs++;
			// ignore . and ..
			if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0) {
				continue;
			}
			// Queue subdirectory for recursion
			if (subdirs) {
				nextPath = intAlloc((MSVCRT$strlen(path) + MSVCRT$strlen(fd.cFileName) + 3)*2);
				MSVCRT$strncat(nextPath, path, MSVCRT$strlen(path)-1);
				MSVCRT$strcat(nextPath, fd.cFileName);
				dirQueue->push(dirQueue, nextPath);
			}
		} else {
			fileSize.LowPart = fd.nFileSizeLow;
			fileSize.HighPart = fd.nFileSizeHigh;
			internal_printf("%16lld %s\n", fileSize.QuadPart, fd.cFileName);

			nFiles++;
			totalFileSize += fileSize.QuadPart;
		}
	} while(KERNEL32$FindNextFileA(hand, &fd));
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
		listDir(curitem, subdirs);
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
	char * path = BeaconDataExtract(&parser, NULL);
	unsigned short subdirs = BeaconDataShort(&parser);

	// Not positive how long path is, let's be safe
	// At worst, we will append \* so give it four bytes (= 2 wchar_t)
	char * realPath = intAlloc(1024);
	MSVCRT$strncat(realPath, path, 1023);

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
