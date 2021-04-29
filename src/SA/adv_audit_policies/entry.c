#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#define SWZ_ROOT_DIRECTORY L"%SYSTEMROOT%\\system32\\GroupPolicy"
#define SWZ_SEARCH_FILENAME L"audit.csv"

DWORD RecursiveFindFile(LPWSTR swzDirectory, LPWSTR swzFileName, LPWSTR** lpswzResults, PDWORD lpdwResultsCount)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	WIN32_FIND_DATAW findFileData = {0};
	HANDLE hFindFile = NULL;
	LPWSTR swzNewFullpathName = NULL;
	WCHAR swzQuery[MAX_PATH];

	intZeroMemory(&findFileData, sizeof(findFileData));
	intZeroMemory(swzQuery, sizeof(MAX_PATH));

	// create the find query
	MSVCRT$_snwprintf(swzQuery, MAX_PATH, L"%s\\*", swzDirectory);

	// find the first entry in the current directory
	hFindFile = KERNEL32$FindFirstFileW(swzQuery, &findFileData);
	if (INVALID_HANDLE_VALUE == hFindFile)
	{
		dwErrorCode = KERNEL32$GetLastError();
		internal_printf("FindFirstFileW failed. (%lu)\n", dwErrorCode);
		goto END;
	}

	// allocate a buffer for the fullpath entry name
	swzNewFullpathName = (LPWSTR)intAlloc(MAX_PATH*sizeof(WCHAR));
	if ( NULL == swzNewFullpathName )
	{
		dwErrorCode = ERROR_OUTOFMEMORY;
		internal_printf("intAlloc failed. (%lu)\n", dwErrorCode);
		goto END;
	}

	// loop through all the entries in the current directory
	do
	{
		intZeroMemory(swzNewFullpathName, MAX_PATH*sizeof(WCHAR));

		// ignore . and ..
		if ( (0 == MSVCRT$wcscmp(findFileData.cFileName, L"."))  || 
			 (0 == MSVCRT$wcscmp(findFileData.cFileName, L".."))    )
		{
			continue;
		}

		// create the fullpath of the new entry and append 			
		MSVCRT$_snwprintf(swzNewFullpathName, MAX_PATH, L"%s\\%s", swzDirectory, findFileData.cFileName);

		// check if current entry is a directory
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// find all matching files in the subdirectory
			dwErrorCode = RecursiveFindFile(swzNewFullpathName, swzFileName, lpswzResults, lpdwResultsCount);
			if ( ERROR_SUCCESS != dwErrorCode)
			{
				internal_printf("RecursiveFindFile(%ls) failed. (%lu)\n", swzNewFullpathName, dwErrorCode);
				goto END;
			}
		} // end if current entry is a directory
		else // else current entry is a file
		{
			// check if the file matches the filename we are looking for
			if (0 == MSVCRT$wcscmp(findFileData.cFileName, swzFileName))
			{
				// increment the find count
				*lpdwResultsCount = *lpdwResultsCount + 1;

				// re-allocate the results buffer to hold the new entry
				(*lpswzResults) = intRealloc((*lpswzResults), (*lpdwResultsCount)*sizeof(LPWSTR));
				if (NULL == (*lpswzResults))
				{
					dwErrorCode = ERROR_OUTOFMEMORY;
					internal_printf("intRealloc failed. (%lu)\n", dwErrorCode);
					goto END;
				}

				// update the results buffer with the new entry
				(*lpswzResults)[(*lpdwResultsCount)-1] = swzNewFullpathName;

				// allocate a new buffer for the fullpath entry name
				swzNewFullpathName = (LPWSTR)intAlloc(MAX_PATH*sizeof(WCHAR));
				if ( NULL == swzNewFullpathName )
				{
					dwErrorCode = ERROR_OUTOFMEMORY;
					internal_printf("intAlloc failed. (%lu)\n", dwErrorCode);
					goto END;
				}
			} // end if the file matches the filename we are looking for
		} // end else current entry is a file
	} while( KERNEL32$FindNextFileW(hFindFile, &findFileData) );


	// check why the loop broke: ERROR_NO_MORE_FILES is normal
	dwErrorCode = KERNEL32$GetLastError();
	if (ERROR_NO_MORE_FILES != dwErrorCode)
	{
		internal_printf("FindNextFileW failed. (%lu)\n", dwErrorCode);
		goto END;
	}

	dwErrorCode = ERROR_SUCCESS;

END:

	if ( NULL != swzNewFullpathName )
	{
		intFree(swzNewFullpathName);
		swzNewFullpathName = NULL;
	}

	if ( ( NULL != hFindFile ) && ( INVALID_HANDLE_VALUE != hFindFile ) )
	{
		KERNEL32$FindClose(hFindFile);
		hFindFile = NULL;
	}

	return dwErrorCode;
}

DWORD Deduplicate_CSV(LPWSTR* lpswzFileSet, DWORD dwFileSetCount, LPSTR* lpszCSV, PDWORD lpdwCSVSize)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	HANDLE hFile = NULL;
	DWORD dwFileContentSize = 0;
	PBYTE lpFileContent = NULL;
	PBYTE lpFileContentEnd = NULL;
	DWORD dwBytesRead = 0;
	LPSTR szCurrentLine = NULL;
	LPSTR szCurrentLineEnd = NULL;
	DWORD dwCurrentLineSize = 0;

	LPSTR szNewCSV = NULL;
	DWORD dwNewCSVSize = 0;
	LPSTR szCurrentCSV = NULL;
	DWORD dwCurrentCSVSize = 0;
	
	szCurrentCSV = intAlloc(1);
	if (NULL == szCurrentCSV)
	{
		dwErrorCode = ERROR_OUTOFMEMORY;
		internal_printf("intAlloc failed. (%lu)\n", dwErrorCode);
		goto END;
	}

	internal_printf("Deduplicating %lu audit files\n", dwFileSetCount);

	// check if there are files
	if (NULL != lpswzFileSet)
	{
		// loop through all the files in the set
		for(DWORD dwFileSetIndex=0; dwFileSetIndex<dwFileSetCount; dwFileSetIndex++)
		{
			// check if the filename is not null
			if (NULL != lpswzFileSet[dwFileSetIndex])
			{
				// close any existing file handles
				if ( ( NULL != hFile ) && ( INVALID_HANDLE_VALUE != hFile ) )
				{
					KERNEL32$CloseHandle( hFile );
					hFile = NULL;
				}

				// open the current file
				hFile = KERNEL32$CreateFileW( lpswzFileSet[dwFileSetIndex], GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
				if ( INVALID_HANDLE_VALUE == hFile )
				{
					dwErrorCode = KERNEL32$GetLastError();
					internal_printf("CreateFileW failed. (%lu)\n", dwErrorCode);
					continue;
				}

				// get the size of the current file
				dwFileContentSize = KERNEL32$GetFileSize(hFile, NULL);
				if ( 0 == dwFileContentSize )
				{
					//internal_printf("File is zero-bytes\n");
					continue;
				}
				if ( INVALID_FILE_SIZE == dwFileContentSize )
				{
					dwErrorCode = KERNEL32$GetLastError();
					internal_printf("GetFileSize failed. (%lu)\n", dwErrorCode);
					goto END;
				}

				// free any current buffers
				if (NULL != lpFileContent)
				{
					intFree(lpFileContent);
					lpFileContent=NULL;
				}

				// allocate a buffer for the current file contents
				lpFileContent = (PBYTE)intAlloc(dwFileContentSize);
				if ( NULL == lpFileContent )
				{
					dwErrorCode = ERROR_OUTOFMEMORY;
					internal_printf("intAlloc failed. (%lu)\n", dwErrorCode);
					goto END;
				}

				// read the current file contents into buffer
				if ( FALSE == ReadFile(	hFile, lpFileContent, dwFileContentSize, &dwBytesRead, NULL )	)
				{
					dwErrorCode = KERNEL32$GetLastError();
					internal_printf("ReadFile failed. (%lu)\n", dwErrorCode);
					goto END;
				}

				// check if we read in everything we were expecting
				if ( dwBytesRead != dwFileContentSize )
				{
					dwErrorCode = ERROR_READ_FAULT;
					internal_printf("ReadFile failed to read all bytes.\n");
					goto END;
				}
				
				lpFileContentEnd = lpFileContent + dwFileContentSize;

				// loop through the current file contents
				for(szCurrentLine = (LPSTR)lpFileContent; szCurrentLine < (LPSTR)(lpFileContentEnd); szCurrentLine = szCurrentLineEnd+2)
				{
					// get the end to the first line
					szCurrentLineEnd = MSVCRT$strstr(szCurrentLine, "\r\n");
					if ( NULL == szCurrentLineEnd ) break;
					
					dwCurrentLineSize = szCurrentLineEnd - szCurrentLine + 2;

					// update the total size with just the size of this line
					dwNewCSVSize = dwCurrentCSVSize + dwCurrentLineSize;

					// allocate a new csv buffer to hold the new entry
					szNewCSV = (LPSTR)intAlloc( dwNewCSVSize );
					if (NULL == szNewCSV)
					{
						dwErrorCode = ERROR_OUTOFMEMORY;
						internal_printf("intRealloc failed. (%lu)\n", dwErrorCode);
						goto END;
					}

					// copy the current buffer
					MSVCRT$memcpy(szNewCSV, szCurrentCSV, dwCurrentCSVSize);

					// append the current line to the overall
					MSVCRT$memcpy(szNewCSV+dwCurrentCSVSize, szCurrentLine, dwCurrentLineSize);

					// update the current buffer and size
					intFree(szCurrentCSV);
					szCurrentCSV = szNewCSV;
					szNewCSV = NULL;
					dwCurrentCSVSize = dwNewCSVSize;
				} // end loop through current file contents
			} // end if filename is not null
		} // end loop through all the files in the set
	} // end if there are files
	else
	{
		dwErrorCode = ERROR_BAD_ARGUMENTS;
		internal_printf("file list is empty.\n");
		goto END;
	}

	*lpdwCSVSize = dwCurrentCSVSize;
	*lpszCSV = szCurrentCSV;

	szCurrentCSV = NULL;

END:

	if ( ( NULL != hFile ) && ( INVALID_HANDLE_VALUE != hFile ) )
	{
		KERNEL32$CloseHandle( hFile );
		hFile = NULL;
	}

	if (NULL != lpFileContent)
	{
		intFree(lpFileContent);
		lpFileContent=NULL;
	}

	if (NULL != szCurrentCSV)
	{
		intFree(szCurrentCSV);
		szCurrentCSV=NULL;
	}

	if (NULL != szNewCSV)
	{
		intFree(szNewCSV);
		szNewCSV=NULL;
	}

	return dwErrorCode;
}


#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPWSTR* lpswzResults = NULL;
	DWORD dwResultsCount = 0;
	WCHAR swzRootDirectory[MAX_PATH];
	
	if(!bofstart())
	{
		return;
	}

	// get the root directory
	if (0 == KERNEL32$ExpandEnvironmentStringsW(SWZ_ROOT_DIRECTORY, swzRootDirectory, MAX_PATH))
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "ExpandEnvironmentStringsW FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

	// find all the audit.csv files
	internal_printf("Find all audit.csv files...\n");
	dwErrorCode = RecursiveFindFile(swzRootDirectory, SWZ_SEARCH_FILENAME, &lpswzResults, &dwResultsCount);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "RecursiveFindFile FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

  
/*
	// deduplicate entries in the all the audit.csv files
	internal_printf("Deduplicate results...\n");
	dwErrorCode = Deduplicate_CSV(lpswzResults, dwResultsCount);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Deduplicate_CSV FAILED (%lu)\n", dwErrorCode);
        goto END;
	}
*/
    internal_printf("SUCCESS.\n");

END:
	if (NULL != lpswzResults)
	{
		for(DWORD dwResultsOffset=0; dwResultsOffset<dwResultsCount; dwResultsOffset++)
		{
			if (NULL != lpswzResults[dwResultsOffset])
			{
				intFree(lpswzResults[dwResultsOffset]);
				lpswzResults[dwResultsOffset]=NULL;
			}
		}
		intFree(lpswzResults);
		lpswzResults=NULL;
	}

	printoutput(TRUE);

	bofstop();
};

#else

int main()
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	WCHAR swzRootDirectory[MAX_PATH];
	LPWSTR* lpswzResults = NULL;
	DWORD dwResultsCount = 0;
	LPSTR szCSV = NULL;
	DWORD dwCSVSize = 0;

	// get the root directory
	if (0 == KERNEL32$ExpandEnvironmentStringsW(SWZ_ROOT_DIRECTORY, swzRootDirectory, MAX_PATH))
	{
		dwErrorCode = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "ExpandEnvironmentStringsW FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

	// find all the audit.csv files
	internal_printf("Find all audit.csv files...\n");
	dwErrorCode = RecursiveFindFile(swzRootDirectory, SWZ_SEARCH_FILENAME, &lpswzResults, &dwResultsCount);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "RecursiveFindFile FAILED (%lu)\n", dwErrorCode);
        goto END;
	}


	// deduplicate entries in the all the audit.csv files
	internal_printf("Deduplicate results...\n");
	dwErrorCode = Deduplicate_CSV(lpswzResults, dwResultsCount, &szCSV, &dwCSVSize );
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Deduplicate_CSV FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

	internal_printf("Deduplicate result:\n%s\n", szCSV);

    internal_printf("SUCCESS.\n");

END:

	if (NULL != szCSV)
	{
		intFree(szCSV);
		szCSV=NULL;
	}

	if (NULL != lpswzResults)
	{
		for(DWORD dwResultsOffset=0; dwResultsOffset<dwResultsCount; dwResultsOffset++)
		{
			if (NULL != lpswzResults[dwResultsOffset])
			{
				intFree(lpswzResults[dwResultsOffset]);
				lpswzResults[dwResultsOffset]=NULL;
			}
		}
		intFree(lpswzResults);
		lpswzResults=NULL;
	}

	return dwErrorCode;
}

#endif
