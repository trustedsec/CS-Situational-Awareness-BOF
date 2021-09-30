#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#define SWZ_ROOT_DIRECTORY L"%SYSTEMROOT%\\system32\\GroupPolicy"
#define SWZ_ROOT_WOW64DIRECTORY L"%SYSTEMROOT%\\sysnative\\GroupPolicy"
#define SWZ_SEARCH_FILENAME L"audit.csv"
#define DW_FIELD_COUNT 6

DWORD RecursiveFindFile(LPWSTR swzDirectory, LPWSTR swzFileName, LPWSTR** lpswzResults, PDWORD lpdwResultsCount)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	WIN32_FIND_DATAW findFileData = {0};
	HANDLE hFindFile = NULL;
	LPWSTR swzNewFullpathName = NULL;
	WCHAR swzQuery[MAX_PATH];

	intZeroMemory(&findFileData, sizeof(findFileData));
	intZeroMemory(swzQuery, MAX_PATH * sizeof(WCHAR));

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

DWORD Combine_CSV(LPWSTR* lpswzFileSet, DWORD dwFileSetCount, LPSTR** lpszCSV, PDWORD lpdwCSVCount)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	HANDLE hFile = NULL;
	DWORD dwBytesRead = 0;
	PBYTE lpFileContent = NULL;
	DWORD dwFileContentSize = 0;
	LPSTR lpFileToken = NULL;
	LPSTR lpNextFileToken = NULL;
	LPSTR szLine = NULL;
	DWORD dwLineSize = 0;
	LPSTR lpLineToken = NULL;
	DWORD dwFileSetIndex=0;
	DWORD dwCSVOffset = 0;
	DWORD dwFieldCount = 0;

	// check if there are files
	if (NULL != lpswzFileSet)
	{
		// loop through all the files in the set
		for(dwFileSetIndex=0; dwFileSetIndex<dwFileSetCount; dwFileSetIndex++)
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
				if ( FALSE == KERNEL32$ReadFile( hFile, lpFileContent, dwFileContentSize, &dwBytesRead, NULL ) )
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
				
				// loop through the lines in the file
				for(lpFileToken = MSVCRT$strtok_s((LPSTR)lpFileContent, "\n", &lpNextFileToken); NULL != lpFileToken; lpFileToken = MSVCRT$strtok_s(NULL, "\n", &lpNextFileToken))
				{
					// check the number of fields in the line
					dwFieldCount = 0;
					lpLineToken = lpFileToken;
					while (TRUE)
					{
						lpLineToken = MSVCRT$strstr(lpLineToken, ",");
						if (NULL == lpLineToken) { break; }
						lpLineToken++;
						dwFieldCount++;
					} 
					if ( dwFieldCount < DW_FIELD_COUNT ) { break; }

					dwLineSize = MSVCRT$strlen(lpFileToken) + 1;

					// allocate a new buffer for the current line
					szLine = (LPSTR)intAlloc(dwLineSize);
					if ( NULL == szLine )
					{
						dwErrorCode = ERROR_OUTOFMEMORY;
						internal_printf("intAlloc failed. (%lu)\n", dwErrorCode);
						goto END;
					}

					// copy the current line
					MSVCRT$strcpy(szLine, lpFileToken);
					szLine[dwLineSize-2] = '\n';

					// check if the line is already in the csv
					for( dwCSVOffset = 0; dwCSVOffset < (*lpdwCSVCount); dwCSVOffset++ )
					{
						if ( 0 == MSVCRT$strcmp((*lpszCSV)[dwCSVOffset], szLine)) {	break; }
					}
					if ( dwCSVOffset < (*lpdwCSVCount) ) { continue; }

					// increment the find count
					(*lpdwCSVCount) = (*lpdwCSVCount) + 1;

					// re-allocate the CSV buffer to hold the new entry
					(*lpszCSV) = intRealloc((*lpszCSV), ((*lpdwCSVCount)*sizeof(LPSTR)));
					if (NULL == (*lpszCSV))
					{
						dwErrorCode = ERROR_OUTOFMEMORY;
						internal_printf("intRealloc failed. (%lu)\n", dwErrorCode);
						goto END;
					}
					
					// update the CSV buffer with the new entry
					(*lpszCSV)[((*lpdwCSVCount)-1)] = szLine;
					szLine = NULL;
				} // end loop through lines in file
			} // end if filename is not null
		} // end loop through all the files in the set
	} // end if there are files
	else
	{
		dwErrorCode = ERROR_BAD_ARGUMENTS;
		internal_printf("No audit.csv files\n");
		goto END;
	}

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

	if (NULL != szLine)
	{
		intFree(szLine);
		szLine=NULL;
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
	WCHAR swzRootDirectory[MAX_PATH];
	LPWSTR* lpswzResults = NULL;
	DWORD dwResultsCount = 0;
	LPSTR* lpszCSV = NULL;
	DWORD dwCSVCount = 0;
	datap parser;
    BOOL iswow64 = 0;

	if(!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	iswow64 = BeaconDataInt(&parser);

	// get the root directory
	if (0 == KERNEL32$ExpandEnvironmentStringsW((iswow64) ? SWZ_ROOT_WOW64DIRECTORY : SWZ_ROOT_DIRECTORY, swzRootDirectory, MAX_PATH))
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

  	// Combine entries in the all the audit.csv files
	internal_printf("Combine results...\n");
	dwErrorCode = Combine_CSV(lpswzResults, dwResultsCount, &lpszCSV, &dwCSVCount );
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Combine_CSV FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

	if (NULL != lpszCSV)
	{
		internal_printf("Combined audit.csv (%lu lines):\n", dwCSVCount);
		for(DWORD dwCSVOffset=0; dwCSVOffset<dwCSVCount; dwCSVOffset++)
		{
			if (NULL != lpszCSV[dwCSVOffset])
			{
				internal_printf("%s", lpszCSV[dwCSVOffset]);
			}
		}
	}

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

	if (NULL != lpszCSV)
	{
		for(DWORD dwCSVOffset=0; dwCSVOffset<dwCSVCount; dwCSVOffset++)
		{
			if (NULL != lpszCSV[dwCSVOffset])
			{
				intFree(lpszCSV[dwCSVOffset]);
				lpszCSV[dwCSVOffset]=NULL;
			}
		}
		intFree(lpszCSV);
		lpszCSV=NULL;
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
	LPSTR* lpszCSV = NULL;
	DWORD dwCSVCount = 0;

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


	// Combine entries in the all the audit.csv files
	internal_printf("Combine results...\n");
	dwErrorCode = Combine_CSV(lpswzResults, dwResultsCount, &lpszCSV, &dwCSVCount );
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Combine_CSV FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

	if (NULL != lpszCSV)
	{
		internal_printf("Combined audit.csv (%lu lines):\n", dwCSVCount);
		for(DWORD dwCSVOffset=0; dwCSVOffset<dwCSVCount; dwCSVOffset++)
		{
			if (NULL != lpszCSV[dwCSVOffset])
			{
				internal_printf("%s", lpszCSV[dwCSVOffset]);
			}
		}
	}

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

	if (NULL != lpszCSV)
	{
		for(DWORD dwCSVOffset=0; dwCSVOffset<dwCSVCount; dwCSVOffset++)
		{
			if (NULL != lpszCSV[dwCSVOffset])
			{
				intFree(lpszCSV[dwCSVOffset]);
				lpszCSV[dwCSVOffset]=NULL;
			}
		}
		intFree(lpszCSV);
		lpszCSV=NULL;
	}

	return dwErrorCode;
}

#endif
