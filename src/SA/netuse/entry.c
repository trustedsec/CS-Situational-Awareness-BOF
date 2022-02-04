#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <winnetwk.h>

#define NET_USE_LIST_FMT_STRING		"%-12S %-8S %-32S %-32S\n"
#define NET_USE_DETAIL_FMT_STRING	"Local name        %S\nRemote name       %S\nResource type     %S\nStatus            %S\nUser Name         %S\n"
#define STR_TRUE					L"TRUE"
#define STR_FALSE					L"FALSE"
#define BIG_BUFFER_SIZE				16384
#define SMALL_BUFFER_SIZE			64
#define CONNECT_ENCRYPTED			32768
#define CMD_ADD 1
#define CMD_LIST 2
#define CMD_DELETE 3

#define SAFE_ALLOC(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define SAFE_FREE(addr) \
		if ((addr) != NULL)	\
		{	\
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (addr)); \
			(addr) = NULL;	\
		}

void * BeaconDataExtractOrNull(datap* parser, int* size)
{
    char * result = BeaconDataExtract(parser, size);
    return result[0] == '\0' ? NULL : result;
}

void print_windows_error(char * premsg, DWORD errnum)
{
    LPSTR msg = NULL;
    if(KERNEL32$FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, errnum,
    0, (LPSTR)&msg, 0, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "%s : %s", (premsg) ? premsg : "", msg);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "failed to format error message: %lu", errnum);
    }
    if(msg)
    {
        KERNEL32$LocalFree(msg);
    }
    return;

}

void Net_use_add(LPWSTR pswzDeviceName, LPWSTR pswzShareName, LPWSTR pswzPassword, LPWSTR pswzUsername, BOOL bPersist, BOOL bPrivacy)
{
	DWORD			dwResult	= ERROR_SUCCESS;
	LPNETRESOURCEW	lpnrLocal	= NULL;
	DWORD			dwFlags		= (bPersist) ? CONNECT_UPDATE_PROFILE : CONNECT_TEMPORARY; //CONNECT_TEMPORARY;

	// check if RequirePrivacy flag is true or false
	if (bPrivacy)
	{
		dwFlags |= CONNECT_ENCRYPTED;
	}

	// Allocate resources
	lpnrLocal = (LPNETRESOURCEW)SAFE_ALLOC(BIG_BUFFER_SIZE);
	if (NULL == lpnrLocal)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "SAFE_ALLOC failed: 0x%08lx\n", dwResult);
		goto fail;
	}
	

	// Fill in the resource
	lpnrLocal->dwType = RESOURCETYPE_DISK;
	lpnrLocal->lpLocalName = pswzDeviceName;
	lpnrLocal->lpRemoteName = pswzShareName;
	lpnrLocal->lpProvider = NULL;

	// Add connection
	dwResult = MPR$WNetAddConnection2W(
		lpnrLocal,
		pswzPassword,
		pswzUsername,
		dwFlags
	);
	if (NO_ERROR == dwResult)
	{
		internal_printf("The command completed successfully.\n");
	}else
	{
		print_windows_error("Unable to map share", dwResult);
		if(dwResult == ERROR_INVALID_PARAMETER)
		{
			BeaconPrintf(CALLBACK_ERROR, "If you set /REQUIREPRIVACY it is likely this flag is not supported on this computer");
		}
	}


fail:
	// Free the memory
	SAFE_FREE(lpnrLocal);

}


void Net_use_delete(LPWSTR target, BOOL bPersist, BOOL force)
{
	DWORD	dwResult	= NO_ERROR;
	DWORD	dwFlags		= (bPersist) ? CONNECT_UPDATE_PROFILE : 0;
	

	// Delete the connection
	dwResult = MPR$WNetCancelConnection2W(
		target,
		dwFlags,
		force
	);
	if (NO_ERROR == dwResult)
	{
		internal_printf("%ls was deleted successfully.\n", target);
	}
	else 
	{
		print_windows_error("Unable to delete share", dwResult);
	}
}


void Net_use_list(LPWSTR pswzDeviceName)
{
	DWORD			dwResult = NO_ERROR;
	HANDLE			hEnum = NULL;
	DWORD			cbBuffer = BIG_BUFFER_SIZE;
	DWORD			cEntries = -1;
	LPNETRESOURCEW	lpnrLocal = NULL;
	DWORD			i = 0;
	LPNETRESOURCEW	lpCurrent = NULL;
	LPNETRESOURCEW	lpnrRemote = NULL;
	DWORD			dwResourceInformationLength = BIG_BUFFER_SIZE;
	LPWSTR			lpSystem = NULL;
	WCHAR			pwszStatus[SMALL_BUFFER_SIZE];
	WCHAR			pwszDriveType[SMALL_BUFFER_SIZE];
	WCHAR			pwszUserName[MAX_PATH];
	DWORD			dwszUserNameLength = MAX_PATH;
	WCHAR			pwszLocalName[MAX_PATH];
	WCHAR			pwszRemoteName[MAX_PATH];
	WCHAR			pwszProviderName[MAX_PATH];

	// Call the WNetOpenEnum function to begin the enumeration
	dwResult = MPR$WNetOpenEnumW(
		RESOURCE_CONNECTED,	// scope - all connected resources
		RESOURCETYPE_ANY,	// type  - all resources
		0,					// usage - all resources
		NULL,
		&hEnum				// handle to the resource enumeration
	);
	if (dwResult != NO_ERROR)
	{
		BeaconPrintf(CALLBACK_ERROR, "MPR$WNetOpenEnumW failed: 0x%08lx\n", dwResult);
		goto fail;
	}

	// Allocate resources
	lpnrLocal = (LPNETRESOURCEW)SAFE_ALLOC(cbBuffer);
	if (NULL == lpnrLocal)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "SAFE_ALLOC failed: 0x%08lx\n", dwResult);
		goto fail;
	}

	// Loop through enumerating the devices until there are no more
	do
	{
		// Initialize the buffer
		intZeroMemory(lpnrLocal, cbBuffer);

		// Call the WNetEnumResource function to continue the enumeration
		dwResult = MPR$WNetEnumResourceW(
			hEnum,			// resource enumeration handle
			&cEntries,		// as many entries as possible (-1)
			lpnrLocal,		// the results, an array of  resource
			&cbBuffer		// buffer size
		);

		// If the call succeeds, loop through the structures
		if (dwResult == NO_ERROR)
		{
			// If we are listing all connected devices, then display the header
			if ( (NULL == pswzDeviceName) )
			{
				internal_printf(NET_USE_LIST_FMT_STRING, L"Status", L"Local", L"Remote", L"Network");
				internal_printf("-------------------------------------------------------------------------------------------------\n");
			}
			// Loop through all the returned network resources in array
			for (i = 0; i < cEntries; i++)
			{
				// Reset/initialize values for current resource
				lpCurrent = &lpnrLocal[i];
				lpnrRemote = NULL;
				dwResourceInformationLength = BIG_BUFFER_SIZE;
				lpSystem = NULL;
				dwszUserNameLength = SMALL_BUFFER_SIZE;
				intZeroMemory(pwszStatus, SMALL_BUFFER_SIZE);
				intZeroMemory(pwszDriveType, SMALL_BUFFER_SIZE);
				intZeroMemory(pwszUserName, MAX_PATH);
				intZeroMemory(pwszLocalName, MAX_PATH);
				intZeroMemory(pwszRemoteName, MAX_PATH);
				intZeroMemory(pwszProviderName, MAX_PATH);

				// Get the local name
				if (lpCurrent->lpLocalName)
				{
					MSVCRT$wcscpy(pwszLocalName, lpCurrent->lpLocalName);
				}
				else
				{
					MSVCRT$wcscpy(pwszLocalName, L"");
				}

				// Get the remote name
				if (lpCurrent->lpRemoteName)
				{
					MSVCRT$wcscpy(pwszRemoteName, lpCurrent->lpRemoteName);
				}
				else
				{
					MSVCRT$wcscpy(pwszRemoteName, L"");
				}

				// Get the network provider
				if (lpCurrent->lpProvider)
				{
					MSVCRT$wcscpy(pwszProviderName, lpCurrent->lpProvider);
				}
				else
				{
					MSVCRT$wcscpy(pwszProviderName, L"");
				}

				// Get the Drive Type
				if (RESOURCETYPE_DISK == lpCurrent->dwType)
				{
					MSVCRT$wcscpy(pwszDriveType, L"Disk");
				}
				else if (RESOURCETYPE_PRINT == lpCurrent->dwType)
				{
					MSVCRT$wcscpy(pwszDriveType, L"Print");
				}
				else
				{
					MSVCRT$wcscpy(pwszDriveType, L"Other");
				}

				// Get the status
				lpnrRemote = (LPNETRESOURCEW)SAFE_ALLOC(dwResourceInformationLength);
				if (NULL == lpnrRemote)
				{
					dwResult = ERROR_OUTOFMEMORY;
					BeaconPrintf(CALLBACK_ERROR, "SAFE_ALLOC failed: 0x%08lx\n", dwResult);
					goto fail;
				}
				dwResult = MPR$WNetGetResourceInformationW(
					lpCurrent,
					lpnrRemote,
					&dwResourceInformationLength,
					&lpSystem
				);
				if (NO_ERROR == dwResult)
				{
					MSVCRT$wcscpy(pwszStatus, L"OK");
				}
				else if (ERROR_BAD_NET_NAME == dwResult)
				{
					MSVCRT$wcscpy(pwszStatus, L"Disconnected");
				}
				else if (ERROR_NO_NETWORK == dwResult)
				{
					MSVCRT$wcscpy(pwszStatus, L"Unavailable");
				}
				else
				{
					MSVCRT$wcscpy(pwszStatus, L"");
				}
				SAFE_FREE(lpnrRemote);

				// Get the username
				dwResult = MPR$WNetGetUserW(
					pwszLocalName,
					pwszUserName,
					&dwszUserNameLength
				);

				// If we are listing all connected devices, then add to the list
				if ( ( NULL == pswzDeviceName) )
				{
					internal_printf(
						NET_USE_LIST_FMT_STRING, 
						pwszStatus, 
						pwszLocalName, 
						pwszRemoteName, 
						pwszProviderName
					);
				}
				else // else we are looking for a specific device
				{
					// Is this the one we are looking for, if not continue
					if (0 != MSVCRT$_wcsicmp(pwszLocalName, pswzDeviceName) && 0 != MSVCRT$_wcsicmp(pwszRemoteName, pswzDeviceName))
					{
						continue;
					}
					
					internal_printf(
						NET_USE_DETAIL_FMT_STRING, 
						pwszLocalName, 
						pwszRemoteName, 
						pwszDriveType,
						pwszStatus,
						pwszUserName
					);
				} // end else we are looking for a specific device
			} // end loop through all the returned network resources in array
		} // end if the call succeeds, loop through the structures
		else if (dwResult != ERROR_NO_MORE_ITEMS)
		{
			BeaconPrintf(CALLBACK_ERROR, "MPR$WNetEnumResourceW failed with error %lu\n", dwResult);
			goto fail;
		} // end else if MPR$WNetEnumResourceW returned an unexpected error
	} while (dwResult != ERROR_NO_MORE_ITEMS);

	internal_printf("The command completed successfully.\n");
	dwResult = NO_ERROR;

fail:

	// Free the memory
	SAFE_FREE(lpnrLocal);
	SAFE_FREE(lpnrRemote);

	// End the enumeration
	if ((NULL != hEnum) && (INVALID_HANDLE_VALUE != hEnum))
	{
		dwResult = MPR$WNetCloseEnum(hEnum);
		if (dwResult != NO_ERROR)
		{
			BeaconPrintf(CALLBACK_ERROR, "MPR$WNetEnumResourceW failed with error %lu\n", dwResult);
		}
		hEnum = NULL;
	}

}

#ifdef BOF
// BOF entry point function
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD	dwResult		= ERROR_SUCCESS;
	datap	parser			= {0};
	LPWSTR	pswzDeviceName	= NULL;
	LPWSTR	pswzShareName	= NULL;
	LPWSTR	pswzPassword	= NULL;
	LPWSTR	pswzUsername	= NULL;
	LPWSTR	pswzDelete		= NULL;
	LPWSTR	pswzPersist		= NULL;
	LPWSTR  pswzPrivacy		= NULL;
	LPWSTR  pswzIpc			= NULL;
	short cmd = 0, persist = 0, requirePrivacy = 0, force = 0;

	if(!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	cmd = BeaconDataShort(&parser);
	switch(cmd)
	{
		case CMD_ADD:
			pswzShareName = (wchar_t *)BeaconDataExtract(&parser, NULL);
			pswzUsername = BeaconDataExtractOrNull(&parser, NULL);
			pswzPassword = BeaconDataExtractOrNull(&parser, NULL);
			pswzDeviceName = BeaconDataExtractOrNull(&parser, NULL);
			persist = BeaconDataShort(&parser);
			requirePrivacy = BeaconDataShort(&parser);
			Net_use_add(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, persist, requirePrivacy);
			break;

		case CMD_LIST:
			pswzDeviceName = BeaconDataExtractOrNull(&parser, NULL);
			Net_use_list(pswzDeviceName);
			break;

		case CMD_DELETE:
			pswzDeviceName = BeaconDataExtractOrNull(&parser, NULL);
			persist = BeaconDataShort(&parser);
			force = BeaconDataShort(&parser);
			Net_use_delete(pswzDeviceName, persist, force);
			break;

		default:
			BeaconPrintf(CALLBACK_ERROR, "Shouldn't be able to get to the default switchcase, invalid argument parse");
			return;
	}

	//dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist, pswzPrivacy, pswzIpc);

	end:
	printoutput(TRUE);

	bofstop();
};
#else
 // NOT IMPLEMENTED
#endif
