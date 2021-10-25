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

#define SAFE_ALLOC(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define SAFE_FREE(addr) \
		if ((addr) != NULL)	\
		{	\
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (addr)); \
			(addr) = NULL;	\
		}


DWORD Net_use_add(LPWSTR pswzDeviceName, LPWSTR pswzShareName, LPWSTR pswzPassword, LPWSTR pswzUsername, BOOL bPersist, BOOL bPrivacy, BOOL bIpc)
{
	DWORD			dwResult	= ERROR_SUCCESS;
	LPNETRESOURCEW	lpnrLocal	= NULL;
	DWORD			dwFlags		= NULL; //CONNECT_TEMPORARY;

	// check if RequirePrivacy flag is true or false
	if (!bPrivacy)
	{
		dwFlags = CONNECT_TEMPORARY;
	}
	else
	{
		dwFlags = CONNECT_TEMPORARY | CONNECT_ENCRYPTED;
	}


	// Basic argument checks
	if ((NULL == pswzDeviceName) || (1 > MSVCRT$wcslen(pswzDeviceName)) || (5 < MSVCRT$wcslen(pswzDeviceName)) )
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_add\n");
		goto fail;
	}
	if ((NULL == pswzShareName) || ( 5 > MSVCRT$wcslen(pswzShareName)))
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_add\n");
		goto fail;		
	}

	// Allocate resources
	lpnrLocal = (LPNETRESOURCEW)SAFE_ALLOC(BIG_BUFFER_SIZE);
	if (NULL == lpnrLocal)
	{
		dwResult = ERROR_OUTOFMEMORY;
		BeaconPrintf(CALLBACK_ERROR, "SAFE_ALLOC failed: 0x%08lx\n", dwResult);
		goto fail;
	}

	// Initialize the resource
	intZeroMemory(lpnrLocal, BIG_BUFFER_SIZE);

	// Fill in the resource
	if (2 < MSVCRT$wcslen(pswzDeviceName))
	{
		lpnrLocal->dwType = RESOURCETYPE_PRINT;
	}
	else
	{
		lpnrLocal->dwType = RESOURCETYPE_DISK;
	}
	// check if mounting IPC$
	if (!bIpc)
	{
		lpnrLocal->lpLocalName = pswzDeviceName;
	}
	else
	{
		lpnrLocal->lpLocalName = NULL;
	}
	lpnrLocal->lpRemoteName = pswzShareName;
	lpnrLocal->lpProvider = NULL;

	// Check if the connection should persist
	if (TRUE == bPersist)
	{
		dwFlags = CONNECT_UPDATE_PROFILE;
	}

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
	}
	else if (ERROR_ACCESS_DENIED == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The caller does not have access to the network resource.\n");
		goto fail;
	}
	else if (ERROR_ALREADY_ASSIGNED == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The device is already connected to a network resource.\n");
		goto fail;
	}
	else if (ERROR_BAD_DEVICE == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The device name is not valid.\n");
		goto fail;
	}
	else if (ERROR_BAD_NET_NAME == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The network name cannot be found.\n");
		goto fail;
	}
	else if (ERROR_BAD_USERNAME == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The user name is not valid.\n");
		goto fail;
	}
	else if (ERROR_INVALID_PASSWORD == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The password is not valid.\n");
		goto fail;
	}
	else if (ERROR_LOGON_FAILURE == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "Logon failure because of an unknown user name or a bad password.\n");
		goto fail;
	}
	else if (ERROR_NO_NET_OR_BAD_PATH == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "No network provider accepted the given network path.\n");
		goto fail;
	}
	else if (ERROR_NO_NETWORK == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "The network is unavailable.\n");
		goto fail;
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "MPR$WNetCancelConnection2W failed: 0x%08lx\n", dwResult);
		goto fail;
	}


fail:
	// Free the memory
	SAFE_FREE(lpnrLocal);

	return dwResult;
}


DWORD Net_use_delete(LPWSTR pswzDeviceName, BOOL bPersist)
{
	DWORD	dwResult	= NO_ERROR;
	DWORD	dwFlags		= 0;

	// Basic argument checks
	if ((NULL == pswzDeviceName) || (1 > MSVCRT$wcslen(pswzDeviceName)) || (5 < MSVCRT$wcslen(pswzDeviceName)))
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_delete\n");
		goto fail;
	}
	
	// Check if the cancelation should persist
	if (TRUE == bPersist)
	{
		dwFlags = CONNECT_UPDATE_PROFILE;
	}

	// Delete the connection
	dwResult = MPR$WNetCancelConnection2W(
		pswzDeviceName,
		dwFlags,
		FALSE
	);
	if (NO_ERROR == dwResult)
	{
		internal_printf("%S was deleted successfully.\n", pswzDeviceName);
	}
	else if (ERROR_DEVICE_IN_USE == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "%S is in use by an active process and cannot be disconnected.\n", pswzDeviceName);
		goto fail;
	}
	else if (ERROR_OPEN_FILES == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "There are open files on %S so it cannot be disconnected.\n", pswzDeviceName);
		goto fail;
	}
	else if (ERROR_NOT_CONNECTED == dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "%S is not a redirected device, or the system is not currently connected to the device.\n", pswzDeviceName);
		goto fail;
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "MPR$WNetCancelConnection2W failed: 0x%08lx\n", dwResult);
		goto fail;
	}

fail:

	return dwResult;
}


DWORD Net_use_list(LPWSTR pswzDeviceName)
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
			if ( (NULL == pswzDeviceName) || (0 == MSVCRT$wcslen(pswzDeviceName)) )
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
				if ( ( NULL == pswzDeviceName) || (0 == MSVCRT$wcslen(pswzDeviceName)) )
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
					if (0 != MSVCRT$_wcsicmp(pwszLocalName, pswzDeviceName))
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

	return dwResult;
}



// Function to perform a basic mimic of the net use command 
DWORD Net_use(LPWSTR pswzDeviceName, LPWSTR pswzShareName, LPWSTR pswzPassword, LPWSTR pswzUsername, LPWSTR pswzDelete, LPWSTR pswzPersist, LPWSTR pswzPrivacy, PWSTR pswzIpc)
{
	DWORD	dwResult	= ERROR_SUCCESS;
	BOOL	bPersist	= FALSE;
	BOOL	bPrivacy	= FALSE;
	BOOL	bIpc		= FALSE;

	// Check what type of net use operation (list, add, delete) based on arguments
	if (
		( (NULL == pswzShareName) || (0 == MSVCRT$wcslen(pswzShareName)) ) 
		&& 
		( (NULL == pswzDelete) || (0 == MSVCRT$wcslen(pswzDelete)) || (0 == MSVCRT$_wcsicmp(pswzDelete, STR_FALSE)) )
		)
	{
		// list connections
		dwResult = Net_use_list(pswzDeviceName);
	}
	else if (
		( (NULL != pswzDeviceName) && (1 < MSVCRT$wcslen(pswzDeviceName)) )
		&&
		( (NULL != pswzShareName) && (1 < MSVCRT$wcslen(pswzShareName)) )
		&&
		( (NULL == pswzDelete) || (0 == MSVCRT$wcslen(pswzDelete)) || (0 == MSVCRT$_wcsicmp(pswzDelete, STR_FALSE)) )
		)
	{
		// Check if persist flag is set
		if ( (NULL != pswzPersist) && (0 == MSVCRT$_wcsicmp(pswzPersist, STR_TRUE)) )
		{
			bPersist = TRUE;
		}
		// Check if privacy flag is set
		if ( (NULL != pswzPrivacy) && (0 == MSVCRT$_wcsicmp(pswzPrivacy, STR_TRUE)) )
		{
			bPrivacy = TRUE;
		}
		// Check if mount_ipc flag is set
		if ( (NULL != pswzIpc) && (0 == MSVCRT$_wcsicmp(pswzIpc, STR_TRUE)) )
		{
			bIpc = TRUE;
		}

		// add connection
		dwResult = Net_use_add(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, bPersist, bPrivacy, bIpc);
	}
	else if (
		( (NULL != pswzDeviceName) && (1 < MSVCRT$wcslen(pswzDeviceName)) )
		&&
		( (NULL != pswzDelete) && (0 == MSVCRT$_wcsicmp(pswzDelete, STR_TRUE)) )
		)
	{
		// Check if persist flag is set
		if ((NULL != pswzPersist) && (0 == MSVCRT$_wcsicmp(pswzPersist, STR_TRUE)))
		{
			bPersist = TRUE;
		}

		// delete connect
		dwResult = Net_use_delete(pswzDeviceName, bPersist);
	}
	else
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use\n");
		goto fail;
	}

fail:
	return dwResult;
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

	BeaconDataParse(&parser, Buffer, Length);
	pswzDeviceName	= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzShareName	= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzPassword	= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzUsername	= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzDelete		= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzPersist		= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzPrivacy		= (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzIpc			= (LPWSTR)BeaconDataExtract(&parser, NULL);


	if(!bofstart())
	{
		return;
	}

	dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist, pswzPrivacy, pswzIpc);

	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "net_use failed: 0x%08lx\n", dwResult);
	}

	printoutput(TRUE);

	bofstop();
};
#else
int main()
{
	DWORD	dwResult		= ERROR_SUCCESS;

	LPWSTR	pswzDeviceName	= NULL;
	LPWSTR	pswzShareName	= NULL;
	LPWSTR	pswzPassword	= NULL;
	LPWSTR	pswzUsername	= NULL;
	LPWSTR	pswzDelete		= NULL;
	LPWSTR	pswzPersist		= NULL;
	
	pswzDeviceName	= L"";
	pswzShareName	= L"";
	pswzPassword	= L"";
	pswzUsername	= L"";
	pswzDelete		= STR_FALSE;
	pswzPersist		= STR_FALSE;

	BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
	BeaconPrintf(CALLBACK_OUTPUT, "Test: List all devices\n");
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDeviceName: \"%S\"\n", pswzDeviceName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzShareName:  \"%S\"\n", pswzShareName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPassword:   \"%S\"\n", pswzPassword);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzUsername:   \"%S\"\n", pswzUsername);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDelete:     \"%S\"\n", pswzDelete);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPersist:    \"%S\"\n", pswzPersist);
	BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");

    dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist);
	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n FAILED (%08lx) \n========================================\n", dwResult);
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n SUCCESS \n========================================\n");
	}
	
	pswzDeviceName	= L"Q:";
	pswzShareName	= L"\\\\192.168.85.131\\share";
	pswzPassword	= L"trustedsec";
	pswzUsername	= L"root";
	pswzDelete		= STR_FALSE;
	pswzPersist		= STR_FALSE;

	BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
	BeaconPrintf(CALLBACK_OUTPUT, "Test: Add network resource\n");
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDeviceName: \"%S\"\n", pswzDeviceName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzShareName:  \"%S\"\n", pswzShareName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPassword:   \"%S\"\n", pswzPassword);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzUsername:   \"%S\"\n", pswzUsername);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDelete:     \"%S\"\n", pswzDelete);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPersist:    \"%S\"\n", pswzPersist);
	BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");

	dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist);
	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n FAILED (%08lx) \n========================================\n", dwResult);
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n SUCCESS \n========================================\n");
	}


	pswzDeviceName	= L"Q:";
	pswzShareName	= NULL;
	pswzPassword	= NULL;
	pswzUsername	= NULL;
	pswzDelete		= NULL;
	pswzPersist		= NULL;

	BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
	BeaconPrintf(CALLBACK_OUTPUT, "Test: List details of specifc device\n");
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDeviceName: \"%S\"\n", pswzDeviceName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzShareName:  \"%S\"\n", pswzShareName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPassword:   \"%S\"\n", pswzPassword);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzUsername:   \"%S\"\n", pswzUsername);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDelete:     \"%S\"\n", pswzDelete);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPersist:    \"%S\"\n", pswzPersist);
	BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");

	dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist);
	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n FAILED (%08lx) \n========================================\n", dwResult);
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n SUCCESS \n========================================\n");
	}

	pswzDeviceName	= L"Q:";
	pswzShareName	= NULL;
	pswzPassword	= NULL;
	pswzUsername	= NULL;
	pswzDelete		= STR_TRUE;
	pswzPersist		= STR_TRUE;

	BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
	BeaconPrintf(CALLBACK_OUTPUT, "Test: Delete specific device\n");
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDeviceName: \"%S\"\n", pswzDeviceName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzShareName:  \"%S\"\n", pswzShareName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPassword:   \"%S\"\n", pswzPassword);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzUsername:   \"%S\"\n", pswzUsername);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDelete:     \"%S\"\n", pswzDelete);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPersist:    \"%S\"\n", pswzPersist);
	BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");

	dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist);
	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n FAILED (%08lx) \n========================================\n", dwResult);
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n SUCCESS \n========================================\n");
	}

	pswzDeviceName = NULL;
	pswzShareName = NULL;
	pswzPassword = NULL;
	pswzUsername = NULL;
	pswzDelete = NULL;
	pswzPersist = NULL;

	BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n");
	BeaconPrintf(CALLBACK_OUTPUT, "Test: List all devices\n");
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDeviceName: \"%S\"\n", pswzDeviceName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzShareName:  \"%S\"\n", pswzShareName);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPassword:   \"%S\"\n", pswzPassword);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzUsername:   \"%S\"\n", pswzUsername);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzDelete:     \"%S\"\n", pswzDelete);
	BeaconPrintf(CALLBACK_OUTPUT, "pswzPersist:    \"%S\"\n", pswzPersist);
	BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");

	dwResult = Net_use(pswzDeviceName, pswzShareName, pswzPassword, pswzUsername, pswzDelete, pswzPersist);
	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n FAILED (%08lx) \n========================================\n", dwResult);
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "\n========================================\n SUCCESS \n========================================\n");
	}
}
#endif
