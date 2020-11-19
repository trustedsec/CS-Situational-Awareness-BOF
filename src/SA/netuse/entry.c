#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <winnetwk.h>

#define NET_USE_DELETE L"DELETE" 


// Helper function to modify connections
DWORD Net_use_connection(LPWSTR pswzDeviceName, LPWSTR pswzShareName)
{
	DWORD dwResult = ERROR_SUCCESS;

	// Basic argument checks
	if ((NULL == pswzDeviceName) || (1 > MSVCRT$wcslen(pswzDeviceName)) || (5 < MSVCRT$wcslen(pswzDeviceName)) )
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_connection");
	}
	if ((NULL == pswzShareName) || ( 5 > MSVCRT$wcslen(pswzShareName)))
	{
		dwResult = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_connection");
	}

	// Check if we are connecting or disconnecting device
	if ( 0 == MSVCRT$_wcsicmp(pswzShareName, NET_USE_DELETE) )
	{
		internal_printf("Cancelling a connection %S", pswzDeviceName);
	}
	else
	{
		internal_printf("Establishing a connection from %S to %S", pswzDeviceName, pswzShareName);
	}

fail:
	return dwResult;
}


// Helper function to list established connections
DWORD Net_use_list(LPWSTR pswzDeviceName)
{
	DWORD dwResult = NO_ERROR;
	LPNETRESOURCEW lpnr = NULL;
	HANDLE hEnum = NULL;
	DWORD cbBuffer = 16384;     // 16K is a good size
	DWORD cEntries = -1;        // enumerate all possible entries
	LPNETRESOURCEW lpnrLocal;    // pointer to enumerated structures
	DWORD i;

	if ((NULL == pswzDeviceName) || ( 0 == MSVCRT$wcslen(pswzDeviceName)))
	{
		internal_printf("Listing all established connections\n");

		dwResult = Net_use_enumerate(lpnr);
	}
	else
	{
		internal_printf("Viewing connection for device %S", pswzDeviceName);
	}

fail:

	// Free the memory
	internal_printf("Free the memory");
	intFree(lpnrLocal);
	
	// End the enumeration
	internal_printf("End the enumeration");
	if ( (NULL != hEnum) && (INVALID_HANDLE_VALUE != hEnum) )
	{
		dwResult = MPR$WNetCloseEnum(hEnum);
		if (dwResult != NO_ERROR)
		{
			BeaconPrintf(CALLBACK_ERROR, "MPR$WNetEnumResourceW failed with error %d\n", dwResult);
		}
		hEnum = NULL;
	}

	return dwResult;
}

DWORD Net_use_enumerate(LPNETRESOURCEW lpnr)
{
	DWORD dwResult = NO_ERROR;
	HANDLE hEnum = NULL;
	DWORD cbBuffer = 16384;     // 16K is a good size
	DWORD cEntries = -1;        // enumerate all possible entries
	LPNETRESOURCEW lpnrLocal;    // pointer to enumerated structures
	DWORD i;

	if ((NULL == pswzDeviceName) || (0 == MSVCRT$wcslen(pswzDeviceName)))
	{
		internal_printf("Listing all established connections\n");

		// Call the WNetOpenEnum function to begin the enumeration
		internal_printf("Call the WNetOpenEnum function to begin the enumeration\n");
		dwResult = MPR$WNetOpenEnumW(
			RESOURCE_GLOBALNET,	// all network resources
			RESOURCETYPE_ANY,	// all resources
			0,					// enumerate all resources
			lpnr,				// NULL first time the function is called
			&hEnum				// handle to the resource
		);
		if (dwResult != NO_ERROR)
		{
			BeaconPrintf(CALLBACK_ERROR, "MPR$WNetOpenEnumW failed: 0x%08lx", dwResult);
			goto fail;
		}

		internal_printf("hEnum: %p\n", hEnum);

		// Allocate resources
		internal_printf("Allocate resources\n");
		lpnrLocal = (LPNETRESOURCEW)intAlloc(cbBuffer);
		if (NULL == lpnrLocal)
		{
			dwResult = ERROR_OUTOFMEMORY;
			BeaconPrintf(CALLBACK_ERROR, "intAlloc failed: 0x%08lx", dwResult);
			goto fail;
		}

		internal_printf("lpnrLocal: %p\n", lpnrLocal);

		do
		{
			// Initialize the buffer
			internal_printf("Initialize the buffer\n");
			intZeroMemory(lpnrLocal, cbBuffer);

			// Call the WNetEnumResource function to continue the enumeration
			internal_printf("Call the WNetEnumResource function to continue the enumeration\n");
			dwResult = MPR$WNetEnumResourceW(
				hEnum,			// resource handle
				&cEntries,		// defined locally as -1
				lpnrLocal,		// LPNETRESOURCE
				&cbBuffer		// buffer size
			);

			internal_printf("dwResult: %d\n", dwResult);

			// If the call succeeds, loop through the structures
			internal_printf("If the call succeeds, loop through the structures\n");
			if (dwResult == NO_ERROR)
			{
				internal_printf("cEntries: %d\n", cEntries);

				for (i = 0; i < cEntries; i++)
				{
					LPNETRESOURCEW lpCurrent = &lpnrLocal[i];

					internal_printf("NETRESOURCE[%d]\n", i);

					internal_printf("  Scope: ");
					//internal_printf("%d\n", lpCurrent->dwScope);
					if (RESOURCE_CONNECTED == lpCurrent->dwScope)
					{
						internal_printf("connected\n");
					}
					else if (RESOURCE_GLOBALNET == lpCurrent->dwScope)
					{
						internal_printf("all resources\n");
					}
					else if (RESOURCE_REMEMBERED == lpCurrent->dwScope)
					{
						internal_printf("remembered\n");
					}
					else
					{
						internal_printf("unknown scope %d\n", lpCurrent->dwScope);
					}


					internal_printf("  Type: ");
					if (RESOURCETYPE_ANY == lpCurrent->dwType)
					{
						internal_printf("any\n");
					}
					else if (RESOURCETYPE_DISK == lpCurrent->dwType)
					{
						internal_printf("disk\n");
					}
					else if (RESOURCETYPE_PRINT == lpCurrent->dwType)
					{
						internal_printf("print\n");
					}
					else
					{
						internal_printf("unknown type %d\n", lpCurrent->dwType);
					}


					internal_printf("  DisplayType: ");
					if (RESOURCEDISPLAYTYPE_GENERIC == lpCurrent->dwDisplayType)
					{
						internal_printf("generic\n");
					}
					else if (RESOURCEDISPLAYTYPE_DOMAIN == lpCurrent->dwDisplayType)
					{
						internal_printf("domain\n");
					}
					else if (RESOURCEDISPLAYTYPE_SERVER == lpCurrent->dwDisplayType)
					{
						internal_printf("server\n");
					}
					else if (RESOURCEDISPLAYTYPE_SHARE == lpCurrent->dwDisplayType)
					{
						internal_printf("share\n");
					}
					else if (RESOURCEDISPLAYTYPE_FILE == lpCurrent->dwDisplayType)
					{
						internal_printf("file\n");
					}
					else if (RESOURCEDISPLAYTYPE_GROUP == lpCurrent->dwDisplayType)
					{
						internal_printf("group\n");
					}
					else if (RESOURCEDISPLAYTYPE_NETWORK == lpCurrent->dwDisplayType)
					{
						internal_printf("network\n");
					}
					else
					{
						internal_printf("unknown display type %d\n", lpCurrent->dwDisplayType);
					}

					internal_printf(" Usage: 0x%x = ", lpCurrent->dwUsage);
					if (lpCurrent->dwUsage & RESOURCEUSAGE_CONNECTABLE)
						internal_printf("connectable ");
					if (lpCurrent->dwUsage & RESOURCEUSAGE_CONTAINER)
						internal_printf("container ");
					internal_printf("\n");

					internal_printf("  Localname: %S\n", lpCurrent->lpLocalName);
					internal_printf("  Remotename: %S\n", lpCurrent->lpRemoteName);
					internal_printf("  Comment: %S\n", lpCurrent->lpComment);
					internal_printf("  Provider: %S\n", lpCurrent->lpProvider);
					internal_printf("\n");

					if (RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER))
					{
						dwResult = Net_use_enumerate(&lpnrLocal[i]);
						if (NO_ERROR != dwResult)
						{
							internal_printf("Net_use_enumerate failed %d\n", dwResult);
						}

				}
			}
			// Process errors
			else if (dwResult != ERROR_NO_MORE_ITEMS)
			{
				BeaconPrintf(CALLBACK_ERROR, "MPR$WNetEnumResourceW failed with error %d\n", dwResult);
				goto fail;
			}
		} while (dwResult != ERROR_NO_MORE_ITEMS);

		dwResult = NO_ERROR;
	}
	else
	{
		internal_printf("Viewing connection for device %S", pswzDeviceName);
	}

fail:

	// Free the memory
	internal_printf("Free the memory");
	intFree(lpnrLocal);

	// End the enumeration
	internal_printf("End the enumeration");
	if ((NULL != hEnum) && (INVALID_HANDLE_VALUE != hEnum))
	{
		dwResult = MPR$WNetCloseEnum(hEnum);
		if (dwResult != NO_ERROR)
		{
			BeaconPrintf(CALLBACK_ERROR, "MPR$WNetEnumResourceW failed with error %d\n", dwResult);
		}
		hEnum = NULL;
	}

	return dwResult;
}

// Function to perform a basic mimic of the net use command 
DWORD Net_use(LPWSTR pswzDeviceName, LPWSTR pswzShareName)
{
	DWORD dwResult = ERROR_SUCCESS;

	// Check if viewing or modifying connections
	if ((NULL == pswzShareName) || (0 == MSVCRT$wcslen(pswzShareName)))
	{
		// Just viewing
		dwResult = Net_use_list(pswzDeviceName);
	}
	else
	{
		// Connect or disconnect device
		dwResult = Net_use_connection(pswzDeviceName, pswzShareName);
	}

fail:
	return dwResult;
}


// BOF entry point function
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD	dwResult = ERROR_SUCCESS;
	datap	parser = {0};
	LPWSTR	pswzDeviceName = NULL;
	LPWSTR	pswzShareName = NULL;
	LPWSTR	pswzDelete = NULL;
	BOOL	bDelete = FALSE;

	BeaconDataParse(&parser, Buffer, Length);
	pswzDeviceName = (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzShareName = (LPWSTR)BeaconDataExtract(&parser, NULL);
	
	if(!bofstart())
	{
		return;
	}

	dwResult = Net_use(pswzDeviceName, pswzShareName);

	if (ERROR_SUCCESS != dwResult)
	{
		BeaconPrintf(CALLBACK_ERROR, "net_use failed: 0x%08lx", dwResult);
	}

	printoutput(TRUE);

	bofstop();
};
