#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>

DWORD Net_use_connect(LPWSTR pswzDeviceName, LPWSTR pswzShareName)
{
	DWORD dwStatus = ERROR_SUCCESS;

	if ((NULL == pswzDeviceName) || (1 > MSVCRT$wcslen(pswzDeviceName)) || (5 < MSVCRT$wcslen(pswzDeviceName)) )
	{
		dwStatus = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_connect");
	}

	if ((NULL == pswzShareName) || (MSVCRT$wcslen(pswzShareName)))
	{
		dwStatus = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_connection");
	}

	internal_printf("Establishing a connection from %S to %S", pswzDeviceName, pswzShareName);

fail:
	return dwStatus;
}

DWORD Net_use_disconnect(LPWSTR pswzDeviceName)
{
	DWORD dwStatus = ERROR_SUCCESS;

	if ((NULL == pswzDeviceName) || (2 > MSVCRT$wcslen(pswzDeviceName)))
	{
		dwStatus = ERROR_BAD_ARGUMENTS;
		BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for Net_use_disconnect");
	}

	internal_printf("Cancelling a connection %S", pswzDeviceName);

fail:
	return dwStatus;
}

// Helper function to perform basic mimic of net use's view established connections
DWORD Net_use_view(LPWSTR pswzDeviceName)
{
	DWORD dwStatus = ERROR_SUCCESS;

	if ((NULL == pswzDeviceName) || ( 0 < MSVCRT$wcslen(pswzDeviceName)))
	{
		internal_printf("Viewing all established connections");
	}
	else
	{
		internal_printf("Viewing connection for device %S", pswzDeviceName);
	}

fail:
	return dwStatus;
}


// Function to perform a basic mimic of the net use command 
DWORD Net_use(LPWSTR pswzDeviceName, LPWSTR pswzShareName, BOOL bDelete)
{
	DWORD dwStatus = ERROR_SUCCESS;

	// Check if viewing or modifying connections
	if ((NULL == pswzShareName) || (MSVCRT$wcslen(pswzShareName)))
	{
		// Just viewing
		dwStatus = Net_use_view(pswzDeviceName);
	}
	else
	{
		// Check if connecting or disconnecting device
		if (TRUE == bDelete)
		{
			// Disconnect a device
			dwStatus = Net_use_disconnect(pswzDeviceName);
		}
		else
		{
			// Connect a device to a shared, network resource
			dwStatus = Net_use_connect(pswzDeviceName, pswzShareName);
		}
	}

fail:
	return dwStatus;
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD	dwStatus = ERROR_SUCCESS;
	datap	parser = {0};
	LPWSTR	pswzDeviceName = NULL;
	LPWSTR	pswzShareName = NULL;
	LPWSTR	pswzDelete = NULL;
	BOOL	bDelete = FALSE;

	BeaconDataParse(&parser, Buffer, Length);
	pswzDeviceName = (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzShareName = (LPWSTR)BeaconDataExtract(&parser, NULL);
	pswzDelete = (LPWSTR)BeaconDataExtract(&parser, NULL);
	
	if(!bofstart())
	{
		return;
	}

	// Any string will be used to indicate true
	if ((NULL == pswzDelete) || ( 0 < MSVCRT$wcslen(pswzDelete)))
	{
		bDelete = TRUE;
	}

	dwStatus = Net_use(pswzDeviceName, pswzShareName, bDelete);

	if (ERROR_SUCCESS != dwStatus)
	{
		BeaconPrintf(CALLBACK_ERROR, "net_use failed: 0x%08lx", dwStatus);
	}

	printoutput(TRUE);

	bofstop();
};
