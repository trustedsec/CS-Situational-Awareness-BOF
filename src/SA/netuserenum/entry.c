
//https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
#include <windows.h>
#include <iphlpapi.h>
#include <lmaccess.h>
#include <lmerr.h>
#include "bofdefs.h"
#include "base.c"

char* netuser_enum(int usedomain){
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = NULL;
    char* usernameString = NULL;

    if (usedomain == 1){
        NETAPI32$NetGetAnyDCName(NULL, NULL, (LPBYTE*)&pszServerName);
    }

    //if (argc == 2)
    //pszServerName =  (LPTSTR) argv[1];
    //wprintf(L"\nUser account on %s: \n", pszServerName);
    //
    // Call the NetUserEnum function, specifying level 0;
    //   enumerate global user account types only.
    //
    do // begin do
    {
        nStatus = NETAPI32$NetUserEnum((LPCWSTR) pszServerName,
            dwLevel,
            FILTER_NORMAL_ACCOUNT, // global users
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);
        //
        // If the call succeeds,
        //
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL){
                //
                // Loop through the entries.
                //
                for (i = 0; (i < dwEntriesRead); i++){
                    if (pTmpBuf == NULL){
                        break;
                    }
					internal_printf("-- %S\n", pTmpBuf->usri0_name);         
                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        else
        {
                BeaconPrintf(CALLBACK_ERROR, "Failed to query for local users\n");
        }
        
        //
        // Free the allocated buffer.
        //  
        if (pBuf != NULL){
            NETAPI32$NetApiBufferFree(pBuf);
            pBuf = NULL;
        }

    }
    // Continue to call NetUserEnum while
    //  there are more entries.
    //
    while (nStatus == ERROR_MORE_DATA); // end do
    //
    // Check again for allocated memory.
    //
    if (pBuf != NULL){
        NETAPI32$NetApiBufferFree(pBuf);
    }

    return NULL;
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	if(!bofstart())
	{
		return;
	}
	BeaconDataParse(&parser, Buffer, Length);
	int d = BeaconDataInt(&parser);
	netuser_enum(d);
	printoutput(TRUE);
	bofstop();
};
