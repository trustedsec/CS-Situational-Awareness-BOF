#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>

//#pragma comment(lib, "Netapi32.lib")
void NetSessions(wchar_t* hostname){
    LPSESSION_INFO_10 pBuf = NULL;
    LPSESSION_INFO_10 pTmpBuf;
    DWORD dwLevel = 10;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    LPCWSTR pszServerName = NULL;
    LPCWSTR pszClientName = NULL;
    LPCWSTR pszUserName = NULL;
    NET_API_STATUS nStatus;

    if (hostname){
        pszServerName = hostname;
    }

    do // begin do
    {
        nStatus = NETAPI32$NetSessionEnum(pszServerName,
            pszClientName,
            pszUserName,
            dwLevel,
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
            if ((pTmpBuf = pBuf) != NULL)
            {
                //
                // Loop through the entries.
                //
                for (i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);

                    if (pTmpBuf == NULL)
                    {
                        BeaconPrintf(CALLBACK_ERROR, "An access violation has occurred\n");
                        break;
                    }
                    //
                    // Print the retrieved data. 
                    //
                    internal_printf("\nClient: %ls\n", pTmpBuf->sesi10_cname);
                    internal_printf("User:   %ls\n", pTmpBuf->sesi10_username);
                    internal_printf("Active: %d\n", pTmpBuf->sesi10_time);
                    internal_printf("Idle:   %d\n", pTmpBuf->sesi10_idle_time);
                    internal_printf("--------------------\n");

                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        //
        // Otherwise, indicate a system error.
        //
        else
            BeaconPrintf(CALLBACK_ERROR, "A system error has occurred: %d\n", nStatus);
        //
        // Free the allocated memory.
        //
        if (pBuf != NULL)
        {
            NETAPI32$NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    }    
    while (nStatus == ERROR_MORE_DATA);
    // Check again for an allocated buffer.
    //
    if (pBuf != NULL)
        NETAPI32$NetApiBufferFree(pBuf);
    //
    // Print the final count of sessions enumerated.
    //
    internal_printf("\nTotal of %d entries enumerated\n", dwTotalCount);
}

VOID go( IN PCHAR Buffer, IN ULONG Length) 
{
    datap  parser;
    wchar_t* hostname =  NULL;
    if(!bofstart())
    {
        return;
    }
    
    BeaconDataParse(&parser, Buffer, Length);
    hostname = (wchar_t*)BeaconDataExtract(&parser, NULL);
    hostname = *hostname == 0 ? NULL : hostname;

    if (hostname){
        BeaconPrintf(CALLBACK_OUTPUT, "enumerating session for system: %ls", hostname);
    }

    NetSessions(hostname);
    printoutput(TRUE);
    bofstop();
};
