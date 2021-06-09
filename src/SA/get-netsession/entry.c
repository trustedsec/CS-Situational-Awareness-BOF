#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <stdio.h>
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
    LPWSTR pszServerName = NULL;
    LPWSTR pszClientName = NULL;
    LPWSTR pszUserName = NULL;
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
                    internal_printf("Active: %lu\n", pTmpBuf->sesi10_time);
                    internal_printf("Idle:   %lu\n", pTmpBuf->sesi10_idle_time);
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
            BeaconPrintf(CALLBACK_ERROR, "A system error has occurred: %lu\n", nStatus);
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
    internal_printf("\nTotal of %lu entries enumerated\n", dwTotalCount);
}

#ifdef BOF
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
};
#else
int main(int argc, char ** argv)
{
    char * hostname = argv[1];
    wchar_t whostname[260] = {0};
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, hostname, -1, whostname, 260);
    NetSessions(argv[1]? whostname: NULL);

    return 0;
}

#endif
