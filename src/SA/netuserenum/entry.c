
//https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
#include <windows.h>
#include <iphlpapi.h>
#include <lmaccess.h>
#include <lmerr.h>
#include "lm.h"
#include "bofdefs.h"
#include "base.c"

/*%enumtype = %(
	all => 1,
	locked => 2,
	disabled =>3,
	active =>4);

)*/

char* netuser_enum(int usedomain, int userfilter){
    LPVOID pBuf = NULL;
    LPUSER_INFO_1 pTmpBuf; // we can use this for lvl 0 as well since the name is in the same place for both
    DWORD dwLevel = 1;
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
    dwLevel = (userfilter == 1) ? 0 : 1;
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
                    if(userfilter == 1)
                    {
					    goto printu;         
                    }
                    else if (userfilter == 2)
                    {
                        if (pTmpBuf->usri1_flags & UF_LOCKOUT)
					        goto printu;
                        else
                            goto nextu;                       
                    }
                    else if (userfilter == 3)
                    {
                        if (pTmpBuf->usri1_flags & UF_ACCOUNTDISABLE)
					        goto printu;
                        else
                            goto nextu;                       
                    }
                    else if (userfilter == 4)
                    {
                        if (!(pTmpBuf->usri1_flags & (UF_ACCOUNTDISABLE | UF_LOCKOUT)))
					        goto printu;
                        else
                            goto nextu;                       
                    }
                    else
                    {
                        //something is wrong
                        break;
                    }  
                    printu:
                    internal_printf("-- %S\n", pTmpBuf->usri1_name); 
                    nextu:
                    if(dwLevel)
                    {   
                        pTmpBuf++;
                    }
                    else
                    {
                        pTmpBuf = (LPUSER_INFO_1)((LPUSER_INFO_0)pTmpBuf + 1);
                    }
                    
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

#ifdef BOF

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
	int usedomain = BeaconDataInt(&parser);
    int userfilter = BeaconDataInt(&parser);
	netuser_enum(usedomain, userfilter);
	printoutput(TRUE);
};

#else

int main()
{
    netuser_enum(1, 1);
    netuser_enum(0, 1);
    return 0;
}

#endif
