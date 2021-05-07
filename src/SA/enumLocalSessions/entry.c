#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>
#include <wtsapi32.h>

void EnumLocalSessions(){
    DWORD nStatus;
    WTS_SESSION_INFO *wtsinfo;
    DWORD wtscount;
    DWORD index;
    int users = 0;
    

        
    nStatus = WTSAPI32$WTSEnumerateSessionsA(
        WTS_CURRENT_SERVER_HANDLE,
        0, 
        1, 
        &wtsinfo, 
        &wtscount);
    
    // If the call succeeds,
    //
    if ((nStatus != 0))
    {
        for (index = 0; index < wtscount; index++)
            {
                LPTSTR username = NULL;
                LPTSTR domain = NULL;
                BOOL freedomain = FALSE;
                LPTSTR stationId = NULL;
                BOOL freestation = FALSE;
                DWORD size;
                
                nStatus = WTSAPI32$WTSQuerySessionInformationA(
                    WTS_CURRENT_SERVER_HANDLE,
                    wtsinfo[index].SessionId, 
                    WTSUserName, 
                    &username, 
                    &size);
                    
                if ((nStatus != 0))
                {
                    if (strlen(username) > 0 && 
                        (wtsinfo[index].State == WTSActive || wtsinfo[index].State == WTSDisconnected))
                    {
                        if(!WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE,wtsinfo[index].SessionId,WTSDomainName,&domain,&size))
                        {domain = "(NULL)";}
                        else {freedomain = TRUE;}
                        if(wtsinfo[index].State == WTSDisconnected)
                        {stationId = "(Disconnected)";}
                        else
                        {
                            if(!WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE,wtsinfo[index].SessionId,WTSWinStationName,&stationId,&size))
                            {stationId = "(NULL)";}
                            else {freestation = TRUE;}
                        }
                        
                        internal_printf("  - [%lu] %s: %s\\%s\n", wtsinfo[index].SessionId,stationId,domain,username);
                        WTSAPI32$WTSFreeMemory(username);
                        if(freedomain) {WTSAPI32$WTSFreeMemory(domain);}
                        if(freestation) {WTSAPI32$WTSFreeMemory(stationId);}
                        users++;
                    }
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "Error recovering information from the sessions (nStatus value): %lu\n", nStatus);
                } 
                
            }
            WTSAPI32$WTSFreeMemory(wtsinfo);
    }
    //
    // Otherwise, indicate a system error.
    //
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "A system error has occurred (nStatus value): %lu\n", nStatus);
    } 

    //
    // Print the final count of sessions enumerated.
    //
    internal_printf("\nTotal of %d entries enumerated\n", users);
        
}

#ifdef BOF
VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length
) 
{   
    if(!bofstart())
    {
        return;
    }
    

    internal_printf("Enumerating sessions for local system:\n");
    EnumLocalSessions();
    printoutput(TRUE);
};

#else
int main(int argc, char ** argv)
{
    EnumLocalSessions();
    return 0;
}

#endif
