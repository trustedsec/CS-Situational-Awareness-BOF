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
    
    DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSEnumerateSessionsA(LPVOID, DWORD, DWORD, PWTS_SESSION_INFO*, DWORD*);
    DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSQuerySessionInformationA(LPVOID, DWORD, WTS_INFO_CLASS , LPSTR*, DWORD*);
    DECLSPEC_IMPORT DWORD WINAPI WTSAPI32$WTSFreeMemory(LPTSTR);
        
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
                LPTSTR username;
                LPTSTR domain;
                LPTSTR stationId;
                LPTSTR idleTime;
                DWORD size;
                int len;
                
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
                        nStatus = WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE,wtsinfo[index].SessionId,WTSDomainName,&domain,&size);
                        nStatus = WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE,wtsinfo[index].SessionId,WTSWinStationName,&stationId,&size);
                        
                        internal_printf("  - [%d] %s: %s\\%s\n", wtsinfo[index].SessionId,stationId,domain,username);
                        users++;
                    }
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "Error recovering information from the sessions (nStatus value): %lu\n", nStatus);
                } 
                
            }
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
    internal_printf("\nTotal of %lu entries enumerated\n", users);
        
}

#ifdef BOF
VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length
) 
{
    datap  parser;
    
    if(!bofstart())
    {
        return;
    }
    
    BeaconDataParse(&parser, Buffer, Length);

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
