#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <stdio.h>
#include <windows.h> 
#include <windns.h>
#include <lm.h>

typedef PCWSTR (*myInetNtopW)(
  INT        Family,
  const VOID *pAddr,
  PWSTR      pStringBuf,
  size_t     StringBufSize
);

// slimmed down from https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/SA/nslookup/entry.c#L14
void query_domain(const char * domainname, unsigned short wType, const char * dnsserver, PDNS_RECORD base, PIP4_ARRAY pSrvList)
{
    PDNS_RECORD pdns = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY;
    DNS_FREE_TYPE freetype = DnsFreeRecordListDeep;
    DWORD status = 0;
    struct in_addr inaddr = {0};
    unsigned int i = 0;
    LPSTR errormsg = NULL;

    status = DNSAPI$DnsQuery_A(domainname, wType, options, pSrvList, &base, NULL);
    
    pdns = base;
    if(status != 0 || pdns == NULL)
    {
		internal_printf("PTR: No PTR record found; reverse lookup failed\n");
        return;
    }

    do {
        // we only care about PTR records since resolving IP to hostname
        if(pdns->wType == DNS_TYPE_PTR){
            internal_printf("PTR: %s\n", pdns->Data.PTR.pNameHost);
        }
        pdns = pdns->pNext;
    } while (pdns);

    if(base)
    {DNSAPI$DnsFree(base, freetype);}
}

//#pragma comment(lib, "Netapi32.lib")
void NetSessions(wchar_t* hostname, unsigned short resolveMethod, char* dnsserver){
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

    // for DNS resolution
    PDNS_RECORD base = NULL;
    myInetNtopW inetntow;
    HMODULE WS = NULL;
    PIP4_ARRAY pSrvList = NULL;

    // for NetWkstaGetInfo
    WKSTA_INFO_100* pInfo = NULL;

    if (hostname){
        pszServerName = hostname;
    }

    // if resolveMethod is DNS, prep for DNS query
    if (resolveMethod == 0)
    {
        WS = LoadLibraryA("WS2_32");
        int (*intinet_pton)(INT, LPCSTR, PVOID);
        if(WS == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
            return;
        }
        else
        {
            inetntow = (myInetNtopW)GetProcAddress(WS, "InetNtopW");
            intinet_pton = (int (*)(INT,LPCSTR,PVOID))GetProcAddress(WS, "inet_pton");
            if(!inetntow || !intinet_pton)
            {
                BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
                goto END;
            }
        }
        
        if(dnsserver != NULL) // I am assuming dnsserver is never set with cacheOnly
        {
            pSrvList = (PIP4_ARRAY)KERNEL32$LocalAlloc(LPTR, sizeof(IP4_ARRAY));
            if (!pSrvList)
            {
                BeaconPrintf(CALLBACK_ERROR, "could not allocate memory");      
                goto END;
            }
            if(intinet_pton(AF_INET, dnsserver, &(pSrvList->AddrArray[0])) != 1)
            {
                BeaconPrintf(CALLBACK_ERROR, "Could not convert dnsserver from ip to binary");
                KERNEL32$LocalFree(pSrvList);
                goto END;
            }
        //   pSrvList->AddrArray[0] = WSOCK32$inet_addr(dnsserver); //DNS (ASCII) to  IP address
        //   pSrvList->
            pSrvList->AddrCount = 1; 
            //options = DNS_QUERY_WIRE_ONLY;
        }
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
                    internal_printf("---------------Session--------------\n");
                    internal_printf("Client: %ls\n", pTmpBuf->sesi10_cname);

                    // get the client name and remove the leading backslashes
                    wchar_t* clientname = pTmpBuf->sesi10_cname;
                    if (clientname[0] == L'\\' && clientname[1] == L'\\'){
                        clientname += 2;
                    }

                    if (resolveMethod == 1)
                    {
                        
                        // if the client name is an ip, query the dns server for the hostname (in arpa format)
                        if (clientname[0] >= L'0' && clientname[0] <= L'9'){
                            char ipAddress[16]; // Assuming IPv4 address
                            MSVCRT$wcstombs(ipAddress, clientname, sizeof(ipAddress));

                            char* octets[4];
                            int i = 0;
                            char* token = MSVCRT$strtok(ipAddress, ".");
                            while (token != NULL && i < 4) {
                                octets[i] = token;
                                token = MSVCRT$strtok(NULL, ".");
                                i++;
                            }

                            if (i != 4)
                            {
                                internal_printf("PTR: Failed; Invalid IP address\n");
                            }
                            else
                            {
                                char arpaFormat[256];
                                MSVCRT$sprintf(arpaFormat, "%s.%s.%s.%s.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
                                //internal_printf("ARPA Format: %s\n", arpaFormat);
                                query_domain(arpaFormat, DNS_TYPE_PTR, NULL, base, pSrvList);
                            }
                            
                        }
                    }
                    else 
                    {
                        // resolve with NetWkstaGetInfo
                        NET_API_STATUS stat = NETAPI32$NetWkstaGetInfo(clientname, 100, (LPBYTE*)&pInfo);
                        if (stat == NERR_Success)
                        {
                            internal_printf("ComputerName: %S\n", pInfo->wki100_computername);
                            internal_printf("ComputerDomain: %S\n", pInfo->wki100_langroup);
                        }
                        else
                        {
                            internal_printf("ComputerName: NetWkstaGetInfo Failed; %lu\n", stat);
                            internal_printf("ComputerDomain: NetWkstaGetInfo Failed; %lu\n", stat);
                        }
                        
                        if (pInfo != NULL)
                        {
                            NETAPI32$NetApiBufferFree(pInfo);
                            pInfo = NULL;
                        }

                        
                    }

                    internal_printf("User: %ls\n", pTmpBuf->sesi10_username);
                    internal_printf("Active: %lu\n", pTmpBuf->sesi10_time);
                    internal_printf("Idle: %lu\n", pTmpBuf->sesi10_idle_time);
                    internal_printf("-------------End Session------------\n\n");

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

    // if resolveMethod is DNS, clean up
    if (resolveMethod == 0)
    {
        goto END;
    }

    // DNS cleanup
    END:
    if(pSrvList != NULL)
    {KERNEL32$LocalFree(pSrvList);}

    if (WS)
    {FreeLibrary(WS);}


}

#ifdef BOF
VOID go( IN PCHAR Buffer, IN ULONG Length) 
{
    datap  parser;
    wchar_t* hostname =  NULL;
    unsigned short resolveMethod = 0;
    char * dnsserver = NULL;


    if(!bofstart())
    {
        return;
    }
    
    BeaconDataParse(&parser, Buffer, Length);
    hostname = (wchar_t*)BeaconDataExtract(&parser, NULL);
    resolveMethod = BeaconDataShort(&parser);
    dnsserver = BeaconDataExtract(&parser, NULL);

    hostname = *hostname == 0 ? NULL : hostname;
    dnsserver = *dnsserver == 0 ? NULL : dnsserver;

    if (hostname){
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating sessions for system: %ls\n", hostname);
    }

    internal_printf("[*] Resolving client IPs to hostnames using ");
    if (resolveMethod == 0)
    {
        internal_printf("DNS\n\n");
    }
    else
    {
        internal_printf("NetWkstaGetInfo\n\n");
    }

    NetSessions(hostname, resolveMethod, dnsserver);
    printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
    char * hostname = argv[1];
    wchar_t whostname[260] = {0};
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, hostname, -1, whostname, 260);
    NetSessions(argv[1]? whostname: NULL, 1, NULL);

    return 0;
}

#endif